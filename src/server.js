// ========== 基础依赖 ==========
const express = require("express");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const dotenv = require("dotenv");
const WebSocket = require("ws");
const fetch = require("node-fetch");

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET || "dev-secret";
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "admin123";

// ========== 内存数据库 ==========
const users = new Map();
const nonces = new Map();
const withdraws = new Map();

// UID 从 200101 开始
let nextUID = 200101;

// ========== 用户创建逻辑 ==========
function createUserIfNotExists(address) {
  let user = users.get(address);
  if (!user) {
    user = {
      wallet: address,
      addressLabel: String(nextUID++),

      remark: "",
      controlMode: "normal",

      balances: {
        USDT: 1000,
        BTC: 0,
      },

      loginCount: 0,
      lastLogin: 0,
      registerIp: "",
      lastLoginIp: "",
      createdAt: Date.now(),

      verifyStatus: "success",
    };

    users.set(address, user);
  }
  return user;
}

// ========== Token 中间件 ==========
function authMiddleware(req, res, next) {
  const auth = req.headers.authorization || "";
  const token = auth.startsWith("Bearer ") ? auth.slice(7) : null;
  if (!token) return res.status(401).json({ message: "缺少 token" });

  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = payload; // { address }
  } catch {
    return res.status(401).json({ message: "token 无效" });
  }

  next();
}

function adminAuthMiddleware(req, res, next) {
  const auth = req.headers.authorization || "";
  const token = auth.startsWith("Bearer ") ? auth.slice(7) : null;
  if (!token) return res.status(401).json({ message: "缺少 adminToken" });

  try {
    const payload = jwt.verify(token, JWT_SECRET);
    if (payload.role !== "admin") return res.status(403).json({ message: "不是管理员" });
    req.admin = payload;
  } catch {
    return res.status(401).json({ message: "adminToken 无效" });
  }

  next();
}

// ========== Auth 接口 ==========
app.post("/api/auth/nonce", (req, res) => {
  const { address } = req.body || {};
  if (!address) return res.status(400).json({ message: "缺少 address" });

  const nonce = Math.floor(Math.random() * 1e9).toString();
  nonces.set(address.toLowerCase(), nonce);

  res.json({ address, nonce });
});

app.post("/api/auth/verify", (req, res) => {
  const { address, signature } = req.body || {};
  if (!address || !signature)
    return res.status(400).json({ message: "缺少 address / signature" });

  const user = createUserIfNotExists(address);

  // 登录记录
  user.loginCount++;
  user.lastLogin = Date.now();
  const ip = req.headers["x-forwarded-for"] || req.socket.remoteAddress || "unknown";
  if (!user.registerIp) user.registerIp = ip;
  user.lastLoginIp = ip;

  const token = jwt.sign({ address }, JWT_SECRET, { expiresIn: "7d" });
  res.json({ token, userId: user.addressLabel, address });
});

// ========== 用户接口 ==========
app.get("/api/user/balance", authMiddleware, (req, res) => {
  const { address } = req.user;
  const user = createUserIfNotExists(address);

res.json({
  userId: user.addressLabel,   // ⭐ UID
  wallet: user.wallet,
  balances: user.balances,
});
});

// ⭐ 用户信息（给 AuthContext 用）
app.get("/api/userinfo", authMiddleware, (req, res) => {
  const { address } = req.user;
  const user = createUserIfNotExists(address);

  res.json({
    userId: user.addressLabel,
    wallet: user.wallet,
    remark: user.remark,
    controlMode: user.controlMode,
    balances: user.balances,
    loginCount: user.loginCount,
    lastLogin: user.lastLogin,
    registerIp: user.registerIp,
    lastLoginIp: user.lastLoginIp,
    createdAt: user.createdAt,
    verifyStatus: user.verifyStatus,
  });
});

// ====== 结算接口 ======
app.post("/api/user/balance/settle", authMiddleware, (req, res) => {
  const { amount, isWin, percent, symbol } = req.body || {};
  const { address } = req.user;

  const user = createUserIfNotExists(address);

  let profit = isWin ? amount * percent : -amount;
  user.balances[symbol] = (user.balances[symbol] || 0) + profit;

  res.json({
    success: true,
    profit,
    balances: user.balances,
  });
});

// ====== 用户提交 Mail ======
app.post("/api/mail", async (req, res) => {
  const { email } = req.body || {};

  if (!email) {
    return res.status(400).json({ error: "Email is required" });
  }

  // 在你后台记录一下（你想存在哪都可以，现在先简单收集）
  console.log("📧 New mail submitted:", email);

  return res.json({ message: "Mail submitted successfully!" });
});

// ====== 用户信息（含语言） ======
app.get("/api/userinfo", authMiddleware, (req, res) => {
  const { address } = req.user;
  const user = createUserIfNotExists(address);

  res.json({
    wallet: user.wallet,
    userId: user.addressLabel,
    language: user.language || "English",
  });
});
// ====== 设置语言 ======
app.post("/api/language", authMiddleware, (req, res) => {
  const { address } = req.user;
  const { language } = req.body || {};

  if (!language) return res.status(400).json({ message: "缺少 language" });

  const user = createUserIfNotExists(address);
  user.language = language;

  res.json({ success: true, language });
});

// ====== 绑定银行卡 ======
// POST /api/bankcard  { name, cardNumber, bankName }
app.post("/api/bankcard", authMiddleware, (req, res) => {
  const { name, cardNumber, bankName } = req.body || {};
  const { address } = req.user;

  if (!name || !cardNumber || !bankName) {
    return res.status(400).json({ error: "缺少字段 name/cardNumber/bankName" });
  }

  const user = createUserIfNotExists(address);

  user.bankCard = {
    name,
    cardNumber,
    bankName,
    updatedAt: Date.now(),
  };

  return res.json({
    success: true,
    message: "Bank card submitted successfully!",
    bankCard: user.bankCard,
  });
});

// ========== 管理员接口 ==========
app.post("/admin/login", (req, res) => {
  const { password } = req.body || {};
  if (password !== ADMIN_PASSWORD)
    return res.status(401).json({ message: "密码错误" });

  const adminToken = jwt.sign({ role: "admin" }, JWT_SECRET, { expiresIn: "1d" });
  res.json({ adminToken });
});

app.get("/admin/users", adminAuthMiddleware, (req, res) => {
  const list = Array.from(users.values()).map((u) => ({
    userId: u.addressLabel,
    wallet: u.wallet,
    remark: u.remark,
    controlMode: u.controlMode,
    balances: u.balances,

    loginCount: u.loginCount,
    lastLogin: u.lastLogin,
    registerIp: u.registerIp,
    lastLoginIp: u.lastLoginIp,
    createdAt: u.createdAt,

    verifyStatus: u.verifyStatus,
  }));
  res.json(list);
});

app.post("/admin/balance/add", adminAuthMiddleware, (req, res) => {
  const { address, symbol, amount } = req.body || {};
  if (!address || !symbol || typeof amount !== "number")
    return res.status(400).json({ message: "缺少字段" });

  const user = createUserIfNotExists(address);
  user.balances[symbol] = (user.balances[symbol] || 0) + amount;

  res.json({ success: true, balances: user.balances });
});

app.post("/admin/user/control", adminAuthMiddleware, (req, res) => {
  const { address, mode, remark } = req.body || {};
  const user = createUserIfNotExists(address);

  if (mode) user.controlMode = mode;
  if (remark !== undefined) user.remark = remark;

  res.json({ success: true, controlMode: user.controlMode, remark: user.remark });
});

// ========== 订单系统 ==========
app.post("/api/order/create", authMiddleware, (req, res) => {
  const { symbol, amount } = req.body || {};
  const { address } = req.user;

  const user = createUserIfNotExists(address);

  const order = {
    id: "ord_" + Date.now(),
    wallet: user.wallet,
    symbol,
    amount,
    remark: user.remark || "",
    createdAt: Date.now(),
  };

  // 推送给后台
  broadcastToAdmins({
    type: "NEW_ORDER",
    order,
  });

  res.json({ success: true, order });
});
// ====== 修改提现密码 ======
app.post("/api/withdrawal-password", authMiddleware, (req, res) => {
  const { password } = req.body || {};
  const { address } = req.user;

  if (!password) {
    return res.status(400).json({ error: "Missing password" });
  }

  const user = createUserIfNotExists(address);

  user.withdrawPassword = password; // 保存提现密码

  return res.json({ message: "Withdrawal password updated successfully" });
});

// ========== 提币系统 ==========
app.post("/api/withdraw/create", authMiddleware, (req, res) => {
  const { symbol, amount, address: withdrawAddress } = req.body || {};
  const { address } = req.user;

  const user = createUserIfNotExists(address);

  const wd = {
    id: "wd_" + Date.now(),
    wallet: user.wallet,
    symbol,
    amount,
    withdrawAddress,
    remark: user.remark || "",
    status: "pending",
    createdAt: Date.now(),
  };

  withdraws.set(wd.id, wd);

  broadcastToAdmins({
    type: "NEW_WITHDRAW",
    withdraw: wd,
  });

  res.json({ success: true, withdraw: wd });
});

app.get("/admin/withdraw/list", adminAuthMiddleware, (req, res) => {
  res.json(Array.from(withdraws.values()));
});

// ====== 用户查询自己的提币记录 ======
app.get("/api/withdraw/list", authMiddleware, (req, res) => {
  const { address } = req.user;

  const list = Array.from(withdraws.values()).filter(
    (w) => w.wallet === address
  );

  res.json(list);
});

app.post("/admin/withdraw/approve", adminAuthMiddleware, (req, res) => {
  const { id } = req.body || {};
  if (!withdraws.has(id)) return res.status(400).json({ message: "不存在" });

  const wd = withdraws.get(id);
  wd.status = "approved";

  res.json({ success: true, withdraw: wd });
});

app.post("/admin/withdraw/reject", adminAuthMiddleware, (req, res) => {
  const { id, reason } = req.body || {};
  if (!withdraws.has(id)) return res.status(400).json({ message: "不存在" });

  const wd = withdraws.get(id);
  wd.status = "rejected";
  wd.reason = reason || "管理员拒绝";

  res.json({ success: true, withdraw: wd });
});

// ========== 币种列表 ==========
app.get("/api/coins", (req, res) => {
  res.json([
    { symbol: "BTCUSDT", name: "Bitcoin" },
    { symbol: "ETHUSDT", name: "Ethereum" },
    { symbol: "SOLUSDT", name: "Solana" },
  ]);
});

// ========== K线数据 ==========
app.get("/api/kline", async (req, res) => {
  const { symbol = "BTCUSDT", interval = "1m", limit = 200 } = req.query;

  const url = `https://api.binance.com/api/v3/klines?symbol=${symbol}&interval=${interval}&limit=${limit}`;

  try {
    const r = await fetch(url);
    const data = await r.json();
    res.json(data);
  } catch {
    res.status(500).json({ message: "kline error" });
  }
});

// ========== WebSocket 统一入口（Admin + Ticker） ==========
const server = app.listen(PORT, () => {
  console.log(`Backend running: http://localhost:${PORT}`);
});

const wsServer = new WebSocket.Server({ noServer: true });

server.on("upgrade", (req, socket, head) => {
  if (req.url === "/admin-ws") {
    wsServer.handleUpgrade(req, socket, head, (ws) => {
      ws.path = "admin";
      wsServer.emit("connection", ws, req);
    });
  } else if (req.url === "/ticker") {
    wsServer.handleUpgrade(req, socket, head, (ws) => {
      ws.path = "ticker";
      wsServer.emit("connection", ws, req);
    });
  } else {
    socket.destroy();
  }
});

const adminClients = new Set();
const tickerClients = new Set();

wsServer.on("connection", (ws) => {
  if (ws.path === "admin") {
    adminClients.add(ws);
    console.log("Admin WS connected");
    ws.on("close", () => adminClients.delete(ws));
  }

  if (ws.path === "ticker") {
    tickerClients.add(ws);
    console.log("Ticker WS connected");
    ws.on("close", () => tickerClients.delete(ws));
  }
});

// 推送到后台
function broadcastToAdmins(data) {
  const msg = JSON.stringify(data);
  adminClients.forEach((c) => {
    if (c.readyState === WebSocket.OPEN) c.send(msg);
  });
}

// Binance Ticker 转发
const binanceWS = new WebSocket("wss://stream.binance.com:9443/ws/btcusdt@ticker");

binanceWS.on("message", (msg) => {
  tickerClients.forEach((c) => {
    if (c.readyState === WebSocket.OPEN) c.send(msg);
  });
});

binanceWS.on("open", () => console.log("Binance Ticker Connected"));
binanceWS.on("error", (e) => console.log("Ticker Error:", e));
