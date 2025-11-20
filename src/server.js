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
const orders = new Map();  // 新增：订单内存表

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

// ========== 用户余额（允许游客访问） ==========
app.get("/api/user/balance", (req, res) => {
  const auth = req.headers.authorization || "";
  const token = auth.startsWith("Bearer ") ? auth.slice(7) : null;

  // 没 token = 游客模式 → 返回默认余额
  if (!token) {
    return res.json({
      userId: "0",
      wallet: "guest",
      balances: {
        USDT: 0,
        BTC: 0,
      },
    });
  }

  // -------- 有 token 的正常逻辑 --------
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    const user = createUserIfNotExists(payload.address);

    return res.json({
      userId: user.addressLabel,
      wallet: user.wallet,
      balances: user.balances,
    });
  } catch (err) {
    // token 错误也按游客处理，避免报错
    return res.json({
      userId: "0",
      wallet: "guest",
      balances: {
        USDT: 0,
        BTC: 0,
      },
    });
  }
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
// 管理员查看全部订单
app.get("/admin/orders", adminAuthMiddleware, (req, res) => {
  const list = Array.from(orders.values());
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
// 下单接口（扣余额 + 记录订单 + 推送后台）
app.post("/api/order/create", authMiddleware, (req, res) => {
  const { symbol, amount, direction } = req.body || {}; // direction: LONG / SHORT
  const { address } = req.user;

  if (!symbol || !amount || !direction) {
    return res
      .status(400)
      .json({ message: "缺少字段 symbol/amount/direction" });
  }

  const user = createUserIfNotExists(address);

  // 校验余额
  if (user.balances.USDT < amount) {
    return res.status(400).json({ message: "余额不足" });
  }

  // 扣除保证金
  user.balances.USDT -= amount;

  const order = {
    id: "ord_" + Date.now(),
    wallet: user.wallet,
    symbol,
    amount,
    direction, // LONG / SHORT
    status: "open",
    profit: 0,
    createdAt: Date.now(),
  };

  // 存入内存数据库
  orders.set(order.id, order);

  // 推送给后台 WebSocket
  broadcastToAdmins({
    type: "NEW_ORDER",
    order,
  });

  res.json({
    success: true,
    order,
    balances: user.balances,
  });
});

// 我的订单列表
app.get("/api/order/list", authMiddleware, (req, res) => {
  const { address } = req.user;

  // 当前用户的钱包地址
  const user = createUserIfNotExists(address);

  const list = Array.from(orders.values()).filter(
    (o) => o.wallet === user.wallet
  );

  res.json(list);
});

// 结算订单（根据输赢返还余额）
app.post("/api/order/settle", authMiddleware, (req, res) => {
  const { orderId, isWin, percent } = req.body || {};
  const { address } = req.user;

  if (!orderId || typeof isWin === "undefined" || typeof percent === "undefined") {
    return res
      .status(400)
      .json({ message: "缺少字段 orderId / isWin / percent" });
  }

  const user = createUserIfNotExists(address);
  const order = orders.get(orderId);

  if (!order) {
    return res.status(400).json({ message: "订单不存在" });
  }

  if (order.wallet !== user.wallet) {
    return res.status(403).json({ message: "不能操作别人的订单" });
  }

  if (order.status === "closed") {
    return res.status(400).json({ message: "订单已结算" });
  }

  // 计算盈亏
  const profit = isWin ? order.amount * percent : -order.amount;

  // 本金 + 盈亏 一起退回或扣完
  user.balances.USDT += order.amount + profit;

  // 更新订单
  order.status = "closed";
  order.closedAt = Date.now();
  order.profit = profit;

  res.json({
    success: true,
    order,
    balances: user.balances,
  });
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
} else if (req.url.startsWith("/ticker")) {
  wsServer.handleUpgrade(req, socket, head, (ws) => {
    ws.path = "ticker";
    ws.query = req.url;  // 保存请求路径，包括 ?symbol=XXX
    wsServer.emit("connection", ws, req);
  });
}
 else {
    socket.destroy();
  }
});

const adminClients = new Set();
const tickerClients = new Set();

function parseSymbol(query) {
  const match = query.match(/symbol=([^&]+)/);
  return match ? match[1].toUpperCase() : "BTCUSDT";
}

wsServer.on("connection", (ws) => {
  if (ws.path === "admin") {
    adminClients.add(ws);
    console.log("Admin WS connected");
    ws.on("close", () => adminClients.delete(ws));
  }

if (ws.path === "ticker") {
  const symbol = parseSymbol(ws.query);
  console.log("📡 用户订阅行情:", symbol);

  // 每个前端一个 Binance WS
  const binanceWS = new WebSocket(
    `wss://stream.binance.com:9443/ws/${symbol.toLowerCase()}@ticker`
  );

  ws.binance = binanceWS;

  binanceWS.on("message", (msg) => {
    if (ws.readyState === WebSocket.OPEN) ws.send(msg);
  });

  binanceWS.on("open", () => {
    console.log("📡 Binance 已连接:", symbol);
  });

  binanceWS.on("close", () => {
    console.log("⚠️ Binance WS closed:", symbol);
  });

  ws.on("close", () => {
    console.log("⚠️ 前端关闭:", symbol);
    if (ws.binance) ws.binance.close();
  });
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
