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

// ⭐ 多币种接口
const priceRouter = require("./routes/price");
app.use("/api/prices", priceRouter);


const PORT = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET || "dev-secret";
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "admin123";

// ========== 内存数据库 ==========
const users = new Map();
const nonces = new Map();
const withdraws = new Map();
const orders = new Map();  

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
    req.user = payload; 
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

  user.loginCount++;
  user.lastLogin = Date.now();
  const ip = req.headers["x-forwarded-for"] || req.socket.remoteAddress || "unknown";
  if (!user.registerIp) user.registerIp = ip;
  user.lastLoginIp = ip;

  const token = jwt.sign({ address }, JWT_SECRET, { expiresIn: "7d" });
  res.json({ token, userId: user.addressLabel, address });
});

// ========== 用户余额 ==========
app.get("/api/user/balance", (req, res) => {
  const auth = req.headers.authorization || "";
  const token = auth.startsWith("Bearer ") ? auth.slice(7) : null;

  if (!token) {
    return res.json({
      userId: "0",
      wallet: "guest",
      balances: { USDT: 0, BTC: 0 },
    });
  }

  try {
    const payload = jwt.verify(token, JWT_SECRET);
    const user = createUserIfNotExists(payload.address);

    return res.json({
      userId: user.addressLabel,
      wallet: user.wallet,
      balances: user.balances,
    });
  } catch {
    return res.json({
      userId: "0",
      wallet: "guest",
      balances: { USDT: 0, BTC: 0 },
    });
  }
});

// ⭐ 用户信息
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

// ====== 用户余额结算 ======
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
  if (!email) return res.status(400).json({ error: "Email is required" });

  console.log("📧 New mail submitted:", email);
  return res.json({ message: "Mail submitted successfully!" });
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
app.post("/api/bankcard", authMiddleware, (req, res) => {
  const { name, cardNumber, bankName } = req.body || {};
  const { address } = req.user;

  if (!name || !cardNumber || !bankName)
    return res.status(400).json({ error: "缺少字段 name/cardNumber/bankName" });

  const user = createUserIfNotExists(address);

  user.bankCard = {
    name,
    cardNumber,
    bankName,
    updatedAt: Date.now(),
  };

  res.json({
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

// 管理员加余额
app.post("/admin/balance/add", adminAuthMiddleware, (req, res) => {
  const { address, symbol, amount } = req.body || {};
  if (!address || !symbol || typeof amount !== "number")
    return res.status(400).json({ message: "缺少字段" });

  const user = createUserIfNotExists(address);
  user.balances[symbol] = (user.balances[symbol] || 0) + amount;

  res.json({ success: true, balances: user.balances });
});

// 用户风控设置
app.post("/admin/user/control", adminAuthMiddleware, (req, res) => {
  const { address, mode, remark } = req.body || {};
  const user = createUserIfNotExists(address);

  if (mode) user.controlMode = mode;
  if (remark !== undefined) user.remark = remark;

  res.json({ success: true, controlMode: user.controlMode, remark: user.remark });
});

// ========== 订单系统 ==========
// 下单接口
app.post("/api/order/create", authMiddleware, (req, res) => {
  const { symbol, amount, direction } = req.body || {}; 
  const { address } = req.user;

  if (!symbol || !amount || !direction) {
    return res
      .status(400)
      .json({ message: "缺少字段 symbol/amount/direction" });
  }

  const user = createUserIfNotExists(address);

  if (user.balances.USDT < amount) {
    return res.status(400).json({ message: "余额不足" });
  }

  user.balances.USDT -= amount;

  const order = {
    id: "ord_" + Date.now(),
    wallet: user.wallet,
    symbol,
    amount,
    direction,
    status: "open",
    profit: 0,
    createdAt: Date.now(),
  };

  orders.set(order.id, order);

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

// 用户订单列表
app.get("/api/order/list", authMiddleware, (req, res) => {
  const { address } = req.user;
  const user = createUserIfNotExists(address);

  const list = Array.from(orders.values()).filter(
    (o) => o.wallet === user.wallet
  );

  res.json(list);
});

// 订单结算
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

  if (!order) return res.status(400).json({ message: "订单不存在" });
  if (order.wallet !== user.wallet) return res.status(403).json({ message: "不能操作别人的订单" });
  if (order.status === "closed") return res.status(400).json({ message: "订单已结算" });

  const profit = isWin ? order.amount * percent : -order.amount;
  user.balances.USDT += order.amount + profit;

  order.status = "closed";
  order.closedAt = Date.now();
  order.profit = profit;

  res.json({
    success: true,
    order,
    balances: user.balances,
  });
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

// ========== 币种 + 实时价格列表 ==========
app.get("/api/coins", async (req, res) => {
  try {
    const symbols = [
      "BTCUSDT","ETHUSDT","BNBUSDT","SOLUSDT","XRPUSDT",
      "DOGEUSDT","ADAUSDT","TRXUSDT","AVAXUSDT","DOTUSDT",
      "LTCUSDT","UNIUSDT","LINKUSDT","ATOMUSDT","ETCUSDT",
      "XMRUSDT","TONUSDT","APTUSDT","NEARUSDT","FTMUSDT",
      "ALGOUSDT","SANDUSDT","MANAUSDT","ICPUSDT","FILUSDT"
    ];

    const reqs = symbols.map(s =>
      fetch(`https://api.binance.com/api/v3/ticker/24hr?symbol=${s}`)
        .then(r => r.json())
        .then(d => ({
          symbol: d.symbol.replace("USDT", ""), // BTC
          price: parseFloat(d.lastPrice).toFixed(4),
          change: parseFloat(d.priceChangePercent).toFixed(2),
          logo: `/images/coins/${d.symbol.replace("USDT", "")}.png`
        }))
    );

    const data = await Promise.all(reqs);

    res.json(data);
  } catch (err) {
    console.log("Error:", err);
    res.status(500).json({ error: "fetch failed" });
  }
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

// ========== WebSocket（仅后台通知用） ==========
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
  } else {
    socket.destroy();
  }
});

const adminClients = new Set();

wsServer.on("connection", (ws) => {
  if (ws.path === "admin") {
    adminClients.add(ws);
    console.log("Admin WS connected");
    ws.on("close", () => adminClients.delete(ws));
  }
});

// 推送后台通知
function broadcastToAdmins(data) {
  const msg = JSON.stringify(data);
  adminClients.forEach((c) => {
    if (c.readyState === WebSocket.OPEN) c.send(msg);
  });
}
