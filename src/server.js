
// ========== 基础依赖 ==========
const express = require("express");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const dotenv = require("dotenv");
const WebSocket = require("ws");
const pool = require("./db"); // PostgreSQL 连接池

dotenv.config();

// Express 初始化
const app = express();
app.use(cors());
app.use(express.json());

// ⭐ 多币种接口
const priceRouter = require("./routes/price");
app.use("/api/prices", priceRouter);

const PORT = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET || "dev-secret";
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "admin123";


// ========== 工具函数：生成随机地址 ==========
function generateFakeEthAddress() {
  const hex = [...Array(40)]
    .map(() => Math.floor(Math.random() * 16).toString(16))
    .join("");
  return "0x" + hex;
}

// =========================================================
//  PostgreSQL: createUserIfNotExists
// =========================================================
async function createUserIfNotExists(address) {
  const addr = address.toLowerCase();

  // 1. 查询用户是否存在
  const result = await pool.query(
    "SELECT * FROM users WHERE address = $1",
    [addr]
  );

  if (result.rows.length > 0) {
    return result.rows[0];
  }

  // 2. 不存在 → 创建
  const addressLabel = "U" + Date.now().toString().slice(-6);

  const insert = await pool.query(
    `INSERT INTO users 
     (address, address_label, balances, created_at, verify_status)
     VALUES ($1, $2, $3, $4, 'success')
     RETURNING *`,
    [
      addr,
      addressLabel,
      JSON.stringify({ USDT: 1000, BTC: 0 }),
      Date.now()
    ]
  );

  return insert.rows[0];
}


// =========================================================
//  Token 中间件
// =========================================================
function authMiddleware(req, res, next) {
  const auth = req.headers.authorization || "";
  const token = auth.startsWith("Bearer ") ? auth.slice(7) : null;

  if (!token) return res.status(401).json({ message: "缺少 token" });

  try {
    req.user = jwt.verify(token, JWT_SECRET);
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


// =========================================================
//  PostgreSQL 版 NONCE
// =========================================================
app.post("/api/auth/nonce", async (req, res) => {
  try {
    const { address } = req.body || {};
    if (!address) return res.status(400).json({ message: "缺少 address" });

    const nonce = Math.floor(Math.random() * 1e9).toString();

    await pool.query(
      `INSERT INTO nonces (address, nonce)
       VALUES ($1, $2)
       ON CONFLICT (address) DO UPDATE SET nonce = $2`,
      [address.toLowerCase(), nonce]
    );

    res.json({ address, nonce });

  } catch (err) {
    console.error("nonce error:", err);
    res.status(500).json({ message: "获取 nonce 失败" });
  }
});


// =========================================================
//  PostgreSQL 版 VERIFY
// =========================================================
app.post("/api/auth/verify", async (req, res) => {
  try {
    const { address, signature } = req.body || {};
    if (!address) return res.status(400).json({ message: "缺少 address" });

    const low = address.toLowerCase();

    // 查询 nonce
    const nonceData = await pool.query(
      "SELECT nonce FROM nonces WHERE address = $1",
      [low]
    );

    if (nonceData.rows.length === 0) {
      return res.status(400).json({ message: "nonce 不存在，请重新获取" });
    }

    // 暂不验证 signature（之后可加）

    // 创建 / 获取用户
    const user = await createUserIfNotExists(low);

    // 更新登录信息
    const ip =
      req.headers["x-forwarded-for"] ||
      req.socket.remoteAddress ||
      "unknown";

    await pool.query(
      `UPDATE users 
       SET login_count = login_count + 1,
           last_login = $1,
           register_ip = COALESCE(register_ip, $2),
           last_login_ip = $2
       WHERE address = $3`,
      [Date.now(), ip, low]
    );

    // 生成 token
    const token = jwt.sign({ address: low }, JWT_SECRET, { expiresIn: "7d" });

    res.json({
      token,
      userId: user.address_label,
      address: low,
    });

  } catch (err) {
    console.error("verify error:", err);
    res.status(500).json({ message: "verify 失败" });
  }
});


// =========================================================
//  游客登录
// =========================================================
app.post("/api/guest-login", async (req, res) => {
  try {
    const guestAddress = generateFakeEthAddress();

    const user = await createUserIfNotExists(guestAddress);

    await pool.query(
      `UPDATE users SET login_count = login_count + 1, last_login = $1 WHERE address = $2`,
      [Date.now(), guestAddress]
    );

    const token = jwt.sign({ address: guestAddress }, JWT_SECRET, {
      expiresIn: "7d",
    });

    res.json({
      data: {
        userId: user.address_label,
        token,
        address: guestAddress,
        isGuest: true,
      }
    });

  } catch (err) {
    console.error("guest login error:", err);
    res.status(500).json({ message: "guest login failed" });
  }
});


// =========================================================
//  获取余额
// =========================================================
app.get("/api/user/balance", async (req, res) => {
  try {
    const auth = req.headers.authorization || "";
    const token = auth.startsWith("Bearer ") ? auth.slice(7) : null;

    if (!token) {
      return res.json({ userId: "0", wallet: "guest", balances: { USDT: 0 } });
    }

    const address = jwt.verify(token, JWT_SECRET).address;

    const r = await pool.query(
      "SELECT address_label, address, balances FROM users WHERE address = $1",
      [address]
    );

    if (r.rows.length === 0) {
      return res.json({ userId: "0", wallet: "guest", balances: { USDT: 0 } });
    }

    const user = r.rows[0];

    res.json({
      userId: user.address_label,
      wallet: user.address,
      balances: user.balances,
    });

  } catch (err) {
    console.error("balance error:", err);
    res.json({ userId: "0", wallet: "guest", balances: { USDT: 0 } });
  }
});


// =========================================================
//  获取用户信息
// =========================================================
app.get("/api/userinfo", authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT * FROM users WHERE address = $1",
      [req.user.address]
    );

    if (result.rows.length === 0)
      return res.status(404).json({ message: "用户不存在" });

    const u = result.rows[0];

    res.json({
      userId: u.address_label,
      wallet: u.address,
      remark: u.remark,
      controlMode: u.control_mode,
      balances: u.balances,
      loginCount: u.login_count,
      lastLogin: u.last_login,
      registerIp: u.register_ip,
      lastLoginIp: u.last_login_ip,
      createdAt: u.created_at,
      verifyStatus: u.verify_status,
    });

  } catch (err) {
    console.error("userinfo error:", err);
    res.status(500).json({ message: "获取用户信息失败" });
  }
});


// =========================================================
//  设置语言
// =========================================================
app.post("/api/language", authMiddleware, async (req, res) => {
  const { language } = req.body || {};
  if (!language) return res.status(400).json({ message: "缺少 language" });

  await pool.query(
    "UPDATE users SET language = $1 WHERE address = $2",
    [language, req.user.address]
  );

  res.json({ success: true, language });
});


// =========================================================
//  绑定银行卡
// =========================================================
app.post("/api/bankcard", authMiddleware, async (req, res) => {
  const { name, cardNumber, bankName } = req.body || {};

  if (!name || !cardNumber || !bankName)
    return res.status(400).json({ message: "缺少字段" });

  await pool.query(
    `UPDATE users 
     SET bankcard = $1 
     WHERE address = $2`,
    [JSON.stringify({ name, cardNumber, bankName, updatedAt: Date.now() }), req.user.address]
  );

  res.json({ success: true });
});


// =========================================================
//  下单
// =========================================================
app.post("/api/order/create", authMiddleware, async (req, res) => {
  try {
    const { symbol, amount, direction } = req.body;
    const address = req.user.address;

    const r = await pool.query(
      "SELECT balances FROM users WHERE address = $1",
      [address]
    );

    const balances = r.rows[0].balances;

    if (balances.USDT < amount)
      return res.status(400).json({ message: "余额不足" });

    balances.USDT -= amount;

    await pool.query(
      "UPDATE users SET balances=$1 WHERE address=$2",
      [balances, address]
    );

    const id = "ord_" + Date.now();
    const createdAt = Date.now();

    await pool.query(
      `INSERT INTO orders(id, wallet, symbol, amount, direction, status, profit, created_at)
       VALUES($1,$2,$3,$4,$5,'open',0,$6)`,
      [id, address, symbol, amount, direction, createdAt]
    );

    res.json({
      success: true,
      order: { id, wallet: address, symbol, amount, direction, status: "open", createdAt },
      balances,
    });

  } catch (err) {
    console.error("order create error:", err);
    res.status(500).json({ message: "下单失败" });
  }
});


// =========================================================
//  查询订单
// =========================================================
app.get("/api/order/list", authMiddleware, async (req, res) => {
  try {
    const r = await pool.query(
      "SELECT * FROM orders WHERE wallet = $1 ORDER BY created_at DESC",
      [req.user.address]
    );

    res.json(r.rows);

  } catch (err) {
    console.error("order list error:", err);
    res.status(500).json({ message: "获取订单列表失败" });
  }
});


// =========================================================
//  订单结算
// =========================================================
app.post("/api/order/settle", authMiddleware, async (req, res) => {
  try {
    const { orderId, isWin, percent } = req.body;
    const address = req.user.address;

    const orderResult = await pool.query(
      "SELECT * FROM orders WHERE id=$1",
      [orderId]
    );

    if (orderResult.rows.length === 0)
      return res.status(400).json({ message: "订单不存在" });

    const order = orderResult.rows[0];

    if (order.wallet !== address)
      return res.status(403).json({ message: "不能操作别人的订单" });

    if (order.status === "closed")
      return res.status(400).json({ message: "订单已结算" });

    const profit = isWin ? order.amount * percent : -order.amount;

    const userResult = await pool.query(
      "SELECT balances FROM users WHERE address=$1",
      [address]
    );

    const balances = userResult.rows[0].balances;

    balances.USDT += order.amount + profit;

    await pool.query(
      "UPDATE users SET balances=$1 WHERE address=$2",
      [balances, address]
    );

    const closedAt = Date.now();

    await pool.query(
      `UPDATE orders SET status='closed', profit=$1, closed_at=$2 WHERE id=$3`,
      [profit, closedAt, orderId]
    );

    res.json({
      success: true,
      order: { ...order, status: "closed", profit, closed_at: closedAt },
      balances,
    });

  } catch (err) {
    console.error("order settle error:", err);
    res.status(500).json({ message: "订单结算失败" });
  }
});


// =========================================================
//  提币
// =========================================================
app.post("/api/withdraw/create", authMiddleware, async (req, res) => {
  try {
    const { symbol, amount, address: withdrawAddress } = req.body;
    const wallet = req.user.address;

    const r = await pool.query(
      "SELECT balances, remark FROM users WHERE address=$1",
      [wallet]
    );

    const user = r.rows[0];
    const balances = user.balances;

    if ((balances[symbol] || 0) < amount)
      return res.status(400).json({ message: "余额不足" });

    balances[symbol] -= amount;

    await pool.query(
      "UPDATE users SET balances=$1 WHERE address=$2",
      [balances, wallet]
    );

    const wid = "wd_" + Date.now();

    await pool.query(
      `INSERT INTO withdraws(id, wallet, symbol, amount, withdraw_address, remark, status, created_at)
       VALUES($1,$2,$3,$4,$5,$6,'pending',$7)`,
      [wid, wallet, symbol, amount, withdrawAddress, user.remark, Date.now()]
    );

    res.json({
      success: true,
      withdraw: { id: wid, wallet, symbol, amount, withdrawAddress, status: "pending" },
      balances
    });

  } catch (err) {
    console.error("withdraw error:", err);
    res.status(500).json({ message: "提现失败" });
  }
});


// =========================================================
//  查询提现记录
// =========================================================
app.get("/api/withdraw/list", authMiddleware, async (req, res) => {
  try {
    const r = await pool.query(
      "SELECT * FROM withdraws WHERE wallet=$1 ORDER BY created_at DESC",
      [req.user.address]
    );

    res.json(r.rows);

  } catch (err) {
    console.error("withdraw list error:", err);
    res.status(500).json({ message: "获取提现列表失败" });
  }
});


// =========================================================
//  管理员：审核提现
// =========================================================
app.post("/admin/withdraw/approve", adminAuthMiddleware, async (req, res) => {
  const { id } = req.body;
  const r = await pool.query(
    "UPDATE withdraws SET status='approved' WHERE id=$1 RETURNING *",
    [id]
  );
  res.json({ success: true, withdraw: r.rows[0] });
});

app.post("/admin/withdraw/reject", adminAuthMiddleware, async (req, res) => {
  const { id, reason } = req.body;
  const r = await pool.query(
    "UPDATE withdraws SET status='rejected', reason=$1 WHERE id=$2 RETURNING *",
    [reason || "管理员拒绝", id]
  );
  res.json({ success: true, withdraw: r.rows[0] });
});


// =========================================================
//  管理员系统
// =========================================================
app.post("/admin/login", (req, res) => {
  const { password } = req.body;
  if (password !== ADMIN_PASSWORD)
    return res.status(401).json({ message: "密码错误" });

  const token = jwt.sign({ role: "admin" }, JWT_SECRET, { expiresIn: "1d" });
  res.json({ adminToken: token });
});

app.get("/admin/users", adminAuthMiddleware, async (req, res) => {
  const r = await pool.query("SELECT * FROM users ORDER BY id DESC");
  const rows = r.rows;

  const users = await Promise.all(
    rows.map(async (u) => {
      // ⭐ 根据 IP 获取位置
      const location = await ipToLocation(u.register_ip || u.last_login_ip);

      return {
        userId: u.address_label,      // ID：如 U556622
        wallet: u.address,            // 账号（钱包地址）
        remark: u.remark,             // 备注

        // ===== 登录信息 =====
        loginCount: u.login_count,    // 登录次数
        lastLogin: u.last_login,      // 登录时间（毫秒）

        // ===== 注册信息 =====
        registerIp: u.register_ip,    // 注册时 IP
        createdAt: u.created_at,      // 注册时时间（毫秒）

        // ===== 地址（解析 IP 得来）=====
        addressLabel: location,       // 例如：美国/纽约

        // ===== 其他 =====
        verifyStatus: u.verify_status,
        controlMode: u.control_mode,
        balances: u.balances || {},
      };
    })
  );

  res.json(users);
});




app.get("/admin/orders", adminAuthMiddleware, async (req, res) => {
  const r = await pool.query("SELECT * FROM orders ORDER BY created_at DESC");
  res.json(r.rows);
});

app.post("/admin/balance/add", adminAuthMiddleware, async (req, res) => {
  const { address, symbol, amount } = req.body;

  const r = await pool.query(
    "SELECT balances FROM users WHERE address=$1",
    [address]
  );

  if (r.rows.length === 0)
    return res.status(400).json({ message: "用户不存在" });

  const balances = r.rows[0].balances;
  balances[symbol] = (balances[symbol] || 0) + amount;

  await pool.query(
    "UPDATE users SET balances=$1 WHERE address=$2",
    [balances, address]
  );

  res.json({ success: true, balances });
});


// =========================================================
//  行情与 K线
// =========================================================
let cachedCoins = null;
let lastFetchTime = 0;

app.get("/api/coins", async (req, res) => {
  const now = Date.now();
  if (cachedCoins && now - lastFetchTime < 3000)
    return res.json(cachedCoins);

  try {
    const symbols = [
      "BTC-USDT","ETH-USDT","BNB-USDT","SOL-USDT","XRP-USDT",
      "DOGE-USDT","ADA-USDT","TRX-USDT","AVAX-USDT","DOT-USDT",
      "LTC-USDT","LINK-USDT","ATOM-USDT","FIL-USDT","BCH-USDT",
      "MATIC-USDT","TON-USDT","ICP-USDT","APT-USDT","NEAR-USDT",
      "SAND-USDT","MANA-USDT","ARB-USDT","OP-USDT","SUI-USDT"
    ];

    const reqs = symbols.map(async inst => {
      try {
        const r = await fetch(`https://www.okx.com/api/v5/market/ticker?instId=${inst}`);
        const j = await r.json();
        const d = j.data?.[0];
        if (!d) return null;

        const sym = inst.replace("-USDT", "");
        const open = parseFloat(d.open24h);
        const last = parseFloat(d.last);
        const change = ((last - open) / open) * 100;

        return {
          symbol: sym,
          price: last.toFixed(4),
          change: change.toFixed(2),
          logo: `https://cryptoicons.org/api/icon/${sym.toLowerCase()}/64`,
        };
      } catch {
        return null;
      }
    });

    const coins = (await Promise.all(reqs)).filter(Boolean);

    cachedCoins = coins;
    lastFetchTime = now;

    res.json(coins);

  } catch (err) {
    console.error("OKX error:", err);
    res.status(500).json({ error: "fetch failed" });
  }
});

app.get("/api/kline", async (req, res) => {
  const { symbol = "BTCUSDT", interval = "1m", limit = 200 } = req.query;

  try {
    const r = await fetch(
      `https://api.binance.com/api/v3/klines?symbol=${symbol}&interval=${interval}&limit=${limit}`
    );
    res.json(await r.json());
  } catch {
    res.status(500).json({ message: "kline error" });
  }
});


// =========================================================
//  WebSocket（后台通知）
// =========================================================
const server = app.listen(PORT, () => {
  console.log(`Backend running on http://localhost:${PORT}`);
});

const wsServer = new WebSocket.Server({ noServer: true });
const adminClients = new Set();

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
// 若 Node 版本 >= 18，不需要额外安装 fetch。
// 若你 Node < 18，需要：npm i node-fetch，再解除下面注释：
// const fetch = (...args) => import('node-fetch').then(({default: fetch}) => fetch(...args));

// 内部缓存（避免同一个 IP 反复查询）
const ipCache = new Map();

async function ipToLocation(ip) {
  if (!ip || ip === "-" || ip === "unknown") return "未知";

  if (ipCache.has(ip)) return ipCache.get(ip);

  try {
    const resp = await fetch(`http://ip-api.com/json/${ip}?lang=zh-CN`);
    const data = await resp.json();

    if (data.status === "success") {
      const country = data.country || "";
      const city = data.city || "";
      const text = `${country}${city ? '/' + city : ''}`;
      ipCache.set(ip, text);
      return text;
    }
  } catch {}

  return "未知";
}

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
