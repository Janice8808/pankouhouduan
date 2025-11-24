
// ========== 基础依赖 ==========
const express = require("express");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const dotenv = require("dotenv");
const WebSocket = require("ws");
const pool = require("./db"); // PostgreSQL 连接池
const cookieParser = require("cookie-parser");

dotenv.config();

// Express 初始化
const app = express();

// ⭐ 允许携带 Cookie 的 CORS
app.use(
  cors({
    origin: true,          // 自动回显 Origin
    credentials: true,     // 允许带 Cookie
  })
);



app.use(express.json());
app.use(cookieParser());   // ⭐ 这里启用 cookie 解析

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
// =========================================================
//  PostgreSQL: createUserIfNotExists（固定 UID 递增版）
// =========================================================
async function createUserIfNotExists(address) {
  const addr = address.toLowerCase();

  // 1. 查询用户是否存在
  const result = await pool.query(
    "SELECT * FROM users WHERE address = $1",
    [addr]
  );

  if (result.rows.length > 0) {
    let user = result.rows[0];

    // ⭐ 如果 address_label 为空 → 补 UID
    if (!user.address_label) {
      const uid = 200100 + (user.id - 1);
      await pool.query(
        "UPDATE users SET address_label=$1 WHERE id=$2",
        [uid.toString(), user.id]
      );
      user.address_label = uid.toString();
    }

    return user;
  }

  // 2. 如果不存在 → 创建用户
  const insert = await pool.query(
    `INSERT INTO users (address, balances, created_at, verify_status)
     VALUES ($1, $2, $3, 'success')
     RETURNING *`,
    [
      addr,
      JSON.stringify({ USDT: 1000, BTC: 0 }),
      Date.now()
    ]
  );

  const user = insert.rows[0];

  // ⭐ 生成 UID：从 200100 开始递增
  const uid = 200100 + (user.id - 1);

  await pool.query(
    "UPDATE users SET address_label=$1 WHERE id=$2",
    [uid.toString(), user.id]
  );

  user.address_label = uid.toString();

  return user;
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
//  PostgreSQL 版 VERIFY（正常登录）
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

    // 创建 / 获取用户
    const user = await createUserIfNotExists(low);

    // ⭐⭐ 获取真实用户 IP（Render / Cloudflare / Nginx / 本地 都支持）
    const ip =
      req.headers["x-forwarded-for"]?.split(",")[0]?.trim() ||
      req.headers["x-real-ip"] ||
      req.socket.remoteAddress ||
      "unknown";

    // 更新登录信息
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



// 游客登录（使用前端提供的永久 UID）
app.post("/api/guest-login", async (req, res) => {
  try {
    const { address } = req.body || {};
    if (!address) return res.status(400).json({ message: "缺少 address" });

    const guestAddress = address.toLowerCase();

    // 创建 / 获取用户
    const user = await createUserIfNotExists(guestAddress);

    // 记录 IP
    const ip =
      req.headers["x-forwarded-for"]?.split(",")[0]?.trim() ||
      req.headers["x-real-ip"] ||
      req.socket.remoteAddress ||
      "unknown";

    await pool.query(
      `UPDATE users
       SET login_count = login_count + 1,
           last_login = $1,
           register_ip = COALESCE(register_ip, $2),
           last_login_ip = $2
       WHERE address = $3`,
      [Date.now(), ip, guestAddress]
    );

    // 生成 token
    const token = jwt.sign(
      { address: guestAddress },
      JWT_SECRET,
      { expiresIn: "7d" }
    );

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
//  心跳接口：前台每次打开 or 刷新页面都会调用
// =========================================================
app.post("/api/ping", authMiddleware, async (req, res) => {
  try {
    const address = req.user.address;

    await pool.query(
      `UPDATE users 
       SET last_seen = $1 
       WHERE address = $2`,
      [Date.now(), address]
    );

    res.json({ success: true });

  } catch (err) {
    console.error("ping error:", err);
    res.status(500).json({ message: "ping failed" });
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
//  控输赢
// =========================================================

app.post("/admin/user/control", adminAuthMiddleware, async (req, res) => {
  const { address, mode, remark } = req.body;

  if (!address) return res.status(400).json({ message: "缺少 address" });

  await pool.query(
    `UPDATE users 
     SET control_mode = $1, 
         remark = $2
     WHERE address = $3`,
    [mode || 'normal', remark || '', address.toLowerCase()]
  );

  res.json({ success: true });
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

  // ⭐ 获取用户备注（因为上面的查询不包含 remark 字段）
const remarkResult = await pool.query(
  "SELECT remark FROM users WHERE address=$1",
  [address]
);

const userRemark = remarkResult.rows?.[0]?.remark || "";

// ⭐ 推送后台
broadcastToAdmins({
  type: "NEW_ORDER",
  order: {
    id,
    wallet: address,
    symbol,
    amount,
    direction,
    createdAt,
    remark: userRemark,
  }
});


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
//  订单结算（全面修复版）
// =========================================================
app.post("/api/order/settle", authMiddleware, async (req, res) => {
  try {
    const { orderId, isWin, percent } = req.body;
    const address = req.user.address;

    // ① 获取订单
    const orderResult = await pool.query(
      "SELECT * FROM orders WHERE id=$1",
      [orderId]
    );
    if (orderResult.rows.length === 0)
      return res.status(400).json({ message: "订单不存在" });

    const order = orderResult.rows[0];

    // ② 校验归属
    if (order.wallet !== address)
      return res.status(403).json({ message: "不能操作别人的订单" });

    if (order.status === "closed")
      return res.status(400).json({ message: "订单已结算" });

    // ============== ⭐⭐ 全部强制数字化 ⭐⭐ ==============
    const orderAmount = Number(order.amount) || 0;
    const pct = Number(percent) || 0;

    // ③ 计算盈利
    const profit = isWin ? orderAmount * pct : -orderAmount;

    // ④ 获取余额
    const userResult = await pool.query(
      "SELECT balances FROM users WHERE address=$1",
      [address]
    );
    const balances = userResult.rows[0].balances;

    // ⭐ 永远强制数字化，并避免 NaN
    const currentUSDT = Number(balances.USDT) || 0;

    // ⑤ 更新余额（本金 + 盈利）
    balances.USDT = currentUSDT + orderAmount + profit;

    // ⭐ 防止负数 + NaN
    if (isNaN(balances.USDT)) balances.USDT = currentUSDT;

    // ⑥ 写回数据库
    await pool.query(
      "UPDATE users SET balances=$1 WHERE address=$2",
      [balances, address]
    );

    const closedAt = Date.now();

    // ⑦ 更新订单
    await pool.query(
      `UPDATE orders SET status='closed', profit=$1, closed_at=$2 WHERE id=$3`,
      [profit, closedAt, orderId]
    );

    // ⑧ 推送管理员
    broadcastToAdmins({
      type: "ORDER_SETTLED",
      order: {
        id: orderId,
        wallet: address,
        profit,
        isWin,
        closedAt,
      }
    });

    // ⑨ 返回最终数据
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
//  管理员：减少余额
// =========================================================
app.post("/admin/balance/sub", adminAuthMiddleware, async (req, res) => {
  const { address, symbol, amount } = req.body;

  const r = await pool.query(
    "SELECT balances FROM users WHERE address=$1",
    [address]
  );

  if (r.rows.length === 0)
    return res.status(400).json({ message: "用户不存在" });

  const balances = r.rows[0].balances;
  balances[symbol] = (balances[symbol] || 0) - Math.abs(amount);

  await pool.query(
    "UPDATE users SET balances=$1 WHERE address=$2",
    [balances, address]
  );

  res.json({ success: true, balances });
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
//  管理员发送通知给指定用户
// =========================================================
app.post("/admin/notify", adminAuthMiddleware, async (req, res) => {
  const { address, title, content } = req.body;

  if (!address || !content)
    return res.status(400).json({ message: "缺少字段" });

  await pool.query(
    `INSERT INTO notifications(user_address, title, content, unread, created_at)
     VALUES($1,$2,$3,TRUE,$4)`,
    [address.toLowerCase(), title || "", content, Date.now()]
  );

  res.json({ success: true });
});

// =========================================================
//  用户获取自己的通知列表
// =========================================================
app.get("/api/notice/list", authMiddleware, async (req, res) => {
  const address = req.user.address;

  const r = await pool.query(
    `SELECT * FROM notifications 
     WHERE user_address=$1 
     ORDER BY created_at DESC`,
    [address]
  );

  res.json(r.rows);
});

// =========================================================
//  用户阅读通知 → 将未读全部标记为已读
// =========================================================
app.post("/api/notice/read", authMiddleware, async (req, res) => {
  const address = req.user.address;

  await pool.query(
    `UPDATE notifications 
     SET unread = FALSE 
     WHERE user_address = $1 AND unread = TRUE`,
    [address]
  );

  res.json({ success: true });
});

// =========================================================
//  获取用户未读通知数量
// =========================================================
app.get("/api/notice/unread", authMiddleware, async (req, res) => {
  const address = req.user.address;

  const r = await pool.query(
    `SELECT COUNT(*) FROM notifications 
     WHERE user_address=$1 AND unread=TRUE`,
    [address]
  );

  res.json({ unread: Number(r.rows[0].count) });
});


app.post("/admin/notice/send",
  adminAuthMiddleware,
  async (req, res) => {
    try {
      const { address, title, content } = req.body;

      if (!address) return res.status(400).json({ message: "缺少用户地址" });

      const now = Date.now();

      await pool.query(
        `INSERT INTO notifications(user_address, title, content, unread, created_at)
         VALUES($1, $2, $3, true, $4)`,
        [address.toLowerCase(), title || "", content || "", now]
      );

      broadcastToUser(address, {
        type: "NEW_NOTICE",
        title,
        content,
        createdAt: now,
      });

      res.json({ success: true });
    } catch (err) {
      console.error(err);
      res.status(500).json({ message: "发送通知失败" });
    }
  }
);


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
  // ⭐ 按 UID 数字排序，非数字排最后，不崩溃
  const r = await pool.query(`
    SELECT * FROM users 
    ORDER BY 
      CASE 
        WHEN address_label ~ '^[0-9]+$' THEN address_label::bigint
        ELSE 0
      END DESC
  `);

  const rows = r.rows;

  const users = await Promise.all(
    rows.map(async (u) => {
      const location = await ipToLocation(u.register_ip || u.last_login_ip);

      return {
        userId: u.address_label,
        wallet: u.address,
        remark: u.remark,
        loginCount: u.login_count,
        lastLogin: u.last_login,
        lastSeen: u.last_seen,
        registerIp: u.register_ip,
        createdAt: u.created_at,
        addressLabel: location,
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
  if (req.url.startsWith("/admin-ws")) {
    wsServer.handleUpgrade(req, socket, head, (ws) => {
      ws.path = "admin";
      wsServer.emit("connection", ws, req);
    });
  } else if (req.url.startsWith("/user-ws")) {
    wsServer.handleUpgrade(req, socket, head, (ws) => {
      ws.path = "user";
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

const userClients = new Map(); // address -> ws

wsServer.on("connection", (ws) => {
  if (ws.path === "admin") {
    adminClients.add(ws);
    console.log("Admin WS connected");
    ws.on("close", () => adminClients.delete(ws));
  }

  if (ws.path === "user") {
    console.log("User WS connected");

    ws.on("message", (msg) => {
      let data;
      try {
        data = JSON.parse(msg);
      } catch {
        return;
      }

      if (data.type === "AUTH" && data.token) {
        const payload = jwt.verify(data.token, JWT_SECRET);
        const address = payload.address.toLowerCase();

        userClients.set(address, ws);
        console.log("User authenticated:", address);

        ws.on("close", () => userClients.delete(address));
      }
    });
  }
});

// 推送后台通知
function broadcastToAdmins(data) {
  const msg = JSON.stringify(data);
  adminClients.forEach((c) => {
    if (c.readyState === WebSocket.OPEN) c.send(msg);
  });
}
function broadcastToUser(address, msg) {
  const ws = userClients.get(address.toLowerCase());
  if (ws && ws.readyState === WebSocket.OPEN) {
    ws.send(JSON.stringify(msg));
  }
}
