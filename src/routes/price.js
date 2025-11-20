import express from "express";
import fetch from "node-fetch";

const router = express.Router();

// 缓存避免频繁请求币安（1秒）
let cache = {};
let lastFetchTime = 0;

router.get("/", async (req, res) => {
  const now = Date.now();

  if (now - lastFetchTime < 1000 && cache) {
    return res.json(cache);
  }

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
          symbol: d.symbol.replace("USDT", ""),
          price: parseFloat(d.lastPrice),
          change: parseFloat(d.priceChangePercent),
        }))
    );

    const data = await Promise.all(reqs);

    cache = data;
    lastFetchTime = now;

    res.json(data);
  } catch (err) {
    res.status(500).json({ error: "Binance fetch error" });
  }
});

export default router;
