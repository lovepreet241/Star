require('dotenv').config();
const express = require('express');
const cors = require('cors');
const fs = require('fs');
const crypto = require('crypto');
const Database = require('better-sqlite3');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());

app.use((req, res, next) => {
  res.set("Cache-Control", "no-store, no-cache, must-revalidate, private");
  res.set("Pragma", "no-cache");
  res.set("Expires", "0");
  next();
});


const db = new Database('/var/www/spaceid/database.sqlite');
db.pragma('journal_mode = WAL');

// Referral eligibility: existing users default to ineligible.
const userColumns = db.prepare("PRAGMA table_info(users)").all();
if (!userColumns.some(col => col.name === "referralEligible")) {
  db.exec("ALTER TABLE users ADD COLUMN referralEligible INTEGER NOT NULL DEFAULT 0");
}


// Settings APIs
app.get('/api/settings', (req, res) => {
  try {
    const row = db.prepare('SELECT data FROM settings WHERE id = 1').get();
    if (row && row.data) return res.json(JSON.parse(row.data));
    res.json({});
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/admin/save', (req, res) => {
  const auth = verifyTelegramInitData(req.body?.initData);
  if (!auth.ok) return res.status(401).json({ success: false, error: auth.error });
  if (String(auth.user.id) !== "7982111846") {
    return res.status(403).json({ success: false, error: "Admin access denied." });
  }
  try {
    const allowed = ["withdrawMode","withdrawDate","coinName","coinSymbol","minWithdraw","metRateUsd","depositAddress","requiredEthFee","tgVerifyOn","depositOn","depositOffMsg","tgChannel"];
    const row = db.prepare("SELECT data FROM settings WHERE id=1").get();
    const current = row?.data ? JSON.parse(row.data) : {};
    for (const key of allowed) {
      if (Object.prototype.hasOwnProperty.call(req.body, key)) current[key] = req.body[key];
    }
    if (current.tgVerifyOn && !String(current.tgChannel || "").trim()) {
      return res.status(400).json({ success: false, error: "Telegram channel is required." });
    }
    db.prepare("INSERT OR REPLACE INTO settings (id,data) VALUES (1,?)").run(JSON.stringify(current, null, 2));
    return res.json({ success: true });
  } catch (err) {
    return res.status(500).json({ success: false, error: "Settings could not be saved." });
  }
});

// User Sync API
// Legacy insecure balance sync disabled.
app.post('/api/sync-user', (req, res) => {
  return res.status(410).json({
    success: false,
    error: "Legacy balance sync is disabled. Use authenticated server APIs."
  });
});

// Get User Data API
app.get('/api/user-data/:id', (req, res) => {
  try {
    const row = db.prepare('SELECT * FROM users WHERE userId = ?').get(String(req.params.id));
    if (row) {
      return res.json({
        userId: row.userId,
        username: row.username,
        firstName: row.firstName,
        balance: row.balance,
        eth: row.eth,
        userWallet: row.userWallet,
        refTotal: row.refTotal,
        referredBy: row.referredBy,
        completedTasks: row.completedTasks ? JSON.parse(row.completedTasks) : []
      });
    }
    res.json({});
  } catch (err) { res.json({}); }
});

// Legacy insecure referral endpoint disabled.
// New referrals must use signed Telegram initData.
app.post('/api/track-referral', (req, res) => {
  return res.status(410).json({
    success: false,
    error: "Please use the secure referral system."
  });
});

// Withdrawals API
app.post('/api/withdraw-request', (req, res) => {
  try {
    const { userId, username, amount, wallet } = req.body;
    db.prepare('INSERT INTO withdrawals (userId, username, amount, wallet, createdAt) VALUES (?, ?, ?, ?, ?)').run(
      String(userId), username || "", Number(amount) || 0, wallet || "", new Date().toISOString()
    );
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/admin/withdrawals', (req, res) => {
  try {
    res.json(db.prepare('SELECT * FROM withdrawals ORDER BY id DESC').all());
  } catch (err) { res.json([]); }
});


// Telegram Mini App authentication
function verifyTelegramInitData(initData) {
  if (!process.env.BOT_TOKEN || !initData) {
    return { ok: false, error: "Authentication unavailable" };
  }

  try {
    const params = new URLSearchParams(initData);
    const receivedHash = params.get("hash");

    if (!receivedHash || !/^[a-f0-9]{64}$/i.test(receivedHash)) {
      return { ok: false, error: "Invalid Telegram authentication" };
    }

    const pairs = [...params.entries()]
      .filter(([key]) => key !== "hash")
      .sort(([a], [b]) => a.localeCompare(b));

    const dataCheckString = pairs
      .map(([key, value]) => `${key}=${value}`)
      .join("\n");

    const secretKey = crypto
      .createHmac("sha256", "WebAppData")
      .update(process.env.BOT_TOKEN)
      .digest();

    const calculatedHash = crypto
      .createHmac("sha256", secretKey)
      .update(dataCheckString)
      .digest("hex");

    const received = Buffer.from(receivedHash, "hex");
    const calculated = Buffer.from(calculatedHash, "hex");

    if (
      received.length !== calculated.length ||
      !crypto.timingSafeEqual(received, calculated)
    ) {
      return { ok: false, error: "Telegram authentication failed" };
    }

    const authDate = Number(params.get("auth_date"));
    const now = Math.floor(Date.now() / 1000);

    if (
      !Number.isFinite(authDate) ||
      authDate > now + 60 ||
      now - authDate > 86400
    ) {
      return { ok: false, error: "Telegram session expired. Reopen the app." };
    }

    const user = JSON.parse(params.get("user") || "null");

    if (!user || !user.id) {
      return { ok: false, error: "Telegram user missing" };
    }

    return { ok: true, user };
  } catch (error) {
    return { ok: false, error: "Invalid Telegram authentication data" };
  }
}


// Server-authoritative task rewards
const DEFAULT_TASKS = [
  { id: 201, title: "Join Telegram Channel", sub: "Telegram channel", met: 100, eth: 0.0003, link: "", verify: "telegram", chat: "" },
  { id: 202, title: "Follow Twitter Page", sub: "X (Twitter) page", met: 75, eth: 0.0002, link: "", verify: "", chat: "" },
  { id: 203, title: "Join Telegram Folder", sub: "Telegram folder", met: 50, eth: 0.0001, link: "", verify: "", chat: "" }
];

function getTaskSettings() {
  const row = db.prepare("SELECT data FROM settings WHERE id=1").get();
  const settings = row?.data ? JSON.parse(row.data) : {};
  return { settings, tasks: Array.isArray(settings.tasks) ? settings.tasks : DEFAULT_TASKS };
}

app.get("/api/tasks", (req, res) => {
  try {
    const { tasks } = getTaskSettings();
    res.json({ success: true, tasks });
  } catch (err) {
    res.status(500).json({ success: false, error: "Could not load tasks." });
  }
});

app.post("/api/tasks/save", (req, res) => {
  const auth = verifyTelegramInitData(req.body?.initData);
  if (!auth.ok) return res.status(401).json({ success: false, error: auth.error });
  if (String(auth.user.id) !== "7982111846") {
    return res.status(403).json({ success: false, error: "Admin access denied." });
  }
  try {
    const input = req.body?.tasks;
    if (!Array.isArray(input) || input.length > 50) {
      return res.status(400).json({ success: false, error: "Invalid task list." });
    }
    const ids = new Set();
    const tasks = input.map(t => {
      const id = Number(t.id);
      const title = String(t.title || "").trim().slice(0, 100);
      const met = Number(t.met);
      const eth = Number(t.eth);
      if (!Number.isSafeInteger(id) || ids.has(id) || !title ||
          !Number.isFinite(met) || met < 0 || met > 1000000 ||
          !Number.isFinite(eth) || eth < 0 || eth > 10) {
        throw new Error("Invalid task details.");
      }
      ids.add(id);
      return {
        id, title,
        sub: String(t.sub || "").slice(0, 160),
        met, eth,
        link: String(t.link || "").slice(0, 1000),
        verify: t.verify === "telegram" ? "telegram" : "",
        chat: String(t.chat || "").slice(0, 100)
      };
    });
    const row = db.prepare("SELECT data FROM settings WHERE id=1").get();
    const settings = row?.data ? JSON.parse(row.data) : {};
    settings.tasks = tasks;
    db.prepare("INSERT OR REPLACE INTO settings (id,data) VALUES (1,?)")
      .run(JSON.stringify(settings, null, 2));
    res.json({ success: true, tasks });
  } catch (err) {
    res.status(400).json({ success: false, error: err.message || "Could not save tasks." });
  }
});

app.post("/api/tasks/claim", async (req, res) => {
  const auth = verifyTelegramInitData(req.body?.initData);
  if (!auth.ok) return res.status(401).json({ success: false, error: auth.error });

  try {
    const userId = String(auth.user.id);
    const taskId = Number(req.body?.taskId);
    const { settings, tasks } = getTaskSettings();
    const task = tasks.find(t => Number(t.id) === taskId);
    if (!task) return res.status(404).json({ success: false, error: "Task not found." });

    if (settings.tgVerifyOn && task.verify === "telegram") {
      const channel = String(settings.tgChannel || "").trim();
      if (!channel || !process.env.BOT_TOKEN) {
        return res.status(400).json({ success: false, error: "Telegram verification is not configured." });
      }
      const url = `https://api.telegram.org/bot${process.env.BOT_TOKEN}/getChatMember?chat_id=${encodeURIComponent(channel)}&user_id=${encodeURIComponent(userId)}`;
      const tgRes = await fetch(url);
      const tgData = await tgRes.json();
      const member = tgData?.result;
      const joined = tgData?.ok && member &&
        (["creator", "administrator", "member"].includes(member.status) ||
         (member.status === "restricted" && member.is_member === true));
      if (!joined) return res.status(403).json({ success: false, error: "Join the Telegram channel first." });
    }

    const now = new Date().toISOString();
    const claim = db.transaction(() => {
      db.prepare(`
        INSERT OR IGNORE INTO users
        (userId, username, firstName, balance, eth, refTotal, completedTasks, lastUpdated, referralEligible)
        VALUES (?, ?, ?, 200, 0, 0, '[]', ?, 1)
      `).run(userId, auth.user.username || "", auth.user.first_name || "", now);

      const user = db.prepare("SELECT balance, eth, completedTasks FROM users WHERE userId=?").get(userId);
      let completed = [];
      try { completed = user.completedTasks ? JSON.parse(user.completedTasks) : []; } catch (_) {}
      if (!Array.isArray(completed)) completed = [];
      if (completed.map(String).includes(String(taskId))) {
        return { already: true, balance: user.balance, eth: user.eth, completedTasks: completed };
      }

      const balance = Number(user.balance || 0) + Number(task.met || 0);
      const eth = Number(user.eth || 0) + Number(task.eth || 0);
      completed.push(taskId);
      db.prepare("UPDATE users SET balance=?, eth=?, completedTasks=?, lastUpdated=? WHERE userId=?")
        .run(balance, eth, JSON.stringify(completed), now, userId);
      return { already: false, balance, eth, completedTasks: completed };
    })();

    res.json({ success: true, alreadyClaimed: claim.already, balance: claim.balance, eth: claim.eth, completedTasks: claim.completedTasks });
  } catch (err) {
    res.status(500).json({ success: false, error: "Task claim failed." });
  }
});

app.post("/api/auth", (req, res) => {
  const result = verifyTelegramInitData(req.body?.initData);

  if (!result.ok) {
    return res.status(401).json({
      success: false,
      error: result.error
    });
  }

  res.json({
    success: true,
    user: {
      id: String(result.user.id),
      username: result.user.username || "",
      firstName: result.user.first_name || ""
    }
  });
});


// Authenticated current-user API. Existing balances are never overwritten here.
app.post("/api/me", (req, res) => {
  const auth = verifyTelegramInitData(req.body?.initData);

  if (!auth.ok) {
    return res.status(401).json({ success: false, error: auth.error });
  }

  try {
    const user = auth.user;
    const userId = String(user.id);
    const username = user.username || "";
    const firstName = user.first_name || "";
    const now = new Date().toISOString();

    db.prepare(`
      INSERT OR IGNORE INTO users
      (userId, username, firstName, balance, eth, refTotal, completedTasks, lastUpdated, referralEligible)
      VALUES (?, ?, ?, 200, 0, 0, '[]', ?, 1)
    `).run(userId, username, firstName, now);

    db.prepare(`
      UPDATE users
      SET username = ?, firstName = ?
      WHERE userId = ?
    `).run(username, firstName, userId);

    const row = db.prepare(
      "SELECT * FROM users WHERE userId = ?"
    ).get(userId);

    return res.json({
      success: true,
      user: {
        userId: row.userId,
        username: row.username,
        firstName: row.firstName,
        balance: row.balance,
        eth: row.eth,
        userWallet: row.userWallet,
        refTotal: row.refTotal,
        referredBy: row.referredBy,
        completedTasks: row.completedTasks ? JSON.parse(row.completedTasks) : []
      }
    });
  } catch (err) {
    return res.status(500).json({ success: false, error: "Could not load user data" });
  }
});



// Secure Telegram referral system
db.exec(`
  CREATE TABLE IF NOT EXISTS referral_claims (
    referredUserId TEXT PRIMARY KEY,
    referrerId TEXT NOT NULL,
    reward REAL NOT NULL DEFAULT 350,
    createdAt TEXT NOT NULL
  )
`);

app.post("/api/referral/register", (req, res) => {
  const initData = req.body?.initData;
  const auth = verifyTelegramInitData(initData);

  if (!auth.ok) {
    return res.status(401).json({ success: false, error: auth.error });
  }

  try {
    const params = new URLSearchParams(initData);
    const startParam = params.get("start_param") || "";
    const match = startParam.match(/^ref_(\d+)$/);

    if (!match) {
      return res.json({ success: false, error: "No valid referral link." });
    }

    const referrerId = match[1];
    const referredUserId = String(auth.user.id);

    if (referrerId === referredUserId) {
      return res.json({ success: false, error: "Self referral is not allowed." });
    }

    const now = new Date().toISOString();

    const result = db.transaction(() => {
      db.prepare(`
        INSERT OR IGNORE INTO users
        (userId, username, firstName, balance, eth, refTotal, completedTasks, lastUpdated, referralEligible)
        VALUES (?, ?, ?, 200, 0, 0, '[]', ?, 1)
      `).run(
        referredUserId,
        auth.user.username || "",
        auth.user.first_name || "",
        now
      );

      const newUser = db.prepare(
        "SELECT userId, referredBy, referralEligible FROM users WHERE userId = ?"
      ).get(referredUserId);

      const referrer = db.prepare(
        "SELECT userId FROM users WHERE userId = ?"
      ).get(referrerId);

      if (!newUser || !referrer) {
        return { success: false, error: "User account not found. Reopen the app." };
      }

      if (newUser.referredBy) {
        return { success: false, error: "Referral already registered." };
      }

      if (Number(newUser.referralEligible) !== 1) {
        return { success: false, error: "This account is not eligible for a new-user referral." };
      }

      const alreadyClaimed = db.prepare(
        "SELECT referredUserId FROM referral_claims WHERE referredUserId = ?"
      ).get(referredUserId);

      if (alreadyClaimed) {
        return { success: false, error: "Referral reward already processed." };
      }

      db.prepare(
        "INSERT INTO referral_claims (referredUserId, referrerId, reward, createdAt) VALUES (?, ?, 350, ?)"
      ).run(referredUserId, referrerId, now);

      db.prepare(
        "UPDATE users SET referredBy = ?, referralEligible = 0, lastUpdated = ? WHERE userId = ?"
      ).run(referrerId, now, referredUserId);

      db.prepare(
        "UPDATE users SET refTotal = refTotal + 1, balance = balance + 350, lastUpdated = ? WHERE userId = ?"
      ).run(now, referrerId);

      return { success: true, reward: 350 };
    })();

    return res.json(result);
  } catch (err) {
    console.error("Referral registration error:", err);
    return res.status(500).json({ success: false, error: "Referral registration failed." });
  }
});

app.post("/api/referral/stats", (req, res) => {
  const auth = verifyTelegramInitData(req.body?.initData);

  if (!auth.ok) {
    return res.status(401).json({ success: false, error: auth.error });
  }

  try {
    const userId = String(auth.user.id);

    const referrals = db.prepare(
      "SELECT userId, username, firstName FROM users WHERE referredBy = ? ORDER BY lastUpdated DESC"
    ).all(userId);

    const legacyTotal = Number(
      db.prepare("SELECT refTotal FROM users WHERE userId = ?").get(userId)?.refTotal || 0
    );

    const total = Math.max(referrals.length, legacyTotal);
    const ledgerEarned = Number(
      db.prepare("SELECT COALESCE(SUM(reward), 0) AS total FROM referral_claims WHERE referrerId = ?").get(userId).total
    );

    return res.json({
      success: true,
      total,
      active: total,
      earned: ledgerEarned + Math.max(0, legacyTotal - referrals.length) * 350,
      users: referrals
    });
  } catch (err) {
    console.error("Referral stats error:", err);
    return res.status(500).json({ success: false, error: "Could not load referral stats." });
  }
});

// Server-authoritative mining state
db.exec(`
  CREATE TABLE IF NOT EXISTS mining_state (
    userId TEXT PRIMARY KEY,
    energy INTEGER NOT NULL DEFAULT 1000,
    maxEnergy INTEGER NOT NULL DEFAULT 1000,
    cooldownEnd INTEGER NOT NULL DEFAULT 0,
    tapIdx INTEGER NOT NULL DEFAULT 0,
    lastTapAt INTEGER NOT NULL DEFAULT 0
  )
`);

const SERVER_TAP_REWARDS = [
  0.22, 0.26, 0.22, 0.26, 0.23, 0.29, 0.11, 0.22, 0.28, 0.16,
  0.14, 0.12, 0.28, 0.44, 0.48, 0.33, 0.48, 0.46, 0.64, 0.54,
  0.49, 0.58, 0.62, 0.34, 0.66, 0.49, 0.76, 0.82, 0.76
];
const MIN_TAP_INTERVAL_MS = 250;
const MINING_CYCLE_MS = 8 * 60 * 60 * 1000;

app.post("/api/mine", (req, res) => {
  const auth = verifyTelegramInitData(req.body?.initData);

  if (!auth.ok) {
    return res.status(401).json({ success: false, error: auth.error });
  }

  const userId = String(auth.user.id);
  const now = Date.now();

  try {
    const mine = db.transaction(() => {
      db.prepare(`
        INSERT OR IGNORE INTO users
        (userId, username, firstName, balance, eth, refTotal, completedTasks, lastUpdated)
        VALUES (?, ?, ?, 200, 0, 0, '[]', ?)
      `).run(
        userId,
        auth.user.username || "",
        auth.user.first_name || "",
        new Date(now).toISOString()
      );

      db.prepare(`
        INSERT OR IGNORE INTO mining_state
        (userId, energy, maxEnergy, cooldownEnd, tapIdx, lastTapAt)
        VALUES (?, 1000, 1000, ?, 0, 0)
      `).run(userId, now + MINING_CYCLE_MS);

      const state = db.prepare(
        "SELECT * FROM mining_state WHERE userId = ?"
      ).get(userId);

      let energy = state.energy;
      let cooldownEnd = state.cooldownEnd;

      if (cooldownEnd <= now) {
        const cyclesPassed = Math.floor((now - cooldownEnd) / MINING_CYCLE_MS) + 1;
        cooldownEnd += cyclesPassed * MINING_CYCLE_MS;
        energy = state.maxEnergy;
      }

      if (energy <= 0) {
        db.prepare(`
          UPDATE mining_state SET energy = ?, cooldownEnd = ? WHERE userId = ?
        `).run(energy, cooldownEnd, userId);

        return { error: "Energy finished. Wait for refill.", status: 429,
          energy, cooldownEnd };
      }

      if (state.lastTapAt && now - state.lastTapAt < MIN_TAP_INTERVAL_MS) {
        return { error: "Mining too fast. Try again.", status: 429 };
      }

      const tapIdx = state.tapIdx % SERVER_TAP_REWARDS.length;
      const reward = SERVER_TAP_REWARDS[tapIdx];

      const user = db.prepare(
        "SELECT balance FROM users WHERE userId = ?"
      ).get(userId);

      const newBalance = Math.round((Number(user.balance || 0) + reward) * 1e8) / 1e8;
      energy -= 1;

      db.prepare(`
        UPDATE users SET balance = ?, lastUpdated = ? WHERE userId = ?
      `).run(newBalance, new Date(now).toISOString(), userId);

      db.prepare(`
        UPDATE mining_state
        SET energy = ?, cooldownEnd = ?, tapIdx = ?, lastTapAt = ?
        WHERE userId = ?
      `).run(
        energy,
        cooldownEnd,
        (tapIdx + 1) % SERVER_TAP_REWARDS.length,
        now,
        userId
      );

      return {
        success: true,
        reward,
        balance: newBalance,
        energy,
        maxEnergy: state.maxEnergy,
        cooldownEnd,
        tapIdx: (tapIdx + 1) % SERVER_TAP_REWARDS.length
      };
    });

    const result = mine();

    if (result.error) {
      return res.status(result.status || 400).json({
        success: false,
        error: result.error,
        energy: result.energy,
        cooldownEnd: result.cooldownEnd
      });
    }

    return res.json(result);
  } catch (err) {
    console.error("Mining API error:", err.message);
    return res.status(500).json({ success: false, error: "Mining failed" });
  }
});

app.get("/api/health", (req, res) => {
  res.json({
    success: true,
    database: "sqlite",
    telegramAuthConfigured: !!process.env.BOT_TOKEN
  });
});

app.use(express.static('public'));

app.listen(PORT, () => {
  console.log(`Space ID SQLite server running on port ${PORT}`);
});
