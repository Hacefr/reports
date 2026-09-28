const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');

const app = express();
const db = new sqlite3.Database('./reports.db');

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));

app.use(session({
  secret: 'minecraft-secret-key-change-this',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 24 * 60 * 60 * 1000 }
}));

// Initialize DB Tables
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT,
    role TEXT
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    category TEXT,
    player_ign TEXT,
    target_ign TEXT,
    description TEXT,
    status TEXT DEFAULT 'OPEN',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  // Create default Owner account if it doesn't exist (User: owner / Pass: admin123)
  const defaultPass = bcrypt.hashSync('admin123', 10);
  db.run(`INSERT OR IGNORE INTO users (username, password, role) VALUES ('owner', ?, 'owner')`, [defaultPass]);
});

// --- PUBLIC: SUBMIT REPORT ---
app.post('/api/reports', (req, res) => {
  const { category, player_ign, target_ign, description } = req.body;
  if (!category || !player_ign || !description) {
    return res.status(400).json({ error: 'Missing required fields' });
  }

  db.run(
    `INSERT INTO reports (category, player_ign, target_ign, description) VALUES (?, ?, ?, ?)`,
    [category, player_ign, target_ign || 'N/A', description],
    function(err) {
      if (err) return res.status(500).json({ error: 'Failed to save report' });
      res.json({ success: true, ticketId: this.lastID });
    }
  );
});

// --- AUTH: STAFF LOGIN ---
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  db.get(`SELECT * FROM users WHERE username = ?`, [username], (err, user) => {
    if (err || !user) return res.status(401).json({ error: 'Invalid credentials' });

    if (bcrypt.compareSync(password, user.password)) {
      req.session.user = { id: user.id, username: user.username, role: user.role };
      res.json({ success: true, user: req.session.user });
    } else {
      res.status(401).json({ error: 'Invalid credentials' });
    }
  });
});

app.post('/api/logout', (req, res) => {
  req.session.destroy();
  res.json({ success: true });
});

app.get('/api/session', (req, res) => {
  if (req.session.user) {
    res.json({ loggedIn: true, user: req.session.user });
  } else {
    res.json({ loggedIn: false });
  }
});

// --- STAFF: GET FILTERED REPORTS ---
app.get('/api/staff/reports', (req, res) => {
  if (!req.session.user) return res.status(401).json({ error: 'Unauthorized' });

  const role = req.session.user.role;
  let query = '';
  let params = [];

  if (role === 'owner') {
    // Owner sees ALL reports (Open & Closed)
    query = `SELECT * FROM reports ORDER BY id DESC`;
  } else if (role === 'moderator') {
    // Moderator sees Staff Abuse and Other reports
    query = `SELECT * FROM reports WHERE category IN ('staff_abuse', 'other') ORDER BY id DESC`;
  } else if (role === 'tester') {
    // Tester sees ONLY bugs
    query = `SELECT * FROM reports WHERE category = 'bug' ORDER BY id DESC`;
  } else if (role === 'helper') {
    // Helper sees Other/Player reports
    query = `SELECT * FROM reports WHERE category = 'other' ORDER BY id DESC`;
  }

  db.all(query, params, (err, rows) => {
    if (err) return res.status(500).json({ error: 'Database read error' });
    res.json(rows);
  });
});

// --- STAFF: CLOSE / REOPEN REPORT ---
app.post('/api/staff/status', (req, res) => {
  if (!req.session.user) return res.status(401).json({ error: 'Unauthorized' });
  const { id, status } = req.body;

  db.run(`UPDATE reports SET status = ? WHERE id = ?`, [status, id], function(err) {
    if (err) return res.status(500).json({ error: 'Failed to update' });
    res.json({ success: true });
  });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
