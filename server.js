const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const sqlite3 = require('sqlite3').verbose();

const app = express();
const db = new sqlite3.Database('./reports.db');

// Secure password pulled directly from Render's private Environment Variables
const OWNER_PASS = process.env.OWNER_PASSWORD || 'EmergencySecureFallbackKey987!';

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));

app.use(session({
  secret: 'mc-reports-secret-vault-key',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 24 * 60 * 60 * 1000 }
}));

// Initialize DB Tables & Lock Down Owner Password
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

  // Automatically enforce your private password on startup/restarts
  const hashed = bcrypt.hashSync(OWNER_PASS, 10);
  db.get(`SELECT id FROM users WHERE username = 'owner'`, (err, row) => {
    if (!row) {
      db.run(`INSERT INTO users (username, password, role) VALUES ('owner', ?, 'owner')`, [hashed]);
    } else {
      db.run(`UPDATE users SET password = ? WHERE username = 'owner'`, [hashed]);
    }
  });
});

// Middleware: Owner Only Guard
function requireOwner(req, res, next) {
  if (!req.session.user || req.session.user.role !== 'owner') {
    return res.status(403).json({ error: 'Access denied: Owner only' });
  }
  next();
}

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

// --- AUTHENTICATION ---
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

// --- OWNER ONLY: USER MANAGEMENT ---
app.post('/api/owner/change-password', requireOwner, (req, res) => {
  const { newPassword } = req.body;
  if (!newPassword || newPassword.length < 5) {
    return res.status(400).json({ error: 'Password must be at least 5 characters' });
  }
  const hashed = bcrypt.hashSync(newPassword, 10);
  db.run(`UPDATE users SET password = ? WHERE id = ?`, [hashed, req.session.user.id], (err) => {
    if (err) return res.status(500).json({ error: 'Failed to update password' });
    res.json({ success: true });
  });
});

app.get('/api/owner/staff', requireOwner, (req, res) => {
  db.all(`SELECT id, username, role FROM users ORDER BY id ASC`, (err, rows) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    res.json(rows);
  });
});

app.post('/api/owner/staff', requireOwner, (req, res) => {
  const { username, password, role } = req.body;
  const allowedRoles = ['tester', 'helper', 'moderator', 'owner'];
  
  if (!username || !password || !allowedRoles.includes(role)) {
    return res.status(400).json({ error: 'Invalid staff details' });
  }

  const hashed = bcrypt.hashSync(password, 10);
  db.run(`INSERT INTO users (username, password, role) VALUES (?, ?, ?)`, [username, hashed, role], function(err) {
    if (err) return res.status(400).json({ error: 'Username already taken' });
    res.json({ success: true, id: this.lastID });
  });
});

app.delete('/api/owner/staff/:id', requireOwner, (req, res) => {
  const targetId = req.params.id;
  if (parseInt(targetId) === req.session.user.id) {
    return res.status(400).json({ error: 'Cannot delete your own account' });
  }
  db.run(`DELETE FROM users WHERE id = ?`, [targetId], (err) => {
    if (err) return res.status(500).json({ error: 'Failed to delete user' });
    res.json({ success: true });
  });
});

// --- STAFF TICKET ACTIONS ---
app.get('/api/staff/reports', (req, res) => {
  if (!req.session.user) return res.status(401).json({ error: 'Unauthorized' });

  const role = req.session.user.role;
  let query = '';

  if (role === 'owner') {
    query = `SELECT * FROM reports ORDER BY id DESC`;
  } else if (role === 'moderator') {
    query = `SELECT * FROM reports WHERE category IN ('staff_abuse', 'other') ORDER BY id DESC`;
  } else if (role === 'tester') {
    query = `SELECT * FROM reports WHERE category = 'bug' ORDER BY id DESC`;
  } else if (role === 'helper') {
    query = `SELECT * FROM reports WHERE category = 'other' ORDER BY id DESC`;
  }

  db.all(query, (err, rows) => {
    if (err) return res.status(500).json({ error: 'Database read error' });
    res.json(rows);
  });
});

app.post('/api/staff/status', (req, res) => {
  if (!req.session.user) return res.status(401).json({ error: 'Unauthorized' });
  const { id, status } = req.body;

  db.run(`UPDATE reports SET status = ? WHERE id = ?`, [status, id], function(err) {
    if (err) return res.status(500).json({ error: 'Failed to update' });
    res.json({ success: true });
  });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Reports server listening on port ${PORT}`));
