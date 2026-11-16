const Database = require('better-sqlite3');
const path = require('path');

const db = new Database(path.join(__dirname, 'mezox.db'));
db.pragma('journal_mode = WAL');

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  display_name TEXT NOT NULL,
  age INTEGER DEFAULT 0,
  password_hash TEXT,
  provider TEXT DEFAULT 'local',
  provider_id TEXT,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS friends (
  user_id INTEGER NOT NULL,
  friend_id INTEGER NOT NULL,
  UNIQUE(user_id, friend_id)
);
CREATE TABLE IF NOT EXISTS invites (
  from_id INTEGER NOT NULL,
  to_id INTEGER NOT NULL,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(from_id, to_id)
);
`);

module.exports = db;
