const sqlite3 = require("sqlite3").verbose();

const db = new sqlite3.Database("./mypasswordx.db");

// Create tables and a sample license key on first run
db.serialize(() => {
    db.run(`
    CREATE TABLE IF NOT EXISTS licenses (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      license_key TEXT UNIQUE NOT NULL,
      status TEXT NOT NULL,
      used_by_email TEXT,
      used_on_device_id TEXT,
      used_at DATETIME,
      created_at DATETIME NOT NULL,
      updated_at DATETIME NOT NULL
    )
  `);

    db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      device_id TEXT,
      license_id INTEGER,
      created_at DATETIME NOT NULL,
      updated_at DATETIME NOT NULL
    )
  `);

    db.run(`
    CREATE TABLE IF NOT EXISTS email_verifications (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT NOT NULL,
      device_id TEXT NOT NULL,
      license_id INTEGER NOT NULL,
      code_hash TEXT NOT NULL,
      expires_at DATETIME NOT NULL,
      used INTEGER NOT NULL DEFAULT 0,
      created_at DATETIME NOT NULL
    )
  `);

    // Dev-only sample license – remove or replace in production
    db.run(
        `
    INSERT OR IGNORE INTO licenses
      (license_key, status, created_at, updated_at)
    VALUES
      (?, 'unused', datetime('now'), datetime('now'))
  `,
        ["TEST-LICENSE-KEY-123"]
    );
});

// Promise helpers
function run(sql, params = []) {
    return new Promise((resolve, reject) => {
        db.run(sql, params, function (err) {
            if (err) return reject(err);
            resolve(this);
        });
    });
}

function get(sql, params = []) {
    return new Promise((resolve, reject) => {
        db.get(sql, params, (err, row) => {
            if (err) return reject(err);
            resolve(row);
        });
    });
}

function all(sql, params = []) {
    return new Promise((resolve, reject) => {
        db.all(sql, params, (err, rows) => {
            if (err) return reject(err);
            resolve(rows);
        });
    });
}

module.exports = {
    db,
    run,
    get,
    all
};
