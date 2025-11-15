// src/db.js
const { Pool } = require("pg");

// Prefer Vercel/Supabase-provided URLs:
const connectionString =
    process.env.POSTGRES_URL_NON_POOLING ||
    process.env.POSTGRES_URL;

if (!connectionString) {
    throw new Error(
        "Missing POSTGRES_URL_NON_POOLING or POSTGRES_URL env var. " +
        "Make sure Supabase/Vercel Postgres envs are available."
    );
}

// Supabase requires SSL; this config avoids "self-signed certificate" issues
const pool = new Pool({
    connectionString,
    ssl: {
        require: true,
        rejectUnauthorized: false
    }
});

// Low-level helper
async function query(text, params) {
    const res = await pool.query(text, params);
    return res;
}

// Drop-in helpers roughly matching the old sqlite version

async function run(sql, params = []) {
    // For INSERT/UPDATE/DELETE – returns pg.Result
    return query(sql, params);
}

async function get(sql, params = []) {
    const res = await query(sql, params);
    return res.rows[0] || null;
}

async function all(sql, params = []) {
    const res = await query(sql, params);
    return res.rows;
}

module.exports = {
    query,
    run,
    get,
    all
};
