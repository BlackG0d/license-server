// src/db.js
const { Pool } = require("pg");

// Try Vercel/Supabase-provided URLs first, fall back to local POSTGRES_URL
const connectionString =
    process.env.POSTGRES_URL_NON_POOLING ||
    process.env.POSTGRES_URL ||
    process.env.DATABASE_URL;

if (!connectionString) {
    console.error("DB ERROR: No POSTGRES_URL_NON_POOLING / POSTGRES_URL / DATABASE_URL set");
    throw new Error(
        "Missing Postgres connection string. " +
        "Set POSTGRES_URL_NON_POOLING or POSTGRES_URL (Vercel/Supabase) " +
        "or DATABASE_URL/POSTGRES_URL in your .env for local dev."
    );
}

// SSL:
// - Default: on, with rejectUnauthorized:false (Supabase pattern)
// - You can turn it OFF for local dev by setting DB_SSL=false in .env
const useSSL = process.env.DB_SSL !== "false";

const pool = new Pool({
    connectionString,
    ssl: useSSL ? { rejectUnauthorized: false } : false
});

async function query(text, params) {
    const res = await pool.query(text, params);
    return res;
}

async function run(sql, params = []) {
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
