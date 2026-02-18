// Quick script to create tables on Render PostgreSQL
// Usage: node setup-db.js "YOUR_EXTERNAL_DATABASE_URL"

const { Pool } = require("pg");

const connectionString = process.argv[2];

if (!connectionString) {
    console.error("Usage: node setup-db.js \"YOUR_EXTERNAL_DATABASE_URL\"");
    console.error("Get the External Database URL from Render dashboard → PostgreSQL → Connections");
    process.exit(1);
}

const pool = new Pool({
    connectionString,
    ssl: { rejectUnauthorized: false }
});

async function setup() {
    try {
        console.log("Connecting to database...");

        await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        name VARCHAR(100) NOT NULL,
        email VARCHAR(100) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);
        console.log("✅ users table created");

        await pool.query(`
      CREATE TABLE IF NOT EXISTS uploads (
        id SERIAL PRIMARY KEY,
        file_name VARCHAR(255) NOT NULL,
        file_data BYTEA NOT NULL,
        unique_code VARCHAR(100) NOT NULL,
        upload_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);
        console.log("✅ uploads table created");

        console.log("\n🎉 Database setup complete!");
    } catch (err) {
        console.error("❌ Error:", err.message);
    } finally {
        await pool.end();
    }
}

setup();
