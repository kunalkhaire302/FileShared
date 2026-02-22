const express = require("express");
const multer = require("multer");
const bcrypt = require("bcrypt");
const { Pool } = require("pg");
const crypto = require("crypto");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const path = require("path");

const JWT_SECRET = process.env.JWT_SECRET || "656973";
const app = express();
const port = process.env.PORT || 3001;

// Security middleware
app.use(helmet({ contentSecurityPolicy: false, crossOriginEmbedderPolicy: false }));
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Rate limiting
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: { message: "Too many requests, please try again later." }
});
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  message: { message: "Too many login attempts, please try again later." }
});

// PostgreSQL Connection Pool
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : false
});

// Blocked file extensions
const BLOCKED_EXTENSIONS = [".exe", ".bat", ".cmd", ".scr", ".pif", ".com", ".vbs", ".js", ".wsh", ".ps1"];
const MAX_FILE_SIZE = 1 * 1024 * 1024 * 1024; // 1GB

// Sanitize filename
function sanitizeFilename(filename) {
  return filename.replace(/[^a-zA-Z0-9._-]/g, "_");
}

// JWT Authentication Middleware
function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (!token) return res.status(401).json({ message: "Access denied. No token provided." });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(403).json({ message: "Invalid or expired token." });
  }
}

// Optional auth - doesn't fail if no token, just attaches user if present
function optionalAuth(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (token) {
    try {
      req.user = jwt.verify(token, JWT_SECRET);
    } catch (err) { /* ignore */ }
  }
  next();
}

// Auto-create tables on startup
async function initDB() {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        name VARCHAR(100) NOT NULL,
        email VARCHAR(100) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);
    await pool.query(`
      CREATE TABLE IF NOT EXISTS uploads (
        id SERIAL PRIMARY KEY,
        user_id INT REFERENCES users(id) ON DELETE SET NULL,
        file_name VARCHAR(255) NOT NULL,
        file_data BYTEA NOT NULL,
        file_size BIGINT NOT NULL DEFAULT 0,
        unique_code VARCHAR(100) NOT NULL,
        file_password VARCHAR(255),
        download_count INT DEFAULT 0,
        expires_at TIMESTAMP,
        upload_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);
    // Add columns if they don't exist (for existing databases)
    const columns = [
      "ALTER TABLE uploads ADD COLUMN IF NOT EXISTS user_id INT REFERENCES users(id) ON DELETE SET NULL",
      "ALTER TABLE uploads ADD COLUMN IF NOT EXISTS file_size BIGINT NOT NULL DEFAULT 0",
      "ALTER TABLE uploads ADD COLUMN IF NOT EXISTS file_password VARCHAR(255)",
      "ALTER TABLE uploads ADD COLUMN IF NOT EXISTS download_count INT DEFAULT 0",
      "ALTER TABLE uploads ADD COLUMN IF NOT EXISTS expires_at TIMESTAMP"
    ];
    for (const col of columns) {
      try { await pool.query(col); } catch (e) { /* column may already exist */ }
    }
    console.log("Connected to PostgreSQL & tables ready");
  } catch (err) {
    console.error("Database init error:", err);
  }
}
initDB();

// Cleanup expired files every hour
setInterval(async () => {
  try {
    const result = await pool.query("DELETE FROM uploads WHERE expires_at IS NOT NULL AND expires_at < NOW()");
    if (result.rowCount > 0) console.log(`Cleaned up ${result.rowCount} expired files`);
  } catch (err) { console.error("Cleanup error:", err); }
}, 60 * 60 * 1000);

// Serve static files
app.use(express.static("public"));

// ==================== AUTH ROUTES ====================

// Register User
app.post("/register", authLimiter, async (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password) {
    return res.status(400).json({ message: "All fields are required." });
  }
  if (name.length < 3) return res.status(400).json({ message: "Name must be at least 3 characters." });
  if (password.length < 8) return res.status(400).json({ message: "Password must be at least 8 characters." });

  try {
    const result = await pool.query("SELECT * FROM users WHERE email = $1", [email]);
    if (result.rows.length > 0) {
      return res.status(400).json({ message: "Email already exists" });
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    await pool.query("INSERT INTO users (name, email, password) VALUES ($1, $2, $3)", [name, email, hashedPassword]);
    return res.status(201).json({ message: "User registered successfully!" });
  } catch (err) {
    console.error("Registration error:", err);
    return res.status(500).json({ message: "Server error" });
  }
});

// Login User
app.post("/login", authLimiter, async (req, res) => {
  const { lemail, lpassword, remember } = req.body;
  if (!lemail || !lpassword) {
    return res.status(400).json({ message: "Email and password are required." });
  }

  try {
    const result = await pool.query("SELECT * FROM users WHERE email = $1", [lemail]);
    if (result.rows.length === 0) {
      return res.status(400).json({ message: "Invalid email or password" });
    }
    const user = result.rows[0];
    const isMatch = await bcrypt.compare(lpassword, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: "Invalid email or password" });
    }
    const expiresIn = remember ? "7d" : "1h";
    const token = jwt.sign({ id: user.id, name: user.name }, JWT_SECRET, { expiresIn });
    return res.json({ message: "Login successful", token, name: user.name });
  } catch (err) {
    console.error("Login error:", err);
    return res.status(500).json({ message: "Server error" });
  }
});

// ==================== FILE ROUTES ====================

const storage = multer.memoryStorage();
const upload = multer({
  storage: storage,
  limits: { fileSize: MAX_FILE_SIZE }
});

// Upload file
app.post("/upload", apiLimiter, optionalAuth, upload.single("file"), async (req, res) => {
  if (!req.file) {
    return res.status(400).json({ message: "No file uploaded." });
  }

  const ext = path.extname(req.file.originalname).toLowerCase();
  if (BLOCKED_EXTENSIONS.includes(ext)) {
    return res.status(400).json({ message: `File type ${ext} is not allowed.` });
  }

  const fileName = sanitizeFilename(req.file.originalname);
  const fileData = req.file.buffer;
  const fileSize = req.file.size;
  const uniqueCode = crypto.randomBytes(6).toString("hex");
  const filePassword = req.body.filePassword || null;
  const expiryDays = parseInt(req.body.expiryDays) || 7;
  const expiresAt = new Date(Date.now() + expiryDays * 24 * 60 * 60 * 1000);
  const userId = req.user ? req.user.id : null;

  let hashedFilePassword = null;
  if (filePassword) {
    hashedFilePassword = await bcrypt.hash(filePassword, 10);
  }

  try {
    await pool.query(
      `INSERT INTO uploads (user_id, file_name, file_data, file_size, unique_code, file_password, expires_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7)`,
      [userId, fileName, fileData, fileSize, uniqueCode, hashedFilePassword, expiresAt]
    );
    res.json({
      message: "File uploaded successfully.",
      uniqueCode: uniqueCode,
      fileName: fileName,
      fileSize: fileSize,
      expiresAt: expiresAt.toISOString(),
      hasPassword: !!filePassword
    });
    console.log(`File uploaded: ${fileName} (${uniqueCode})`);
  } catch (err) {
    console.error("Upload error:", err);
    return res.status(500).json({ message: "Error saving file" });
  }
});

// Get file info (without downloading)
app.get("/api/file-info/:code", async (req, res) => {
  const uniqueCode = req.params.code;
  try {
    const result = await pool.query(
      "SELECT id, file_name, file_size, unique_code, download_count, expires_at, upload_time, file_password IS NOT NULL as has_password FROM uploads WHERE unique_code = $1",
      [uniqueCode]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ message: "File not found" });
    }
    const file = result.rows[0];
    if (file.expires_at && new Date(file.expires_at) < new Date()) {
      return res.status(410).json({ message: "This file has expired" });
    }
    res.json(file);
  } catch (err) {
    console.error("File info error:", err);
    return res.status(500).json({ message: "Server error" });
  }
});

// Download file
app.post("/download/:code", async (req, res) => {
  const uniqueCode = req.params.code;
  const { password } = req.body || {};

  try {
    const result = await pool.query("SELECT * FROM uploads WHERE unique_code = $1", [uniqueCode]);
    if (result.rows.length === 0) {
      return res.status(404).json({ message: "File not found" });
    }
    const file = result.rows[0];

    // Check expiry
    if (file.expires_at && new Date(file.expires_at) < new Date()) {
      await pool.query("DELETE FROM uploads WHERE id = $1", [file.id]);
      return res.status(410).json({ message: "This file has expired and been deleted" });
    }

    // Check password
    if (file.file_password) {
      if (!password) {
        return res.status(401).json({ message: "This file is password protected", requiresPassword: true });
      }
      const passwordMatch = await bcrypt.compare(password, file.file_password);
      if (!passwordMatch) {
        return res.status(401).json({ message: "Incorrect password" });
      }
    }

    // Increment download count
    await pool.query("UPDATE uploads SET download_count = download_count + 1 WHERE id = $1", [file.id]);

    res.setHeader("Content-Type", "application/octet-stream");
    res.setHeader("Content-Disposition", `attachment; filename="${file.file_name}"`);
    res.send(file.file_data);
  } catch (err) {
    console.error("Download error:", err);
    return res.status(500).json({ message: "Error fetching file" });
  }
});

// Keep GET download for backward compatibility
app.get("/download/:code", async (req, res) => {
  const uniqueCode = req.params.code;
  try {
    const result = await pool.query("SELECT * FROM uploads WHERE unique_code = $1", [uniqueCode]);
    if (result.rows.length === 0) {
      return res.status(404).send("File not found");
    }
    const file = result.rows[0];
    if (file.expires_at && new Date(file.expires_at) < new Date()) {
      return res.status(410).send("This file has expired");
    }
    if (file.file_password) {
      return res.status(401).json({ message: "This file is password protected", requiresPassword: true });
    }
    await pool.query("UPDATE uploads SET download_count = download_count + 1 WHERE id = $1", [file.id]);
    res.setHeader("Content-Type", "application/octet-stream");
    res.setHeader("Content-Disposition", `attachment; filename="${file.file_name}"`);
    res.send(file.file_data);
  } catch (err) {
    console.error("Download error:", err);
    return res.status(500).send("Error fetching file");
  }
});

// ==================== USER DASHBOARD ROUTES ====================

// Get user's files
app.get("/api/my-files", authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT id, file_name, file_size, unique_code, download_count, expires_at, upload_time, file_password IS NOT NULL as has_password FROM uploads WHERE user_id = $1 ORDER BY upload_time DESC",
      [req.user.id]
    );
    res.json(result.rows);
  } catch (err) {
    console.error("My files error:", err);
    return res.status(500).json({ message: "Server error" });
  }
});

// Delete own file
app.delete("/api/files/:id", authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      "DELETE FROM uploads WHERE id = $1 AND user_id = $2 RETURNING id",
      [req.params.id, req.user.id]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ message: "File not found or not authorized" });
    }
    res.json({ message: "File deleted successfully" });
  } catch (err) {
    console.error("Delete error:", err);
    return res.status(500).json({ message: "Server error" });
  }
});

// ==================== ERROR HANDLING ====================

// 404 handler
app.use((req, res) => {
  res.status(404).sendFile(path.join(__dirname, "public", "404.html"));
});

// 500 handler
app.use((err, req, res, next) => {
  console.error("Server error:", err);
  res.status(500).json({ message: "Internal server error" });
});

// Start the server
app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`);
});
