const express = require("express");
const multer = require("multer");
const bcrypt = require("bcrypt");
const { Pool } = require("pg");
const crypto = require("crypto");
const cors = require("cors");
const jwt = require("jsonwebtoken");

const JWT_SECRET = process.env.JWT_SECRET || "656973";
const app = express();

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const port = process.env.PORT || 3001;

// PostgreSQL Database Connection Pool
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL
    ? { rejectUnauthorized: false }
    : false
});

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
        file_name VARCHAR(255) NOT NULL,
        file_data BYTEA NOT NULL,
        unique_code VARCHAR(100) NOT NULL,
        upload_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);
    console.log("Connected to PostgreSQL & tables ready");
  } catch (err) {
    console.error("Database init error:", err);
  }
}
initDB();

// Serve static files from the "public" directory
app.use(express.static("public"));

// Register User
app.post("/register", async (req, res) => {
  const { name, email, password } = req.body;
  console.log(name, email, password);

  try {
    const result = await pool.query(
      "SELECT * FROM users WHERE email = $1",
      [email]
    );

    if (result.rows.length > 0) {
      return res.status(400).json({ message: "Email already exists" });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Insert new user
    await pool.query(
      "INSERT INTO users (name, email, password) VALUES ($1, $2, $3)",
      [name, email, hashedPassword]
    );

    return res.status(201).json({ message: "User registered successfully!" });
  } catch (err) {
    console.error("Registration error:", err);
    return res.status(500).json({ message: "Server error" });
  }
});

// Login User
app.post("/login", async (req, res) => {
  const { lemail, lpassword, remember } = req.body;
  console.log(lemail, lpassword, remember);

  try {
    const result = await pool.query(
      "SELECT * FROM users WHERE email = $1",
      [lemail]
    );

    if (result.rows.length === 0) {
      return res.status(400).json({ message: "Invalid email or password" });
    }

    const user = result.rows[0];

    // Check password
    const isMatch = await bcrypt.compare(lpassword, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: "Invalid email or password" });
    }

    // Determine token expiration based on "Remember Me" checkbox
    const expiresIn = remember ? "7d" : "1h";

    // If login is successful
    const token = jwt.sign({ id: user.id }, JWT_SECRET, { expiresIn });
    return res.json({ message: "Login successful", token });
  } catch (err) {
    console.error("Login error:", err);
    return res.status(500).json({ message: "Server error" });
  }
});

const storage = multer.memoryStorage();
const upload = multer({ storage: storage });

// Upload route
app.post("/upload", upload.single("file"), async (req, res) => {
  if (!req.file) {
    return res.status(400).send("No file uploaded.");
  }

  const fileName = req.file.originalname;
  const fileData = req.file.buffer;

  // Generate a unique code
  const uniqueCode = crypto.randomBytes(6).toString("hex");

  try {
    await pool.query(
      "INSERT INTO uploads (file_name, file_data, unique_code) VALUES ($1, $2, $3)",
      [fileName, fileData, uniqueCode]
    );

    res.json({
      message: "File uploaded successfully.",
      uniqueCode: uniqueCode
    });
    console.log(
      `File uploaded successfully. Use this code to download: ${uniqueCode}`
    );
  } catch (err) {
    console.error("Error saving to database: ", err);
    return res.status(500).send("Error saving file info");
  }
});

// Route to download file using unique code
app.get("/download/:code", async (req, res) => {
  const uniqueCode = req.params.code;

  try {
    const result = await pool.query(
      "SELECT * FROM uploads WHERE unique_code = $1",
      [uniqueCode]
    );

    if (result.rows.length === 0) {
      return res.status(404).send("File not found");
    }

    const file = result.rows[0];
    res.setHeader("Content-Type", "application/octet-stream");
    res.setHeader(
      "Content-Disposition",
      `attachment; filename=${file.file_name}`
    );
    res.send(file.file_data);
  } catch (err) {
    console.error("Error fetching file:", err);
    return res.status(500).send("Error fetching file info");
  }
});

// Start the server
app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`);
});
