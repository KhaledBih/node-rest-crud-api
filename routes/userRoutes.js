const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const pool = require("../config");

const router = express.Router();
const crypto = require("crypto");
const JWT_SECRET = crypto.randomBytes(64).toString("hex");
console.log(JWT_SECRET);

// Register a new user
router.post("/register", async (req, res) => {
  const { name, email, password } = req.body;
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    await pool.query(
      "INSERT INTO users (name, email, password) VALUES (?, ?, ?)",
      [name, email, hashedPassword]
    );
    res.status(201).json({ message: "User registered successfully" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Login a user
router.post("/login", async (req, res) => {
  const { email, password } = req.body;
  try {
    const [rows] = await pool.query("SELECT * FROM users WHERE email = ?", [
      email,
    ]);
    if (rows.length > 0) {
      const user = rows[0];
      const isMatch = await bcrypt.compare(password, user.password);
      if (isMatch) {
        const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, {
          expiresIn: "1h",
        });
        res.json({ token });
      } else {
        res.status(400).json({ error: "Invalid credentials" });
      }
    } else {
      res.status(400).json({ error: "Invalid credentials" });
    }
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Middleware to protect routes
const authenticateJWT = (req, res, next) => {
  const token = req.header("Authorization")?.split(" ")[1];
  if (token) {
    jwt.verify(token, JWT_SECRET, (err, user) => {
      if (err) {
        return res.sendStatus(403);
      }
      req.user = user;
      next();
    });
  } else {
    res.sendStatus(401);
  }
};

// Get user profile
router.get("/profile", authenticateJWT, async (req, res) => {
  try {
    const [rows] = await pool.query(
      "SELECT id, name, email FROM users WHERE id = ?",
      [req.user.id]
    );
    if (rows.length > 0) {
      res.json(rows[0]);
    } else {
      res.status(404).json({ error: "User not found" });
    }
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Create a user
router.post("/", async (req, res) => {
  const { name, email, password } = req.body;
  try {
    const [result] = await pool.query(
      "INSERT INTO users (name, email, password) VALUES (?, ?, ?)",
      [name, email, password]
    );
    res.status(201).json({ id: result.insertId, name, email });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

// Read all users
router.get("/", async (req, res) => {
  try {
    const [rows] = await pool.query("SELECT id, name, email FROM users");
    res.json(rows);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

// Read a user by id
router.get("/:id", async (req, res) => {
  const userId = req.params.id;
  try {
    const [rows] = await pool.query(
      "SELECT id, name, email FROM users WHERE id = ?",
      [userId]
    );
    if (rows.length > 0) {
      res.json(rows[0]);
    } else {
      res.status(404).json({ error: "User not found" });
    }
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

// Update a user
router.put("/:id", async (req, res) => {
  const userId = req.params.id;
  const { name, email, password } = req.body;
  try {
    await pool.query(
      "UPDATE users SET name = ?, email = ?, password = ? WHERE id = ?",
      [name, email, password, userId]
    );
    res.json({ message: "User updated successfully" });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

// Delete a user
router.delete("/:id", async (req, res) => {
  const userId = req.params.id;
  try {
    await pool.query("DELETE FROM users WHERE id = ?", [userId]);
    res.json({ message: "User deleted successfully" });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

module.exports = router;
