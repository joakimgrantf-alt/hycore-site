const express = require("express");
const session = require("express-session");
const bcrypt = require("bcrypt");
const multer = require("multer");
const sqlite3 = require("sqlite3").verbose();
const path = require("path");
const fs = require("fs");

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.urlencoded({ extended: true }));
app.use(express.static("public"));

app.use(
  session({
    secret: process.env.SESSION_SECRET || "9f2k3l9dksl2394ksl29dkf92384kfsdf",
    resave: false,
    saveUninitialized: false,
  })
);

// --- DB (SQLite)
const db = new sqlite3.Database("./database.db");

db.run(`CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY,
  username TEXT UNIQUE,
  password TEXT
)`);

// Create initial admin user (first run)
async function createAdminOnce() {
  const username = "admin";
  const password = "Andr0meda1!";

  const hashed = await bcrypt.hash(password, 10);
  db.run(
    "INSERT OR IGNORE INTO users (username, password) VALUES (?, ?)",
    [username, hashed]
  );
}
createAdminOnce();

// --- Auth middleware
function requireLogin(req, res, next) {
  if (!req.session.userId) return res.redirect("/login.html");
  next();
}

// --- Upload setup
if (!fs.existsSync("uploads")) fs.mkdirSync("uploads");

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, "uploads/"),
  filename: (req, file, cb) => cb(null, Date.now() + "-" + file.originalname),
});

const upload = multer({
  storage,
  limits: { fileSize: 50 * 1024 * 1024 }, // 50MB
});

// --- Routes
app.post("/login", (req, res) => {
  const { username, password } = req.body;

  db.get(
    "SELECT * FROM users WHERE username = ?",
    [username],
    async (err, user) => {
      if (err || !user) return res.redirect("/login.html");

      const match = await bcrypt.compare(password, user.password);
      if (!match) return res.redirect("/login.html");

      req.session.userId = user.id;
      res.redirect("/steering");
    }
  );
});

app.get("/logout", (req, res) => {
  req.session.destroy(() => res.redirect("/"));
});

app.get("/steering", requireLogin, (req, res) => {
  // Simple file list (server-side)
  const files = fs.readdirSync("uploads").map((f) => ({
    name: f,
    url: "/uploads/" + encodeURIComponent(f),
  }));

  const html = `
  <!doctype html>
  <html>
    <head><meta charset="utf-8"><title>Steering</title></head>
    <body>
      <h2>Steering Documents</h2>
      <p><a href="/logout">Logout</a></p>

      <form action="/upload" method="POST" enctype="multipart/form-data">
        <input type="file" name="file" required>
        <button type="submit">Upload</button>
      </form>

      <h3>Uploaded files</h3>
      <ul>
        ${files.map(f => `<li><a href="${f.url}">${f.name}</a></li>`).join("") || "<li>No files yet</li>"}
      </ul>

      <p><small>Non-sensitive documents only.</small></p>
    </body>
  </html>`;
  res.send(html);
});

// Serve uploads (only for logged-in users)
app.get("/uploads/:file", requireLogin, (req, res) => {
  const filePath = path.join(__dirname, "uploads", req.params.file);
  res.sendFile(filePath);
});

app.post("/upload", requireLogin, upload.single("file"), (req, res) => {
  res.redirect("/steering");
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
  console.log(`Login: http://localhost:${PORT}/login.html (admin / ChangeThisPassword123!)`);
});