const express = require("express");
const session = require("express-session");
const bcrypt = require("bcrypt");
const multer = require("multer");
const sqlite3 = require("sqlite3").verbose();
const path = require("path");

const {
  S3Client,
  PutObjectCommand,
  ListObjectsV2Command,
  GetObjectCommand,
} = require("@aws-sdk/client-s3");

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.urlencoded({ extended: true }));
app.use(express.static("public"));

app.use(
  session({
    secret: process.env.SESSION_SECRET || "change-this-secret-now",
    resave: false,
    saveUninitialized: false,
  })
);

// --------------------
// SQLite users (simple)
// --------------------
const db = new sqlite3.Database("./database.db");

db.run(`CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY,
  username TEXT UNIQUE,
  password TEXT
)`);

// Create initial admin user (first run)
async function createAdminOnce() {
  const username = process.env.INIT_ADMIN_USER || "admin";
  const password = process.env.INIT_ADMIN_PASS || "ChangeThisPassword123!";

  const hashed = await bcrypt.hash(password, 10);
  db.run(
    "INSERT OR IGNORE INTO users (username, password) VALUES (?, ?)",
    [username, hashed]
  );
}
createAdminOnce();

// --------------------
// Auth middleware
// --------------------
function requireLogin(req, res, next) {
  if (!req.session.userId) return res.redirect("/login.html");
  next();
}

// --------------------
// Cloudflare R2 (S3 API)
// --------------------
const R2_ACCOUNT_ID = process.env.R2_ACCOUNT_ID;
const R2_ACCESS_KEY_ID = process.env.R2_ACCESS_KEY_ID;
const R2_SECRET_ACCESS_KEY = process.env.R2_SECRET_ACCESS_KEY;
const R2_BUCKET = process.env.R2_BUCKET;

if (!R2_ACCOUNT_ID || !R2_ACCESS_KEY_ID || !R2_SECRET_ACCESS_KEY || !R2_BUCKET) {
  console.warn(
    "Missing R2 env vars. Set R2_ACCOUNT_ID, R2_ACCESS_KEY_ID, R2_SECRET_ACCESS_KEY, R2_BUCKET."
  );
}

const s3 = new S3Client({
  region: "auto",
  endpoint: `https://${R2_ACCOUNT_ID}.r2.cloudflarestorage.com`,
  credentials: {
    accessKeyId: R2_ACCESS_KEY_ID,
    secretAccessKey: R2_SECRET_ACCESS_KEY,
  },
});

// Multer: store uploads in memory, then send to R2
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 50 * 1024 * 1024 }, // 50MB
  fileFilter: (req, file, cb) => {
    // Optional: restrict file types (PDF + DOCX). Add more if you like.
    const allowed = [
      "application/pdf",
      "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
      "application/msword",
      "application/vnd.ms-excel",
      "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
      "application/vnd.openxmlformats-officedocument.presentationml.presentation",
      "text/plain",
    ];
    if (allowed.includes(file.mimetype)) return cb(null, true);
    cb(new Error("File type not allowed"));
  },
});

// --------------------
// Routes
// --------------------
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

app.get("/steering", requireLogin, async (req, res) => {
  try {
    const list = await s3.send(
      new ListObjectsV2Command({
        Bucket: R2_BUCKET,
        Prefix: "steering/",
      })
    );

    const files = (list.Contents || [])
      .filter((o) => o.Key && !o.Key.endsWith("/"))
      .sort((a, b) => (b.LastModified?.getTime?.() || 0) - (a.LastModified?.getTime?.() || 0))
      .map((o) => ({
        key: o.Key,
        name: o.Key.replace("steering/", ""),
        size: o.Size || 0,
        lastModified: o.LastModified ? new Date(o.LastModified).toISOString().slice(0, 10) : "",
      }));

    const html = `
      <!doctype html>
      <html>
        <head><meta charset="utf-8"><title>HYCORE Steering</title></head>
        <body>
          <h2>Steering Documents</h2>
          <p><a href="/logout">Logout</a></p>

          <form action="/upload" method="POST" enctype="multipart/form-data">
            <input type="file" name="file" required>
            <button type="submit">Upload</button>
          </form>

          <h3>Uploaded files</h3>
          <ul>
            ${
              files.length
                ? files
                    .map(
                      (f) =>
                        `<li>
                          <a href="/download?key=${encodeURIComponent(f.key)}">${f.name}</a>
                          <small>(${Math.round(f.size / 1024)} KB, ${f.lastModified})</small>
                        </li>`
                    )
                    .join("")
                : "<li>No files yet</li>"
            }
          </ul>

          <p><small>Non-sensitive documents only (protocols, eCRF plans, funding).</small></p>
        </body>
      </html>`;
    res.send(html);
  } catch (e) {
    res.status(500).send("Error listing files from R2. Check R2 env vars.");
  }
});

app.post("/upload", requireLogin, upload.single("file"), async (req, res) => {
  try {
    if (!req.file) return res.redirect("/steering");

    const safeName = req.file.originalname.replace(/[^a-zA-Z0-9._-]/g, "_");
    const key = `steering/${Date.now()}-${safeName}`;

    await s3.send(
      new PutObjectCommand({
        Bucket: R2_BUCKET,
        Key: key,
        Body: req.file.buffer,
        ContentType: req.file.mimetype,
      })
    );

    res.redirect("/steering");
  } catch (e) {
    res.status(500).send("Upload failed. Check R2 settings and file type limits.");
  }
});

app.get("/download", requireLogin, async (req, res) => {
  try {
    const key = req.query.key;
    if (!key || typeof key !== "string" || !key.startsWith("steering/")) {
      return res.status(400).send("Invalid key.");
    }

    const obj = await s3.send(
      new GetObjectCommand({
        Bucket: R2_BUCKET,
        Key: key,
      })
    );

    const filename = key.replace("steering/", "");

    res.setHeader("Content-Disposition", `attachment; filename="${filename}"`);
    if (obj.ContentType) res.setHeader("Content-Type", obj.ContentType);

    // Stream to client
    obj.Body.pipe(res);
  } catch (e) {
    res.status(404).send("File not found.");
  }
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});