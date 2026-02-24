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
  DeleteObjectCommand,
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
  password TEXT,
  role TEXT DEFAULT 'member'
)`);
db.run(`ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'member'`, () => {});
// Create initial admin user (first run)
async function createAdminOnce() {
  const username = process.env.INIT_ADMIN_USER || "admin";
  const password = process.env.INIT_ADMIN_PASS || "ChangeThisPassword123!";

  const hashed = await bcrypt.hash(password, 10);
  db.run(
  "INSERT OR IGNORE INTO users (username, password, role) VALUES (?, ?, ?)",
  [username, hashed, "admin"]
);

// Ensure admin role is correct
db.run("UPDATE users SET role='admin' WHERE username = ?", [username]);
}
createAdminOnce();

// --------------------
// Auth middleware
// --------------------
function requireLogin(req, res, next) {
  if (!req.session.userId) return res.redirect("/login.html");
  next();
}
function requireAdmin(req, res, next) {
  db.get(
    "SELECT role FROM users WHERE id = ?",
    [req.session.userId],
    (err, row) => {
      if (err || !row || row.role !== "admin") {
        return res.status(403).send("Admins only");
      }
      next();
    }
  );
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
const FOLDERS = ["General", "Copenhagen", "Utrecht", "Leuven", "Misc"];
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
app.post("/admin/create-user", requireLogin, requireAdmin, async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).send("Missing fields");

  const hashed = await bcrypt.hash(password, 10);
  db.run(
  "INSERT INTO users (username, password, role) VALUES (?, ?, 'member')",
  [username, hashed],
    (err) => {
      if (err) return res.status(400).send("User already exists or error");
      res.redirect("/steering");
    }
  );
});
app.get("/logout", (req, res) => {
  req.session.destroy(() => res.redirect("/"));
});


app.get("/steering", requireLogin, async (req, res) => {
  try {
    const selectedFolderRaw = (req.query.folder || "General").toString().trim();
    const selectedFolder = FOLDERS.includes(selectedFolderRaw) ? selectedFolderRaw : "General";
    const prefix = `steering/${selectedFolder}/`;
    const list = await s3.send(
      new ListObjectsV2Command({
        Bucket: R2_BUCKET,
        Prefix: prefix,
    
      })
    );

    const files = (list.Contents || [])
      .filter((o) => o.Key && !o.Key.endsWith("/"))
      .sort((a, b) => (b.LastModified?.getTime?.() || 0) - (a.LastModified?.getTime?.() || 0))
      .map((o) => ({
        key: o.Key,
        name: o.Key.split("/").pop(),
        size: o.Size || 0,
        lastModified: o.LastModified ? new Date(o.LastModified).toISOString().slice(0, 10) : "",
      }));
// --- Determine if current user is admin ---
const me = await new Promise((resolve) => {
  db.get(
    "SELECT role FROM users WHERE id = ?",
    [req.session.userId],
    (err, row) => resolve(row || { role: "member" })
  );
});
const isAdmin = me.role === "admin";
const fileListHtml = files.length
  ? files
      .map((f) => {
        const deleteHtml = isAdmin
          ? `
            <form method="POST" action="/admin/delete" style="display:inline; margin-left:10px;"
                  onsubmit="return confirm('Delete ${f.name}? This cannot be undone.');">
              <input type="hidden" name="key" value="${f.key}">
              <input type="text" name="confirm" placeholder="Type DELETE" required style="width:110px;">
              <button type="submit">Delete</button>
            </form>
          `
          : "";

        return `
          <li>
            <a href="/download?key=${encodeURIComponent(f.key)}">${f.name}</a>
            <small>(${Math.round(f.size / 1024)} KB, ${f.lastModified})</small>
            ${deleteHtml}
          </li>
        `;
      })
      .join("")
  : "<li>No files yet</li>";
    const users = await new Promise((resolve) => {
  if (!isAdmin) return resolve([]);
  db.all("SELECT id, username, role FROM users ORDER BY role DESC, username ASC", [], (err, rows) => {
    resolve(err ? [] : rows);
  });
});

const userListHtml = isAdmin
  ? (users.length
      ? users.map(u => {
          const isMe = u.id === req.session.userId;
          const roleLabel = u.role;

          const promoteDemote = u.role === "admin"
            ? (isMe ? `<em style="margin-left:10px;">(you)</em>` : `
                <form method="POST" action="/admin/demote" style="display:inline; margin-left:10px;"
                      onsubmit="return confirm('Demote ${u.username} from admin to member?');">
                  <input type="hidden" name="userId" value="${u.id}">
                  <button type="submit">Demote</button>
                </form>
              `)
            : `
                <form method="POST" action="/admin/promote" style="display:inline; margin-left:10px;"
                      onsubmit="return confirm('Promote ${u.username} to admin?');">
                  <input type="hidden" name="userId" value="${u.id}">
                  <button type="submit">Promote</button>
                </form>
              `;

          const resetPw = `
            <form method="POST" action="/admin/reset-password" style="display:inline; margin-left:10px;"
                  onsubmit="return confirm('Reset password for ${u.username}?');">
              <input type="hidden" name="userId" value="${u.id}">
              <input type="password" name="newPassword" placeholder="New password" required style="width:160px;">
              <button type="submit">Reset</button>
            </form>
          `;

          const deleteUser = isMe ? "" : `
            <form method="POST" action="/admin/delete-user" style="display:inline; margin-left:10px;"
                  onsubmit="return confirm('Delete user ${u.username}?');">
              <input type="hidden" name="userId" value="${u.id}">
              <button type="submit">Delete</button>
            </form>
          `;

          return `
            <li>
              <strong>${u.username}</strong> <small>(${roleLabel}, id=${u.id})</small>
              ${isMe ? `<em style="margin-left:10px;">(you)</em>` : ""}
              ${promoteDemote}
              ${resetPw}
              ${deleteUser}
            </li>
          `;
        }).join("")
      : "<li>No users found</li>")
  : "";
const folderNavHtml = `
  <h3>Folders</h3>
  <ul>
    ${FOLDERS.map(f => `
      <li>
        <a href="/steering?folder=${encodeURIComponent(f)}">${f}</a>
        ${f === selectedFolder ? "<strong> (current)</strong>" : ""}
      </li>
    `).join("")}
  </ul>
`;
    const html = `
      <!doctype html>
      <html>
        <head><meta charset="utf-8"><title>HYCORE Steering</title></head>
        <body>
          <h2>Steering Documents</h2>
          <p><a href="/logout">Logout</a></p>
          ${folderNavHtml}

          <form action="/upload" method="POST" enctype="multipart/form-data">
  <label>Upload to:</label>
  <select name="folder" required>
    ${FOLDERS.map(f => `<option value="${f}" ${f === selectedFolder ? "selected" : ""}>${f}</option>`).join("")}
  </select>
  <input type="file" name="file" required>
  <button type="submit">Upload</button>
</form>
${isAdmin ? `
<h3>Create user (admin)</h3>
<form method="POST" action="/admin/create-user">
  <input name="username" placeholder="username" required>
  <input name="password" type="password" placeholder="password" required>
  <button type="submit">Create</button>
</form>
` : ""}
${isAdmin ? `
<h3>Current users (admin)</h3>
<ul>
  ${userListHtml}
</ul>
` : ""}
          <h3>Uploaded files</h3>
<ul>
  ${fileListHtml}
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
    const folderRaw = (req.body.folder || "General").toString().trim();
    const folder = FOLDERS.includes(folderRaw) ? folderRaw : "General";
    const key = `steering/${folder}/${Date.now()}/${safeName}`;

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
app.post("/admin/delete", requireLogin, requireAdmin, async (req, res) => {
  try {
    const key = req.body.key;
    const confirm = req.body.confirm;

    // Guardrails
    if (!key || typeof key !== "string" || !key.startsWith("steering/")) {
      return res.status(400).send("Invalid key.");
    }

    // Optional confirmation to reduce accidents
    if (confirm !== "DELETE") {
      return res.status(400).send('Type "DELETE" to confirm deletion.');
    }

    await s3.send(
      new DeleteObjectCommand({
        Bucket: R2_BUCKET,
        Key: key,
      })
    );

    return res.redirect("/steering");
  } catch (e) {
    return res.status(500).send("Delete failed.");
  }
});
app.post("/admin/delete-user", requireLogin, requireAdmin, (req, res) => {
  const userId = Number(req.body.userId);
  if (!Number.isInteger(userId)) return res.status(400).send("Invalid userId");

  // Don't allow admin to delete themselves (saves you from chaos)
  if (userId === req.session.userId) {
    return res.status(400).send("You cannot delete your own account.");
  }

  // Optional: prevent deleting the last admin
  db.get("SELECT role FROM users WHERE id = ?", [userId], (err, target) => {
    if (err || !target) return res.status(404).send("User not found");

    if (target.role === "admin") {
      db.get("SELECT COUNT(*) AS n FROM users WHERE role='admin'", [], (err2, row) => {
        if (err2) return res.status(500).send("DB error");
        if ((row?.n || 0) <= 1) return res.status(400).send("Cannot delete the last admin.");

        db.run("DELETE FROM users WHERE id = ?", [userId], (err3) => {
          if (err3) return res.status(500).send("Delete failed");
          res.redirect("/steering");
        });
      });
    } else {
      db.run("DELETE FROM users WHERE id = ?", [userId], (err3) => {
        if (err3) return res.status(500).send("Delete failed");
        res.redirect("/steering");
      });
    }
  });
});
app.post("/admin/reset-password", requireLogin, requireAdmin, async (req, res) => {
  try {
    const userId = Number(req.body.userId);
    const newPassword = (req.body.newPassword || "").trim();

    if (!Number.isInteger(userId)) return res.status(400).send("Invalid userId");
    if (newPassword.length < 10) return res.status(400).send("Password must be at least 10 characters.");

    const hashed = await bcrypt.hash(newPassword, 10);

    db.run("UPDATE users SET password = ? WHERE id = ?", [hashed, userId], (err) => {
      if (err) return res.status(500).send("Password reset failed.");
      res.redirect("/steering");
    });
  } catch (e) {
    res.status(500).send("Password reset failed.");
  }
});
app.post("/admin/promote", requireLogin, requireAdmin, (req, res) => {
  const userId = Number(req.body.userId);
  if (!Number.isInteger(userId)) return res.status(400).send("Invalid userId");

  db.run("UPDATE users SET role='admin' WHERE id = ?", [userId], (err) => {
    if (err) return res.status(500).send("Promote failed.");
    res.redirect("/steering");
  });
});
app.post("/admin/demote", requireLogin, requireAdmin, (req, res) => {
  const userId = Number(req.body.userId);
  if (!Number.isInteger(userId)) return res.status(400).send("Invalid userId");

  // Don't let admin demote themselves (optional but sensible)
  if (userId === req.session.userId) {
    return res.status(400).send("You cannot demote your own account.");
  }

  // Ensure we're not demoting the last admin
  db.get("SELECT role FROM users WHERE id = ?", [userId], (err, target) => {
    if (err || !target) return res.status(404).send("User not found");
    if (target.role !== "admin") return res.redirect("/steering"); // already not admin

    db.get("SELECT COUNT(*) AS n FROM users WHERE role='admin'", [], (err2, row) => {
      if (err2) return res.status(500).send("DB error");
      if ((row?.n || 0) <= 1) return res.status(400).send("Cannot demote the last admin.");

      db.run("UPDATE users SET role='member' WHERE id = ?", [userId], (err3) => {
        if (err3) return res.status(500).send("Demote failed.");
        res.redirect("/steering");
      });
    });
  });
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});