const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const fs = require("fs/promises");
const path = require("path");
const multer = require("multer");
const { getPool } = require("../config/db");
const { requireAuth } = require("../middleware/auth");
const { isGoogleOAuthEnabled, isGoogleOAuthConfigured } = require("../config/googleEnv");
const { sendVerificationEmail } = require("../services/gmailService");

const router = express.Router();
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 4 * 1024 * 1024 } });
const {
  getRequiredDomainByRole,
  normalizeEmail,
  getEmailDomain,
  matchesRoleDomain
} = require("../utils/emailDomain");

function allowPasswordLogin() {
  const v = String(process.env.ALLOW_PASSWORD_LOGIN || "true").toLowerCase();
  return v === "true" || v === "1" || v === "yes";
}

router.get("/providers", (_req, res) => {
  res.json({
    password: allowPasswordLogin(),
    google: isGoogleOAuthEnabled() && isGoogleOAuthConfigured()
  });
});

function validateStrongPassword(password) {
  const value = String(password || "");
  if (value.length < 10) return "Password must be at least 10 characters.";
  if (!/[a-z]/.test(value)) return "Password must include a lowercase letter.";
  if (!/[A-Z]/.test(value)) return "Password must include an uppercase letter.";
  if (!/\d/.test(value)) return "Password must include a number.";
  if (!/[^A-Za-z0-9]/.test(value)) return "Password must include a special character.";
  return null;
}

router.post("/login", async (req, res) => {
  if (!allowPasswordLogin()) {
    return res.status(403).json({
      message:
        "Password sign-in is disabled. Set ALLOW_PASSWORD_LOGIN=true in .env, or enable Microsoft / Google SSO in .env."
    });
  }
  const { email, password, role } = req.body;
  if (!email || !password || !role) return res.status(400).json({ message: "Missing required fields" });
  if (role === "student") {
    return res.status(403).json({ message: "Student sign-in is Google-only. Use Continue with Google." });
  }
  if (!["counselor", "admin"].includes(role)) {
    return res.status(400).json({ message: "Invalid role for manual sign-in." });
  }
  if (!matchesRoleDomain(email, role)) {
    const required = getRequiredDomainByRole(role);
    return res.status(400).json({ message: `Invalid email domain for ${role}. Use @${required}.` });
  }

  const normalizedEmail = normalizeEmail(email);
  if (!normalizedEmail || !matchesRoleDomain(normalizedEmail, role)) {
    const required = getRequiredDomainByRole(role);
    return res.status(400).json({ message: `Invalid email domain for ${role}. Use @${required}.` });
  }
  
  const db = getPool();
  const [rows] = await db.query(
    "SELECT id, full_name, email, password_hash, role, is_active, email_verified FROM users WHERE email = ?",
    [normalizedEmail]
  );
  const user = rows[0];
  if (!user || !user.is_active) return res.status(401).json({ message: "Invalid credentials" });
  if (user.role !== role) return res.status(403).json({ message: "Role mismatch for this account" });
  if (!user.email_verified) {
    return res.status(403).json({ message: "Please verify your email before logging in." });
  }
  if (!user.password_hash) return res.status(401).json({ message: "Invalid credentials" });

  const ok = await bcrypt.compare(password, user.password_hash);
  if (!ok) return res.status(401).json({ message: "Invalid credentials" });

  await db.query("INSERT INTO audit_logs (actor_id, action, meta) VALUES (?, ?, ?)", [
    user.id,
    "user_login",
    JSON.stringify({ email: user.email, role: user.role })
  ]);

  const token = jwt.sign(
    { id: user.id, role: user.role, name: user.full_name, email: user.email },
    process.env.JWT_SECRET || "change_this_secret",
    { expiresIn: "8h" }
  );

  return res.json({
    token,
    user: { id: user.id, role: user.role, name: user.full_name, email: user.email }
  });
});

router.post("/signup", async (_req, res) => {
  return res.status(403).json({
    message: "Self sign-up is disabled. Counselor/Admin accounts must be created by an administrator from the Users panel."
  });
});

router.get("/verify", async (req, res) => {
  const token = String(req.query.token || "").trim();
  if (!token) return res.status(400).send("Missing verification token.");
  const db = getPool();
  const [rows] = await db.query(
    `SELECT id, email, verification_expires_at
     FROM users
     WHERE verification_token = ?
     LIMIT 1`,
    [token]
  );
  const user = rows[0];
  if (!user) return res.status(400).send("Invalid verification token.");
  const exp = new Date(user.verification_expires_at);
  if (Number.isNaN(exp.getTime()) || exp.getTime() < Date.now()) {
    return res.status(400).send("Verification token has expired.");
  }

  await db.query(
    "UPDATE users SET email_verified = 1, verification_token = NULL, verification_expires_at = NULL WHERE id = ?",
    [user.id]
  );

  return res.redirect("/?verified=1");
});

router.get("/me", requireAuth, async (req, res) => {
  const db = getPool();
  const [rows] = await db.query(
    "SELECT id, full_name, email, role, profile_picture, auth_provider, password_hash FROM users WHERE id = ? LIMIT 1",
    [req.user.id]
  );
  const user = rows[0];
  if (!user) return res.status(404).json({ message: "User not found." });
  res.json({
    id: user.id,
    name: user.full_name,
    email: user.email,
    role: user.role,
    profilePicture: user.profile_picture || "",
    authProvider: user.auth_provider || null,
    hasPassword: Boolean(user.password_hash)
  });
});

router.patch("/me/profile", requireAuth, async (req, res) => {
  const { fullName } = req.body;
  const db = getPool();
  await db.query(
    "UPDATE users SET full_name = COALESCE(?, full_name) WHERE id = ?",
    [fullName || null, req.user.id]
  );
  res.json({ ok: true });
});

router.post("/me/profile-picture", requireAuth, upload.single("profilePicture"), async (req, res) => {
  if (!req.file) return res.status(400).json({ message: "Image file is required." });
  const ext = path.extname(req.file.originalname || "").toLowerCase() || ".png";
  const safeExt = [".png", ".jpg", ".jpeg", ".webp", ".gif"].includes(ext) ? ext : ".png";
  const fileName = `user-${req.user.id}-${Date.now()}${safeExt}`;
  const uploadDir = path.join(process.cwd(), "assets", "uploads");
  await fs.mkdir(uploadDir, { recursive: true });
  await fs.writeFile(path.join(uploadDir, fileName), req.file.buffer);
  const relativePath = `assets/uploads/${fileName}`;

  const db = getPool();
  await db.query("UPDATE users SET profile_picture = ? WHERE id = ?", [relativePath, req.user.id]);
  res.json({ ok: true, profilePicture: relativePath });
});

router.patch("/me/password", requireAuth, async (req, res) => {
  const { currentPassword, newPassword } = req.body;
  if (!currentPassword || !newPassword) return res.status(400).json({ message: "currentPassword and newPassword are required." });
  const passwordValidation = validateStrongPassword(newPassword);
  if (passwordValidation) return res.status(400).json({ message: passwordValidation });

  const db = getPool();
  const [rows] = await db.query(
    "SELECT password_hash, auth_provider FROM users WHERE id = ? LIMIT 1",
    [req.user.id]
  );
  const user = rows[0];
  if (!user) return res.status(404).json({ message: "User not found." });
  if (!user.password_hash) {
    return res.status(400).json({
      message:
        "No password is set for this account. Sign in with Microsoft or Google (if enabled), or ask an administrator to set a password."
    });
  }
  const ok = await bcrypt.compare(currentPassword, user.password_hash);
  if (!ok) return res.status(401).json({ message: "Current password is incorrect." });

  const hash = await bcrypt.hash(newPassword, 10);
  await db.query("UPDATE users SET password_hash = ? WHERE id = ?", [hash, req.user.id]);
  res.json({ ok: true });
});

router.delete("/me", requireAuth, async (req, res) => {
  const db = getPool();
  await db.query("UPDATE users SET is_active = 0 WHERE id = ?", [req.user.id]);
  await db.query("INSERT INTO audit_logs (actor_id, action, meta) VALUES (?, ?, ?)", [
    req.user.id,
    "user_deactivated_own_account",
    JSON.stringify({ userId: req.user.id })
  ]);
  res.json({ ok: true });
});

module.exports = router;
module.exports.normalizeEmail = normalizeEmail;
module.exports.getEmailDomain = getEmailDomain;
module.exports.matchesRoleDomain = matchesRoleDomain;