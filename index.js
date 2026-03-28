const express = require("express");
const mysql = require("mysql2/promise");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { ROLE_NAMES, PERMISSIONS, can, buildPermissions } = require("./role-policy");
let nodemailer = null;
try {
  nodemailer = require("nodemailer");
} catch {
  nodemailer = null;
}

// ─── App & Config ────────────────────────────────────────────────────────────

const app = express();
const port = Number.parseInt(process.env.PORT, 10) || 4000;
const dbName = process.env.DB_NAME || "to_do_list";
const dbHost = process.env.DB_HOST || "127.0.0.1";
const dbPort = Number.parseInt(process.env.DB_PORT || "3306", 10);
const dbUser = process.env.DB_USER || "root";
const dbPassword = process.env.DB_PASSWORD || "";
const APP_BASE_URL = process.env.APP_BASE_URL || `http://localhost:${port}`;

const SESSION_COOKIE_NAME = "taskflow_sid";
const SESSION_TTL_MS = 1000 * 60 * 60 * 8;
const RESET_TOKEN_TTL_MS = 1000 * 60 * 30;
const TEAM_INVITE_TOKEN_TTL_MS = 1000 * 60 * 60 * 24 * 365;
const RATE_LIMIT_WINDOW_MS = 1000 * 60 * 15;
const DEFAULT_USER_PASSWORD = "123";
const USER_DIRECTORY_ROLE_NAMES = Object.freeze([
  ROLE_NAMES.ADMIN,
  ROLE_NAMES.TEAM_LEADER,
  ROLE_NAMES.PERSONAL_ACCOUNT,
  ROLE_NAMES.MEMBER
]);
const SMTP_HOST = (process.env.SMTP_HOST || "").trim();
const SMTP_PORT = Number.parseInt(process.env.SMTP_PORT || "587", 10);
const SMTP_USER = (process.env.SMTP_USER || "").trim();
const SMTP_PASS = process.env.SMTP_PASS || "";
const SMTP_FROM = (process.env.SMTP_FROM || SMTP_USER || "").trim();
const SMTP_SECURE = String(process.env.SMTP_SECURE || "").toLowerCase() === "true";
const SERVER_OUT_LOG_PATH = path.join(__dirname, "server.out.log");
const SERVER_ERR_LOG_PATH = path.join(__dirname, "server.err.log");
const AUTH_LOG_PATH = path.join(__dirname, "auth.log");

function appendLogLine(filePath, message) {
  const line = `[${new Date().toISOString()}] ${message}\n`;
  fs.appendFile(filePath, line, (error) => {
    if (error) {
      // Keep this silent to avoid recursive logging noise.
    }
  });
}

function logAuthEvent(eventName, user, req) {
  const username = user?.username || "unknown";
  const roleName = user?.role_name || user?.roleName || "NoRole";
  const accountType = user?.account_type || user?.accountType || "unknown";
  const ip = req.ip || req.headers["x-forwarded-for"] || "unknown-ip";
  appendLogLine(AUTH_LOG_PATH, `${eventName} username=${username} role=${roleName} account=${accountType} ip=${ip}`);
}

// ─── Security Headers ────────────────────────────────────────────────────────

app.disable("x-powered-by");
app.set("trust proxy", 1);
app.use((_req, res, next) => {
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
  res.setHeader("Permissions-Policy", "geolocation=(), microphone=(), camera=()");
  res.setHeader(
    "Content-Security-Policy",
    "default-src 'self'; img-src 'self' https: data:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'"
  );
  next();
});
app.use((req, res, next) => {
  const start = Date.now();
  res.on("finish", () => {
    const isStaticAsset =
      req.path.startsWith("/images/") ||
      req.path.endsWith(".css") ||
      req.path.endsWith(".js") ||
      req.path.endsWith(".ico");
    if (isStaticAsset) return;
    const tookMs = Date.now() - start;
    const userPart = req.currentUser?.username ? ` user=${req.currentUser.username}` : " user=guest";
    appendLogLine(SERVER_OUT_LOG_PATH, `${req.method} ${req.originalUrl} -> ${res.statusCode} (${tookMs}ms)${userPart}`);
  });
  next();
});

app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "views", "public")));
app.set("view engine", "ejs");
app.use((req, res, next) => {
  res.locals.currentPath = req.path || "";
  next();
});

app.get("/health", (_req, res) => {
  res.status(200).type("text/plain").send("ok");
});

// ─── Rate Limiting ───────────────────────────────────────────────────────────

function createRateLimiter({ windowMs, maxRequests }) {
  const hits = new Map();
  return (req, res, next) => {
    const key = `${req.ip ?? "unknown"}:${req.path}`;
    const now = Date.now();
    const current = hits.get(key);
    if (!current || current.resetAt < now) {
      hits.set(key, { count: 1, resetAt: now + windowMs });
      return next();
    }
    if (current.count >= maxRequests) {
      res.setHeader("Retry-After", Math.ceil((current.resetAt - now) / 1000));
      return res.status(429).send("Too many requests. Please try again shortly.");
    }
    current.count += 1;
    next();
  };
}

const globalRateLimiter = createRateLimiter({ windowMs: RATE_LIMIT_WINDOW_MS, maxRequests: 300 });
const authRateLimiter = createRateLimiter({ windowMs: RATE_LIMIT_WINDOW_MS, maxRequests: 35 });
app.use(globalRateLimiter);

// ─── Password & Token Helpers ────────────────────────────────────────────────

function createPasswordHash(password) {
  const salt = crypto.randomBytes(16).toString("hex");
  const hash = crypto.scryptSync(password, salt, 64).toString("hex");
  return `${salt}:${hash}`;
}

function verifyPassword(password, storedHash) {
  if (!password || !storedHash || !storedHash.includes(":")) return false;
  const [salt, expectedHash] = storedHash.split(":");
  const hash = crypto.scryptSync(password, salt, 64).toString("hex");
  const expected = Buffer.from(expectedHash, "hex");
  const actual = Buffer.from(hash, "hex");
  return expected.length === actual.length && crypto.timingSafeEqual(expected, actual);
}

function hashResetToken(token) {
  return crypto.createHash("sha256").update(token).digest("hex");
}

function createResetTokenPair() {
  const rawToken = crypto.randomBytes(32).toString("hex");
  return { rawToken, tokenHash: hashResetToken(rawToken) };
}

function createTeamInviteTokenPair() {
  const rawToken = crypto.randomBytes(32).toString("hex");
  return { rawToken, tokenHash: hashResetToken(rawToken) };
}

function buildMemberPlaceholderEmail(username) {
  const base =
    (username ?? "member")
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, ".")
      .replace(/^\.+|\.+$/g, "") || "member";
  return `${base}.${Date.now()}.${crypto.randomBytes(3).toString("hex")}@no-login.local`;
}

// ─── Session Store ───────────────────────────────────────────────────────────

const sessions = new Map();

function parseCookies(cookieHeader) {
  if (!cookieHeader) return {};
  return cookieHeader.split(";").reduce((acc, part) => {
    const [rawName, ...rest] = part.split("=");
    const name = rawName?.trim();
    if (!name) return acc;
    try {
      acc[name] = decodeURIComponent(rest.join("=").trim());
    } catch {
      acc[name] = rest.join("=").trim();
    }
    return acc;
  }, {});
}

function setSessionCookie(res, sessionId) {
  const isSecure = process.env.NODE_ENV === "production";
  const parts = [
    `${SESSION_COOKIE_NAME}=${encodeURIComponent(sessionId)}`,
    "Path=/",
    "HttpOnly",
    "SameSite=Lax",
    `Max-Age=${Math.floor(SESSION_TTL_MS / 1000)}`,
  ];
  if (isSecure) parts.push("Secure");
  res.setHeader("Set-Cookie", parts.join("; "));
}

function clearSessionCookie(res) {
  const secure = process.env.NODE_ENV === "production" ? "; Secure" : "";
  res.setHeader("Set-Cookie", `${SESSION_COOKIE_NAME}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0${secure}`);
}

function createSession(user) {
  const sessionId = crypto.randomBytes(24).toString("hex");
  sessions.set(sessionId, {
    userId: user.id,
    username: user.username,
    email: user.email,
    accountType: user.account_type === "team" ? "team" : "personal",
    roleId: user.role_id,
    roleName: user.role_name ?? null,
    csrfToken: crypto.randomBytes(24).toString("hex"),
    expiresAt: Date.now() + SESSION_TTL_MS,
  });
  return sessionId;
}

function invalidateSessionsForUser(userId) {
  for (const [id, session] of sessions) {
    if (session.userId === userId) sessions.delete(id);
  }
}

function destroySession(req, res) {
  const cookies = parseCookies(req.headers.cookie ?? "");
  const sessionId = cookies[SESSION_COOKIE_NAME];
  if (sessionId) sessions.delete(sessionId);
  clearSessionCookie(res);
}

// ─── Middleware ───────────────────────────────────────────────────────────────

function sessionMiddleware(req, res, next) {
  const cookies = parseCookies(req.headers.cookie ?? "");
  const sessionId = cookies[SESSION_COOKIE_NAME];
  if (!sessionId) {
    res.locals.currentUser = null;
    return next();
  }
  const session = sessions.get(sessionId);
  if (!session || session.expiresAt < Date.now()) {
    sessions.delete(sessionId);
    clearSessionCookie(res);
    res.locals.currentUser = null;
    return next();
  }
  session.csrfToken ??= crypto.randomBytes(24).toString("hex");
  session.expiresAt = Date.now() + SESSION_TTL_MS;
  req.currentUser = session;
  res.locals.currentUser = session;
  next();
}

function requireAuth(req, res, next) {
  if (req.currentUser) return next();
  const returnTo = safeReturnTo(req.originalUrl ?? "/home");
  res.redirect(`/login?returnTo=${encodeURIComponent(returnTo)}`);
}

function denyWithRedirect(req, res, defaultPath, message) {
  const returnTo = safeReturnTo(req.originalUrl ?? defaultPath);
  return res.redirect(`${defaultPath}?error=${encodeURIComponent(message)}&returnTo=${encodeURIComponent(returnTo)}`);
}

function requirePermission(permission, deniedPath = "/home") {
  return (req, res, next) => {
    if (can(req.currentUser?.roleName, permission)) return next();
    return denyWithRedirect(req, res, deniedPath, "You do not have permission to access that page.");
  };
}

function attachAuthorizationLocals(req, res, next) {
  const roleName = req.currentUser?.roleName ?? null;
  res.locals.roleName = roleName;
  res.locals.permissions = buildPermissions(roleName);
  res.locals.csrfToken = req.currentUser?.csrfToken ?? "";
  next();
}

function attachTeamAccessLocals(req, res, next) {
  if (!req.currentUser) {
    res.locals.canViewTeams = false;
    return next();
  }
  if (can(req.currentUser.roleName, PERMISSIONS.MANAGE_TEAMS)) {
    res.locals.canViewTeams = true;
    return next();
  }
  if (req.currentUser.accountType !== "team") {
    res.locals.canViewTeams = false;
    return next();
  }
  dbQueryWithRetry("SELECT 1 FROM team_members WHERE user_id = ? LIMIT 1", [req.currentUser.userId], { retries: 1 })
    .then(([rows]) => {
      res.locals.canViewTeams = rows.length > 0;
      next();
    })
    .catch((error) => {
      if (isTransientDbError(error)) {
        console.warn("Transient DB error in attachTeamAccessLocals; continuing with canViewTeams=false:", error?.code || error?.message || error);
        res.locals.canViewTeams = false;
        return next();
      }
      next(error);
    });
}

function requireCsrf(req, res, next) {
  if (req.method !== "POST" || !req.currentUser) return next();
  const provided =
    (typeof req.body?.csrf_token === "string" ? req.body.csrf_token : "") ||
    (typeof req.headers["x-csrf-token"] === "string" ? req.headers["x-csrf-token"] : "");
  if (!provided || provided !== req.currentUser.csrfToken) {
    return denyWithRedirect(req, res, "/home", "Invalid CSRF token. Refresh and try again.");
  }
  next();
}

// ─── Utility Helpers ─────────────────────────────────────────────────────────

function safeReturnTo(value) {
  if (!value || typeof value !== "string") return "/";
  if (!value.startsWith("/") || value.startsWith("//")) return "/";
  return value;
}

function parseOptionalInt(value) {
  if (value === undefined || value === null || value === "") return null;
  const parsed = Number.parseInt(value, 10);
  return Number.isNaN(parsed) ? null : parsed;
}

function appendQueryValue(urlPath, key, value) {
  const separator = urlPath.includes("?") ? "&" : "?";
  return `${urlPath}${separator}${key}=${encodeURIComponent(value)}`;
}

function normalizeTeamsErrorMessage(error) {
  if (!error) return "";
  if (error === "Please select team, user, and role") return "Please select team and role";
  if (error === "Select an existing user or enter a new member name") return "Please enter member name";
  return error;
}

function readLogTail(filePath, options = {}) {
  const maxLines = Number.isInteger(options.maxLines) ? Math.max(1, options.maxLines) : 200;
  const maxChars = Number.isInteger(options.maxChars) ? Math.max(500, options.maxChars) : 120000;
  if (!fs.existsSync(filePath)) {
    return { exists: false, text: "Log file not found." };
  }
  const content = fs.readFileSync(filePath, "utf8");
  const clipped = content.length > maxChars ? content.slice(content.length - maxChars) : content;
  const lines = clipped.split(/\r?\n/);
  const tail = lines.slice(-maxLines).join("\n");
  return { exists: true, text: tail.trim() || "(No log entries yet)" };
}

function isUserDirectoryRoleName(roleName) {
  return USER_DIRECTORY_ROLE_NAMES.includes(roleName);
}

// ─── Database ────────────────────────────────────────────────────────────────

let db;

function isTransientDbError(error) {
  const code = String(error?.code || "").toUpperCase();
  const message = String(error?.message || "").toUpperCase();
  return (
    code === "ECONNRESET" ||
    code === "PROTOCOL_CONNECTION_LOST" ||
    code === "ETIMEDOUT" ||
    code === "EPIPE" ||
    code === "EAI_AGAIN" ||
    message.includes("ECONNRESET") ||
    message.includes("PROTOCOL_CONNECTION_LOST")
  );
}

function delay(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function dbQueryWithRetry(sql, params = [], options = {}) {
  const retries = Number.isInteger(options.retries) ? Math.max(0, options.retries) : 1;
  let attempt = 0;
  while (true) {
    try {
      return await db.query(sql, params);
    } catch (error) {
      const canRetry = isTransientDbError(error) && attempt < retries;
      if (!canRetry) throw error;
      attempt += 1;
      await delay(100 * attempt);
    }
  }
}

async function initDatabase() {
  const base = await mysql.createConnection({
    host: dbHost,
    port: dbPort,
    user: dbUser,
    password: dbPassword,
  });

  await base.query(`CREATE DATABASE IF NOT EXISTS \`${dbName}\``);
  await base.end();

  db = await mysql.createPool({
    host: dbHost,
    port: dbPort,
    user: dbUser,
    password: dbPassword,
    database: dbName,
    waitForConnections: true,
    connectionLimit: 10,
  });

  await createTables();
  await runMigrations();
  await seedRoles();
  await ensureDefaultAdminUser();
  console.log("Database and tables are ready");
}

async function createTables() {
  await db.query(`
    CREATE TABLE IF NOT EXISTS roles (
      id INT AUTO_INCREMENT PRIMARY KEY,
      name VARCHAR(100) NOT NULL UNIQUE,
      is_active TINYINT(1) NOT NULL DEFAULT 1,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);
  await db.query(`
    CREATE TABLE IF NOT EXISTS users (
      id INT AUTO_INCREMENT PRIMARY KEY,
      username VARCHAR(120) NOT NULL,
      email VARCHAR(190) NOT NULL UNIQUE,
      password_hash VARCHAR(255) NOT NULL,
      account_type VARCHAR(20) NULL,
      phone VARCHAR(40) NULL,
      address VARCHAR(255) NULL,
      profile_photo VARCHAR(255) NULL,
      reset_token_hash VARCHAR(128) NULL,
      reset_token_expires_at DATETIME NULL,
      team_invite_token_hash VARCHAR(128) NULL,
      team_invite_token_expires_at DATETIME NULL,
      role_id INT NULL,
      is_active TINYINT(1) NOT NULL DEFAULT 1,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE SET NULL ON UPDATE CASCADE
    )
  `);
  await db.query(`
    CREATE TABLE IF NOT EXISTS teams (
      id INT AUTO_INCREMENT PRIMARY KEY,
      name VARCHAR(120) NOT NULL UNIQUE,
      is_active TINYINT(1) NOT NULL DEFAULT 1,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);
  await db.query(`
    CREATE TABLE IF NOT EXISTS tasks (
      id INT AUTO_INCREMENT PRIMARY KEY,
      title VARCHAR(255) NOT NULL,
      status VARCHAR(30) NOT NULL DEFAULT 'Pending',
      priority VARCHAR(20) NOT NULL DEFAULT 'Medium',
      due_date DATE NULL,
      user_id INT NULL,
      assignee_user_id INT NULL,
      team_id INT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);
  await db.query(`
    CREATE TABLE IF NOT EXISTS team_members (
      id INT AUTO_INCREMENT PRIMARY KEY,
      team_id INT NOT NULL,
      user_id INT NOT NULL,
      role_id INT NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      UNIQUE KEY uq_team_user (team_id, user_id),
      FOREIGN KEY (team_id) REFERENCES teams(id) ON DELETE CASCADE ON UPDATE CASCADE,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE ON UPDATE CASCADE,
      FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE RESTRICT ON UPDATE CASCADE
    )
  `);
}

async function ensureColumn(table, column, definition) {
  const [rows] = await db.query(
    "SELECT 1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = ? AND TABLE_NAME = ? AND COLUMN_NAME = ? LIMIT 1",
    [dbName, table, column]
  );
  if (!rows.length) await db.query(`ALTER TABLE \`${table}\` ADD COLUMN ${definition}`);
}

async function runMigrations() {
  // Schema columns that may be missing from pre-existing tables
  const columns = [
    ["roles", "is_active", "is_active TINYINT(1) NOT NULL DEFAULT 1"],
    ["users", "is_active", "is_active TINYINT(1) NOT NULL DEFAULT 1"],
    ["users", "password_hash", "password_hash VARCHAR(255) NOT NULL DEFAULT ''"],
    ["users", "account_type", "account_type VARCHAR(20) NULL"],
    ["users", "phone", "phone VARCHAR(40) NULL"],
    ["users", "address", "address VARCHAR(255) NULL"],
    ["users", "profile_photo", "profile_photo VARCHAR(255) NULL"],
    ["users", "reset_token_hash", "reset_token_hash VARCHAR(128) NULL"],
    ["users", "reset_token_expires_at", "reset_token_expires_at DATETIME NULL"],
    ["users", "team_invite_token_hash", "team_invite_token_hash VARCHAR(128) NULL"],
    ["users", "team_invite_token_expires_at", "team_invite_token_expires_at DATETIME NULL"],
    ["tasks", "priority", "priority VARCHAR(20) NOT NULL DEFAULT 'Medium'"],
    ["tasks", "due_date", "due_date DATE NULL"],
    ["tasks", "user_id", "user_id INT NULL"],
    ["tasks", "assignee_user_id", "assignee_user_id INT NULL"],
    ["tasks", "team_id", "team_id INT NULL"],
  ];
  for (const [table, column, definition] of columns) {
    await ensureColumn(table, column, definition);
  }

  // Backfill team_id on tasks for single-team users
  await db.query(`
    UPDATE tasks
    INNER JOIN (
      SELECT user_id, MIN(team_id) AS team_id, COUNT(DISTINCT team_id) AS team_count
      FROM team_members
      GROUP BY user_id
    ) s ON s.user_id = tasks.user_id
    SET tasks.team_id = s.team_id
    WHERE tasks.team_id IS NULL AND s.team_count = 1
  `);

  // Backfill account_type from team_members
  await db.query(`
    UPDATE users SET account_type = 'team'
    WHERE account_type IS NULL AND id IN (SELECT DISTINCT user_id FROM team_members)
  `);
  await db.query("UPDATE users SET account_type = 'personal' WHERE account_type IS NULL");
}

async function seedRoles() {
  await db.query("INSERT IGNORE INTO roles (name) VALUES ('Admin'), ('Personal Account'), ('Editor'), ('Team Leader'), ('Viewer'), ('Member')");
}

async function ensureDefaultAdminUser() {
  const adminEmail = (process.env.DEFAULT_ADMIN_EMAIL || "admin@taskflow.local").trim();
  const adminPassword = process.env.DEFAULT_ADMIN_PASSWORD || "ChangeMe123!";
  const adminName = (process.env.DEFAULT_ADMIN_USERNAME || "Admin").trim();

  const [[role]] = await db.query("SELECT id FROM roles WHERE name = 'Admin' LIMIT 1");
  if (!role) throw new Error("Admin role is missing");

  const passwordHash = createPasswordHash(adminPassword);
  await db.query(
    `INSERT INTO users (username, email, password_hash, account_type, role_id, is_active)
     VALUES (?, ?, ?, 'personal', ?, 1)
     ON DUPLICATE KEY UPDATE
       username = VALUES(username),
       password_hash = VALUES(password_hash),
       account_type = 'personal',
       role_id = VALUES(role_id),
       is_active = 1`,
    [adminName, adminEmail, passwordHash, role.id]
  );
  await db.query("UPDATE roles SET is_active = 1 WHERE id = ?", [role.id]);
  console.log("Default admin account is ready");
  
}

// ─── DB Query Helpers ────────────────────────────────────────────────────────

async function countActiveAdmins() {
  const [[row]] = await db.query(
    `SELECT COUNT(*) AS count FROM users
     INNER JOIN roles ON roles.id = users.role_id
     WHERE users.is_active = 1 AND roles.name = ? AND roles.is_active = 1`,
    [ROLE_NAMES.ADMIN]
  );
  return Number(row?.count ?? 0);
}

async function findRoleById(roleId) {
  const [[role]] = await db.query("SELECT id, name, is_active FROM roles WHERE id = ? LIMIT 1", [roleId]);
  return role ?? null;
}

async function findUserWithRole(userId) {
  const [[user]] = await db.query(
    `SELECT users.id, users.is_active, users.role_id,
            roles.name AS role_name, roles.is_active AS role_is_active
     FROM users LEFT JOIN roles ON roles.id = users.role_id
     WHERE users.id = ? LIMIT 1`,
    [userId]
  );
  return user ?? null;
}

async function findUserTeamIds(userId) {
  const [rows] = await db.query(
    "SELECT DISTINCT team_id FROM team_members WHERE user_id = ? ORDER BY team_id ASC",
    [userId]
  );
  return rows.map((r) => r.team_id);
}

async function findTeamMembersByTeamIds(teamIds, options = {}) {
  if (!Array.isArray(teamIds) || !teamIds.length) return [];
  const excludeUserId = Number.isInteger(options.excludeUserId) ? options.excludeUserId : null;
  const roleName = typeof options.roleName === "string" && options.roleName.trim() ? options.roleName.trim() : null;
  const placeholders = teamIds.map(() => "?").join(",");
  const excludeClause = excludeUserId ? "AND users.id <> ?" : "";
  const roleClause = roleName ? "AND roles.name = ?" : "";
  const queryParams = [...teamIds];
  if (excludeUserId) queryParams.push(excludeUserId);
  if (roleName) queryParams.push(roleName);
  const [rows] = await db.query(
    `SELECT DISTINCT users.id, users.username, users.email, roles.name AS role_name
     FROM team_members
     INNER JOIN users ON users.id = team_members.user_id
     INNER JOIN roles ON roles.id = team_members.role_id
     INNER JOIN teams ON teams.id = team_members.team_id
     WHERE team_members.team_id IN (${placeholders})
       AND users.is_active = 1
       AND roles.is_active = 1
       AND teams.is_active = 1
       ${excludeClause}
       ${roleClause}
     ORDER BY users.username ASC`,
    queryParams
  );
  return rows;
}

let smtpTransporter = null;
function getSmtpTransporter() {
  if (!nodemailer || !SMTP_HOST || !SMTP_FROM || !SMTP_PORT) return null;
  if (!smtpTransporter) {
    smtpTransporter = nodemailer.createTransport({
      host: SMTP_HOST,
      port: SMTP_PORT,
      secure: SMTP_SECURE,
      auth: SMTP_USER ? { user: SMTP_USER, pass: SMTP_PASS } : undefined,
    });
  }
  return smtpTransporter;
}

async function sendTaskAssignmentEmail({ toEmail, assigneeName, assignerName, title, status, priority, dueDate }) {
  if (!toEmail) return false;
  const transporter = getSmtpTransporter();
  if (!transporter) {
    console.log(`[assignment email skipped] Missing SMTP settings. Assigned "${title}" to ${toEmail}.`);
    return false;
  }

  const duePart = dueDate ? `Due date: ${dueDate}` : "Due date: Not set";
  const subject = `New task assigned: ${title}`;
  const text = [
    `Hello ${assigneeName || "team member"},`,
    "",
    `${assignerName} assigned you a task in Task Flow.`,
    `Task: ${title}`,
    `Status: ${status}`,
    `Priority: ${priority}`,
    duePart,
    "",
    `Open your tasks: ${APP_BASE_URL}/tasks`,
  ].join("\n");

  try {
    await transporter.sendMail({
      from: SMTP_FROM,
      to: toEmail,
      subject,
      text,
    });
    return true;
  } catch (error) {
    console.error(`Failed to send assignment email to ${toEmail}:`, error?.message || error);
    return false;
  }
}

async function sendTeamInviteEmail({ toEmail, memberName, inviterName, teamName, inviteLink }) {
  if (!toEmail || !inviteLink) return false;
  const transporter = getSmtpTransporter();
  if (!transporter) {
    console.log(`[team invite email skipped] Missing SMTP settings. Invite link for ${toEmail}: ${inviteLink}`);
    return false;
  }

  const subject = `You were added to ${teamName} on Task Flow`;
  const text = [
    `Hello ${memberName || "Team member"},`,
    "",
    `${inviterName || "Your Team Leader"} added you to team "${teamName}".`,
    "Click this link to join the team workspace and open tasks:",
    inviteLink,
    "",
    "You can use this same link again anytime.",
  ].join("\n");

  try {
    await transporter.sendMail({
      from: SMTP_FROM,
      to: toEmail,
      subject,
      text,
    });
    return true;
  } catch (error) {
    console.error(`Failed to send team invite email to ${toEmail}:`, error?.message || error);
    return false;
  }
}

async function resolveTaskScope(req) {
  const userId = req.currentUser?.userId;
  const roleName = req.currentUser?.roleName ?? null;
  if (!userId) throw new Error("Missing current user for task scope");

  if (roleName === ROLE_NAMES.ADMIN) {
    return { type: "all", userId, roleName, teamIds: [], primaryTeamId: null };
  }

  if (req.currentUser?.accountType !== "team") {
    return { type: "personal", userId, roleName, teamIds: [], primaryTeamId: null };
  }

  const teamIds = await findUserTeamIds(userId);
  // Team account without team membership should still be able to manage personal tasks.
  if (!teamIds.length) return { type: "personal", userId, roleName, teamIds: [], primaryTeamId: null };
  return { type: "team", userId, roleName, teamIds, primaryTeamId: teamIds[0] };
}

function buildTaskScopeCondition(scope, tableAlias = "") {
  const p = tableAlias ? `${tableAlias}.` : "";
  if (scope.type === "all") {
    return {
      clause: "1 = 1",
      params: [],
    };
  }
  if (scope.type === "team" && scope.teamIds.length) {
    if (scope.roleName === ROLE_NAMES.MEMBER) {
      return {
        clause: `${p}team_id IN (${scope.teamIds.map(() => "?").join(",")}) AND ${p}assignee_user_id = ?`,
        params: [...scope.teamIds, scope.userId],
      };
    }
    return {
      clause: `${p}team_id IN (${scope.teamIds.map(() => "?").join(",")})`,
      params: [...scope.teamIds],
    };
  }
  if (scope.type === "team") {
    return {
      clause: "1 = 0",
      params: [],
    };
  }
  return {
    clause: `${p}user_id = ? AND ${p}team_id IS NULL`,
    params: [scope.userId],
  };
}

function workspaceViewFromScope(scope) {
  return scope.type === "all" ? "admin" : scope.type;
}

// ─── Routes: Public ───────────────────────────────────────────────────────────

app.get("/", (req, res) => res.redirect(req.currentUser ? "/home" : "/login"));

app.get("/login", (req, res) => {
  if (req.currentUser) return res.redirect("/home");
  res.render("login", {
    returnTo: safeReturnTo(req.query.returnTo || "/home"),
    error: req.query.error || "",
    message: req.query.message || "",
  });
});

app.get("/register", (req, res) => {
  if (req.currentUser) return res.redirect("/home");
  res.render("register", {
    error: req.query.error || "",
    message: req.query.message || "",
    initialAccountType: req.query.accountType === "team_leader" ? "team_leader" : "personal",
  });
});

app.get("/join-team", (req, res) => {
  if (req.currentUser) return res.redirect("/teams");
  const rawToken = typeof req.query.token === "string" ? req.query.token.trim() : "";

  const renderJoinPage = (inviteDetails = null) =>
    res.render("join_team", {
      error: req.query.error || "",
      message: req.query.message || "",
      inviteToken: rawToken,
      invitedUsername: inviteDetails?.username || "",
      invitedTeamName: inviteDetails?.team_name || "",
      invitedEmail: inviteDetails?.email || "",
    });

  if (!rawToken) return renderJoinPage();

  (async () => {
    try {
      const tokenHash = hashResetToken(rawToken);
      const [rows] = await db.query(
        `SELECT users.id, users.username, users.email, users.is_active, teams.name AS team_name
         FROM users
         INNER JOIN team_members ON team_members.user_id = users.id
         INNER JOIN teams ON teams.id = team_members.team_id
         INNER JOIN roles ON roles.id = team_members.role_id
         WHERE users.team_invite_token_hash = ?
           AND (users.team_invite_token_expires_at IS NULL OR users.team_invite_token_expires_at > NOW())
           AND users.account_type = 'team'
           AND teams.is_active = 1
           AND roles.name = ?
         LIMIT 1`,
        [tokenHash, ROLE_NAMES.MEMBER]
      );
      const member = rows[0] || null;
      if (!member) {
        return res.redirect(`/login?type=team&error=${encodeURIComponent("Invite link is invalid or expired")}`);
      }
      if (member.is_active) {
        return res.redirect(`/login?type=team&message=${encodeURIComponent("Invite already accepted. Please sign in.")}`);
      }
      return renderJoinPage(member);
    } catch (err) {
      return res.redirect(`/login?type=team&error=${encodeURIComponent("Unable to open invite link right now")}`);
    }
  })();
});

app.post("/join-team", async (req, res, next) => {
  try {
    const inviteToken = typeof req.body.token === "string" ? req.body.token.trim() : "";
    const username = (req.body.username || "").trim();
    const teamName = (req.body.team_name || "").trim();
    const password = req.body.password || "";
    const confirmPassword = req.body.confirm_password || "";
    const tokenQuery = inviteToken ? `&token=${encodeURIComponent(inviteToken)}` : "";

    if ((!inviteToken && (!username || !teamName)) || !password || !confirmPassword) {
      return res.redirect(`/join-team?error=${encodeURIComponent("All fields are required")}${tokenQuery}`);
    }
    if (password.length < 8) {
      return res.redirect(`/join-team?error=${encodeURIComponent("Password must be at least 8 characters")}${tokenQuery}`);
    }
    if (password !== confirmPassword) {
      return res.redirect(`/join-team?error=${encodeURIComponent("Passwords do not match")}${tokenQuery}`);
    }

    const [rows] = inviteToken
      ? await db.query(
        `SELECT users.id, users.username, users.email, users.account_type, users.role_id, users.is_active,
                roles.name AS role_name
         FROM users
         INNER JOIN team_members ON team_members.user_id = users.id
         INNER JOIN teams ON teams.id = team_members.team_id
         INNER JOIN roles ON roles.id = team_members.role_id
         WHERE users.team_invite_token_hash = ?
           AND (users.team_invite_token_expires_at IS NULL OR users.team_invite_token_expires_at > NOW())
           AND teams.is_active = 1
           AND users.account_type = 'team'
           AND roles.name = ?
         LIMIT 1`,
        [hashResetToken(inviteToken), ROLE_NAMES.MEMBER]
      )
      : await db.query(
        `SELECT users.id, users.username, users.email, users.account_type, users.role_id, users.is_active,
                roles.name AS role_name
         FROM users
         INNER JOIN team_members ON team_members.user_id = users.id
         INNER JOIN teams ON teams.id = team_members.team_id
         INNER JOIN roles ON roles.id = team_members.role_id
         WHERE LOWER(users.username) = LOWER(?)
           AND LOWER(teams.name) = LOWER(?)
           AND teams.is_active = 1
           AND users.account_type = 'team'
           AND roles.name = ?
         LIMIT 1`,
        [username, teamName, ROLE_NAMES.MEMBER]
      );
    const member = rows[0] || null;

    if (!member) {
      return res.redirect(`/join-team?error=${encodeURIComponent("No pending member invite found for that username and team")}${tokenQuery}`);
    }
    if (member.is_active) {
      return res.redirect(`/login?type=team&message=${encodeURIComponent("Your team account is already active. Please sign in.")}`);
    }

    await db.query(
      "UPDATE users SET password_hash = ?, is_active = 1, team_invite_token_hash = NULL, team_invite_token_expires_at = NULL WHERE id = ?",
      [createPasswordHash(password), member.id]
    );

    const sessionId = createSession({
      id: member.id,
      username: member.username,
      email: member.email,
      account_type: member.account_type,
      role_id: member.role_id,
      role_name: member.role_name,
    });
    setSessionCookie(res, sessionId);
    return res.redirect("/teams?message=Welcome%20to%20your%20team%20workspace");
  } catch (err) {
    return next(err);
  }
});

app.get("/team-invite/accept", async (req, res, next) => {
  try {
    const token = typeof req.query.token === "string" ? req.query.token.trim() : "";
    if (!token) {
      return res.redirect(`/login?type=team&error=${encodeURIComponent("Invite link is missing or invalid")}`);
    }

    const tokenHash = hashResetToken(token);
    const [rows] = await db.query(
      `SELECT users.id, users.username, users.email, users.account_type, users.role_id, users.is_active,
              roles.name AS role_name, teams.name AS team_name
       FROM users
       INNER JOIN team_members ON team_members.user_id = users.id
       INNER JOIN teams ON teams.id = team_members.team_id
       INNER JOIN roles ON roles.id = team_members.role_id
       WHERE users.team_invite_token_hash = ?
         AND (users.team_invite_token_expires_at IS NULL OR users.team_invite_token_expires_at > NOW())
         AND users.account_type = 'team'
         AND teams.is_active = 1
         AND roles.name = ?
       LIMIT 1`,
      [tokenHash, ROLE_NAMES.MEMBER]
    );
    const member = rows[0] || null;
    if (!member) {
      return res.redirect(`/login?type=team&error=${encodeURIComponent("Invite link is invalid or expired")}`);
    }

    return res.redirect(`/join-team?token=${encodeURIComponent(token)}&message=${encodeURIComponent(`Welcome to ${member.team_name}. Set your password to continue.`)}`);
  } catch (err) {
    return next(err);
  }
});

app.post("/register", async (req, res, next) => {
  try {
    const username = (req.body.username || "").trim();
    const email = (req.body.email || "").trim();
    const password = req.body.password || "";
    const accountType = req.body.account_type === "team_leader" ? "team_leader" : "personal";
    const teamName = (req.body.team_name || "").trim();

    if (!username || !email || !password)
      return res.redirect(`/register?error=${encodeURIComponent("Username, email, and password are required")}`);
    if (password.length < 8)
      return res.redirect(`/register?error=${encodeURIComponent("Password must be at least 8 characters")}`);
    if (accountType === "team_leader" && !teamName)
      return res.redirect(`/register?accountType=team_leader&error=${encodeURIComponent("Team name is required for a Team Leader account")}`);

    const [roles] = await db.query(
      "SELECT id, name FROM roles WHERE name IN ('Viewer', 'Team Leader') AND is_active = 1"
    );
    const viewerRole = roles.find((r) => r.name === ROLE_NAMES.VIEWER) ?? null;
    const teamLeaderRole = roles.find((r) => r.name === ROLE_NAMES.TEAM_LEADER) ?? null;
    const roleToAssign = accountType === "team_leader" ? teamLeaderRole : viewerRole;

    if (!roleToAssign)
      return res.redirect(`/register?error=${encodeURIComponent("Required role is missing or inactive. Contact an administrator.")}`);

    const passwordHash = createPasswordHash(password);

    if (accountType !== "team_leader") {
      const [result] = await db.query(
        "INSERT INTO users (username, email, password_hash, account_type, role_id, is_active) VALUES (?, ?, ?, 'personal', ?, 1)",
        [username, email, passwordHash, roleToAssign.id]
      ).catch((err) => {
        if (err.code === "ER_DUP_ENTRY")
          return res.redirect(`/register?error=${encodeURIComponent("That email is already in use")}`);
        throw err;
      });
      const sessionId = createSession({ id: result.insertId, username, email, account_type: "personal", role_id: roleToAssign.id, role_name: roleToAssign.name });
      logAuthEvent("REGISTER_AND_LOGIN", { username, role_name: roleToAssign.name, account_type: "personal" }, req);
      setSessionCookie(res, sessionId);
      return res.redirect(`/home?message=${encodeURIComponent("Account created. Welcome to your dashboard!")}`);
    }

    const conn = await db.getConnection();
    try {
      await conn.beginTransaction();
      const [userResult] = await conn.query(
        "INSERT INTO users (username, email, password_hash, account_type, role_id, is_active) VALUES (?, ?, ?, 'team', ?, 1)",
        [username, email, passwordHash, roleToAssign.id]
      );
      const [teamResult] = await conn.query("INSERT INTO teams (name, is_active) VALUES (?, 1)", [teamName]);
      await conn.query("INSERT INTO team_members (team_id, user_id, role_id) VALUES (?, ?, ?)", [teamResult.insertId, userResult.insertId, roleToAssign.id]);
      await conn.commit();
      const sessionId = createSession({ id: userResult.insertId, username, email, account_type: "team", role_id: roleToAssign.id, role_name: roleToAssign.name });
      logAuthEvent("REGISTER_AND_LOGIN", { username, role_name: roleToAssign.name, account_type: "team" }, req);
      setSessionCookie(res, sessionId);
      res.redirect(`/home?message=${encodeURIComponent("Team Leader account created. Welcome to your dashboard.")}`);
    } catch (err) {
      await conn.rollback();
      if (err.code === "ER_DUP_ENTRY") {
        const target = err.message.includes("teams") ? "team_leader&error=" + encodeURIComponent("That team name already exists") : "team_leader&error=" + encodeURIComponent("That email is already in use");
        return res.redirect(`/register?accountType=${target}`);
      }
      throw err;
    } finally {
      conn.release();
    }
  } catch (err) {
    next(err);
  }
});

app.use(["/login", "/register", "/reset-password", "/reset-password/confirm"], authRateLimiter);

app.post("/login", async (req, res, next) => {
  try {
    const identifier = (req.body.identifier || req.body.email || "").trim();
    const password = req.body.password || "";
    const returnTo = safeReturnTo(req.body.returnTo || "/home");
    const loginType = req.body.login_type === "team" ? "team" : "personal";

    if (!identifier || !password)
      return res.redirect(`/login?error=${encodeURIComponent("Username or email and password are required")}&returnTo=${encodeURIComponent(returnTo)}`);

    const [[user]] = await db.query(
      `SELECT users.id, users.username, users.email, users.password_hash, users.account_type,
              users.role_id, users.is_active, roles.name AS role_name, roles.is_active AS role_is_active
       FROM users LEFT JOIN roles ON roles.id = users.role_id
       WHERE users.email = ? OR users.username = ?
       ORDER BY CASE WHEN users.email = ? THEN 0 WHEN users.username = ? THEN 1 ELSE 2 END, users.id DESC
       LIMIT 1`,
      [identifier, identifier, identifier, identifier]
    );

    if (!user || !user.is_active || !verifyPassword(password, user.password_hash))
      return res.redirect(`/login?error=${encodeURIComponent("Invalid username/email or password")}&returnTo=${encodeURIComponent(returnTo)}`);
    if (user.role_id && !user.role_is_active)
      return res.redirect(`/login?error=${encodeURIComponent("Your role is inactive. Contact an administrator.")}&returnTo=${encodeURIComponent(returnTo)}`);

    const userAccountType = user.account_type === "team" ? "team" : "personal";
    if (loginType === "team" && userAccountType !== "team") {
      return res.redirect(`/login?error=${encodeURIComponent("This account is not a Team account. Use Personal Sign In.")}&returnTo=${encodeURIComponent(returnTo)}`);
    }
    if (loginType === "personal" && userAccountType !== "personal") {
      return res.redirect(`/login?error=${encodeURIComponent("This account is a Team account. Use Team Sign In.")}&returnTo=${encodeURIComponent(returnTo)}&type=team`);
    }

    logAuthEvent("LOGIN_SUCCESS", user, req);
    setSessionCookie(res, createSession(user));
    res.redirect("/home");
  } catch (err) {
    next(err);
  }
});

app.post("/logout", requireAuth, requireCsrf, (req, res) => {
  logAuthEvent("LOGOUT", req.currentUser, req);
  destroySession(req, res);
  res.redirect("/login");
});

app.get("/logout", (req, res) => {
  if (req.currentUser) logAuthEvent("LOGOUT", req.currentUser, req);
  destroySession(req, res);
  res.redirect("/login?message=You%20have%20been%20logged%20out.");
});

app.get("/reset-password", (req, res) => {
  if (req.currentUser) return res.redirect("/home");
  res.render("reset_password", { error: req.query.error || "", message: req.query.message || "", resetLink: "" });
});

app.post("/reset-password", async (req, res, next) => {
  try {
    const email = (req.body.email || "").trim();
    if (!email)
      return res.redirect(`/reset-password?error=${encodeURIComponent("Email is required")}`);

    const [[user]] = await db.query("SELECT id, is_active FROM users WHERE email = ? LIMIT 1", [email]);
    const successMessage = "If an active account exists, a reset link has been generated.";
    if (!user || !user.is_active)
      return res.redirect(`/reset-password?message=${encodeURIComponent(successMessage)}`);

    const { rawToken, tokenHash } = createResetTokenPair();
    await db.query(
      "UPDATE users SET reset_token_hash = ?, reset_token_expires_at = ? WHERE id = ?",
      [tokenHash, new Date(Date.now() + RESET_TOKEN_TTL_MS), user.id]
    );
    const resetLink = `${APP_BASE_URL}/reset-password/confirm?token=${encodeURIComponent(rawToken)}`;
    console.log(`Password reset link for ${email}: ${resetLink}`);
    res.render("reset_password", {
      error: "",
      message: "Reset link created. Use the link below or copy it from the server console.",
      resetLink,
    });
  } catch (err) {
    next(err);
  }
});

app.get("/reset-password/confirm", async (req, res, next) => {
  try {
    if (req.currentUser) return res.redirect("/home");
    const token = (req.query.token || "").trim();
    if (!token)
      return res.redirect(`/reset-password?error=${encodeURIComponent("Reset token is missing")}`);

    const [[row]] = await db.query(
      "SELECT id FROM users WHERE reset_token_hash = ? AND reset_token_expires_at > NOW() AND is_active = 1 LIMIT 1",
      [hashResetToken(token)]
    );
    if (!row)
      return res.redirect(`/reset-password?error=${encodeURIComponent("Reset link is invalid or has expired")}`);

    res.render("reset_password_confirm", { token, error: req.query.error || "", message: req.query.message || "" });
  } catch (err) {
    next(err);
  }
});

app.post("/reset-password/confirm", async (req, res, next) => {
  try {
    const token = (req.body.token || "").trim();
    const password = req.body.password || "";
    const confirmPassword = req.body.confirm_password || "";

    if (!token)
      return res.redirect(`/reset-password?error=${encodeURIComponent("Reset token is missing")}`);
    if (!password || !confirmPassword)
      return res.redirect(`/reset-password/confirm?token=${encodeURIComponent(token)}&error=${encodeURIComponent("Password and confirmation are required")}`);
    if (password.length < 8)
      return res.redirect(`/reset-password/confirm?token=${encodeURIComponent(token)}&error=${encodeURIComponent("Password must be at least 8 characters")}`);
    if (password !== confirmPassword)
      return res.redirect(`/reset-password/confirm?token=${encodeURIComponent(token)}&error=${encodeURIComponent("Passwords do not match")}`);

    const [[user]] = await db.query(
      "SELECT id FROM users WHERE reset_token_hash = ? AND reset_token_expires_at > NOW() AND is_active = 1 LIMIT 1",
      [hashResetToken(token)]
    );
    if (!user)
      return res.redirect(`/reset-password?error=${encodeURIComponent("Reset link is invalid or has expired")}`);

    await db.query(
      "UPDATE users SET password_hash = ?, reset_token_hash = NULL, reset_token_expires_at = NULL WHERE id = ?",
      [createPasswordHash(password), user.id]
    );
    invalidateSessionsForUser(user.id);
    res.redirect(`/login?message=${encodeURIComponent("Password reset successful. Please sign in.")}`);
  } catch (err) {
    next(err);
  }
});

// ─── Routes: Authenticated ────────────────────────────────────────────────────

app.use(sessionMiddleware);
app.use(attachAuthorizationLocals);
app.use(attachTeamAccessLocals);
app.use(requireAuth);
app.use(requireCsrf);

const requireTaskReadAccess = requirePermission(PERMISSIONS.VIEW_TASKS, "/home");
const requireTaskWriteAccess = async (req, res, next) => {
  try {
    if (can(req.currentUser?.roleName, PERMISSIONS.WRITE_TASKS)) return next();
    const scope = await resolveTaskScope(req);
    // Personal scope users can always manage their own personal tasks.
    if (scope.type === "personal") return next();
    return denyWithRedirect(req, res, "/tasks", "You do not have permission to access that page.");
  } catch (err) {
    next(err);
  }
};
const requireUserRoleAdminAccess = requirePermission(PERMISSIONS.MANAGE_USERS_ROLES, "/home");
const requireTeamMemberManageAccess = async (req, res, next) => {
  try {
    if (req.currentUser?.roleName === ROLE_NAMES.TEAM_LEADER) return next();
    if (can(req.currentUser?.roleName, PERMISSIONS.MANAGE_USERS_ROLES)) return next();
    return denyWithRedirect(req, res, "/home", "Only Team Leaders can manage team members.");
  } catch (err) {
    next(err);
  }
};
const requireTeamAreaAccess = (req, res, next) => {
  if (can(req.currentUser?.roleName, PERMISSIONS.MANAGE_USERS_ROLES)) return next();
  if (req.currentUser?.accountType === "team") return next();
  return denyWithRedirect(req, res, "/home", "Team pages are available only to team users.");
};

app.get("/admin/logs", requireUserRoleAdminAccess, async (req, res, next) => {
  try {
    const logs = [
      {
        title: "Access Audit Log",
        path: "auth.log",
        content: readLogTail(path.join(__dirname, "auth.log"), { maxLines: 500, maxChars: 200000 }).text,
      },
      {
        title: "Server Output",
        path: "server.out.log",
        content: readLogTail(path.join(__dirname, "server.out.log"), { maxLines: 250, maxChars: 120000 }).text,
      },
      {
        title: "Server Errors",
        path: "server.err.log",
        content: readLogTail(path.join(__dirname, "server.err.log"), { maxLines: 250, maxChars: 120000 }).text,
      },
    ];
    return res.render("admin_logs", { logs, error: req.query.error || "", message: req.query.message || "" });
  } catch (err) {
    return next(err);
  }
});

app.get("/overview", requireTaskReadAccess, (_req, res) => res.redirect("/home"));
app.get("/csrf-token", requireAuth, (req, res) => {
  res.setHeader("Cache-Control", "no-store");
  return res.json({ csrfToken: req.currentUser?.csrfToken ?? "" });
});

// ─── Tasks ────────────────────────────────────────────────────────────────────

app.get("/tasks", requireTaskReadAccess, async (req, res, next) => {
  try {
    const currentStatus = req.query.status || "All";
    const currentPriority = req.query.priority || "All";
    const search = (req.query.q || "").trim();
    const scope = await resolveTaskScope(req);
    const scoped = buildTaskScopeCondition(scope);
    const where = [scoped.clause];
    const params = [...scoped.params];

    if (currentStatus !== "All") { where.push("status = ?"); params.push(currentStatus); }
    if (currentPriority !== "All") { where.push("priority = ?"); params.push(currentPriority); }
    if (search) { where.push("title LIKE ?"); params.push(`%${search}%`); }

    const [tasks] = await db.query(
      `SELECT tasks.*, assignee.username AS assignee_username
       FROM tasks
       LEFT JOIN users AS assignee ON assignee.id = tasks.assignee_user_id
       WHERE ${where.join(" AND ")}
       ORDER BY tasks.id DESC`,
      params
    );
    const workspaceView = workspaceViewFromScope(scope);
    const canWriteTasks = can(req.currentUser?.roleName, PERMISSIONS.WRITE_TASKS) || scope.type === "personal";
    const teamMembers =
      scope.type === "team" &&
      req.currentUser?.roleName === ROLE_NAMES.TEAM_LEADER &&
      scope.primaryTeamId
        ? await findTeamMembersByTeamIds([scope.primaryTeamId], { excludeUserId: req.currentUser.userId, roleName: ROLE_NAMES.MEMBER })
        : [];
    res.render("index", {
      tasks,
      teamMembers,
      currentStatus,
      currentPriority,
      search,
      workspaceView,
      canWriteTasks,
      showTeamFields: workspaceView === "admin" || workspaceView === "team",
      error: req.query.error || "",
      message: req.query.message || "",
      returnTo: req.originalUrl || "/tasks",
    });
  } catch (err) { next(err); }
});

app.post("/add", requireTaskWriteAccess, async (req, res, next) => {
  try {
    const title = (req.body.title || "").trim();
    if (!title) return res.redirect(safeReturnTo(req.body.returnTo));
    const allowedStatuses = new Set(["Pending", "In Progress", "Completed"]);
    const allowedPriorities = new Set(["High", "Medium", "Low"]);
    const status = allowedStatuses.has(req.body.status) ? req.body.status : "Pending";
    const priority = allowedPriorities.has(req.body.priority) ? req.body.priority : "Medium";
    const dueDate = typeof req.body.due_date === "string" && /^\d{4}-\d{2}-\d{2}$/.test(req.body.due_date)
      ? req.body.due_date
      : null;
    const scope = await resolveTaskScope(req);
    if (scope.type === "team" && !scope.primaryTeamId) {
      return res.redirect("/home?error=You%20are%20not%20assigned%20to%20an%20active%20team");
    }
    const teamId = scope.type === "team" ? scope.primaryTeamId : null;
    let assigneeUserId = null;
    let assignee = null;
    const canAssignTeamTasks =
      scope.type === "team" &&
      req.currentUser?.roleName === ROLE_NAMES.TEAM_LEADER &&
      teamId;
    if (canAssignTeamTasks) {
      const requestedAssigneeId = parseOptionalInt(req.body.assignee_user_id);
      if (requestedAssigneeId !== null) {
        const members = await findTeamMembersByTeamIds([teamId], { excludeUserId: req.currentUser.userId, roleName: ROLE_NAMES.MEMBER });
        assignee = members.find((member) => Number(member.id) === requestedAssigneeId) || null;
        if (!assignee) {
          return res.redirect(appendQueryValue(safeReturnTo(req.body.returnTo), "error", "Please choose a valid team member assignee"));
        }
        assigneeUserId = requestedAssigneeId;
      }
    }
    await db.query(
      "INSERT INTO tasks (title, status, priority, due_date, user_id, assignee_user_id, team_id) VALUES (?, ?, ?, ?, ?, ?, ?)",
      [title, status, priority, dueDate, req.currentUser.userId, assigneeUserId, teamId]
    );
    if (assignee?.email) {
      await sendTaskAssignmentEmail({
        toEmail: assignee.email,
        assigneeName: assignee.username,
        assignerName: req.currentUser?.username || "Team Leader",
        title,
        status,
        priority,
        dueDate: dueDate || null,
      });
    }
    res.redirect(safeReturnTo(req.body.returnTo));
  } catch (err) { next(err); }
});

app.get("/edit/:id", requireTaskWriteAccess, async (req, res, next) => {
  try {
    const scope = await resolveTaskScope(req);
    const scoped = buildTaskScopeCondition(scope);
    const [[task]] = await db.query(`SELECT * FROM tasks WHERE id = ? AND ${scoped.clause}`, [req.params.id, ...scoped.params]);
    if (!task) return res.redirect(safeReturnTo(req.query.returnTo));
    const teamMembers =
      task.team_id && req.currentUser?.roleName === ROLE_NAMES.TEAM_LEADER
        ? await findTeamMembersByTeamIds([task.team_id], { excludeUserId: req.currentUser.userId, roleName: ROLE_NAMES.MEMBER })
        : [];
    res.render("edit", { task, teamMembers, returnTo: safeReturnTo(req.query.returnTo) });
  } catch (err) { next(err); }
});

app.post("/update/:id", requireTaskWriteAccess, async (req, res, next) => {
  try {
    const title = (req.body.title || "").trim();
    const returnTo = safeReturnTo(req.body.returnTo);
    if (!title) return res.redirect(`/edit/${req.params.id}?returnTo=${encodeURIComponent(returnTo)}`);
    const allowedStatuses = new Set(["Pending", "In Progress", "Completed"]);
    const allowedPriorities = new Set(["High", "Medium", "Low"]);
    const status = allowedStatuses.has(req.body.status) ? req.body.status : "Pending";
    const priority = allowedPriorities.has(req.body.priority) ? req.body.priority : "Medium";
    const dueDate = typeof req.body.due_date === "string" && /^\d{4}-\d{2}-\d{2}$/.test(req.body.due_date)
      ? req.body.due_date
      : null;
    const scope = await resolveTaskScope(req);
    const scoped = buildTaskScopeCondition(scope);
    const [[existingTask]] = await db.query(`SELECT * FROM tasks WHERE id = ? AND ${scoped.clause}`, [req.params.id, ...scoped.params]);
    if (!existingTask) return res.redirect(returnTo);
    let assigneeUserId = existingTask.assignee_user_id ?? null;
    let assignee = null;
    const canAssignTeamTasks =
      existingTask.team_id &&
      req.currentUser?.roleName === ROLE_NAMES.TEAM_LEADER;
    if (canAssignTeamTasks) {
      const requestedAssigneeId = parseOptionalInt(req.body.assignee_user_id);
      if (requestedAssigneeId === null) {
        assigneeUserId = null;
      } else {
        const members = await findTeamMembersByTeamIds([existingTask.team_id], { excludeUserId: req.currentUser.userId, roleName: ROLE_NAMES.MEMBER });
        assignee = members.find((member) => Number(member.id) === requestedAssigneeId) || null;
        if (!assignee) {
          return res.redirect(`/edit/${req.params.id}?returnTo=${encodeURIComponent(returnTo)}&error=${encodeURIComponent("Please choose a valid team member assignee")}`);
        }
        assigneeUserId = requestedAssigneeId;
      }
    }
    await db.query(
      `UPDATE tasks SET title = ?, status = ?, priority = ?, due_date = ?, assignee_user_id = ? WHERE id = ? AND ${scoped.clause}`,
      [title, status, priority, dueDate, assigneeUserId, req.params.id, ...scoped.params]
    );
    if (assignee?.email && Number(existingTask.assignee_user_id || 0) !== Number(assigneeUserId || 0)) {
      await sendTaskAssignmentEmail({
        toEmail: assignee.email,
        assigneeName: assignee.username,
        assignerName: req.currentUser?.username || "Team Leader",
        title,
        status,
        priority,
        dueDate: dueDate || null,
      });
    }
    res.redirect(returnTo);
  } catch (err) { next(err); }
});

app.post("/delete/:id", requireTaskWriteAccess, async (req, res, next) => {
  try {
    const scope = await resolveTaskScope(req);
    const scoped = buildTaskScopeCondition(scope);
    await db.query(`DELETE FROM tasks WHERE id = ? AND ${scoped.clause}`, [req.params.id, ...scoped.params]);
    res.redirect(safeReturnTo(req.body.returnTo));
  } catch (err) { next(err); }
});

app.post("/complete/:id", requireTaskWriteAccess, async (req, res, next) => {
  try {
    const scope = await resolveTaskScope(req);
    const scoped = buildTaskScopeCondition(scope);
    await db.query(`UPDATE tasks SET status = 'Completed' WHERE id = ? AND ${scoped.clause}`, [req.params.id, ...scoped.params]);
    res.redirect(safeReturnTo(req.body.returnTo));
  } catch (err) { next(err); }
});

// ─── Home ─────────────────────────────────────────────────────────────────────

app.get("/home", async (req, res, next) => {
  try {
    if (!req.currentUser) return res.redirect("/login");
    const scope = await resolveTaskScope(req);
    const workspaceView = workspaceViewFromScope(scope);
    if (workspaceView === "team" || workspaceView === "admin") {
      const isAdminManager = can(req.currentUser?.roleName, PERMISSIONS.MANAGE_USERS_ROLES);
      const isTeamLeader = req.currentUser?.roleName === ROLE_NAMES.TEAM_LEADER;
      const assignableRoles = [ROLE_NAMES.TEAM_LEADER, ROLE_NAMES.MEMBER];
      const visibleTeamIds = isAdminManager
        ? (await db.query("SELECT id FROM teams ORDER BY id ASC"))[0].map((row) => row.id)
        : await findUserTeamIds(req.currentUser.userId);
      if (!visibleTeamIds.length && !isAdminManager) {
        return res.redirect("/home?error=You%20are%20not%20assigned%20to%20a%20team");
      }

      const [roles] = await db.query("SELECT id, name, is_active FROM roles WHERE is_active = 1 AND name IN (?, ?) ORDER BY name ASC", assignableRoles);
      const memberAssignableRoles = roles.filter((role) => role.name === ROLE_NAMES.MEMBER);
      const scopeWhere = !isAdminManager && visibleTeamIds.length
        ? `WHERE teams.id IN (${visibleTeamIds.map(() => "?").join(",")})`
        : "";
      const scopeParams = !isAdminManager && visibleTeamIds.length ? visibleTeamIds : [];

      const [teams] = await db.query(
        `SELECT teams.id, teams.name, teams.is_active, COUNT(team_members.id) AS member_count
         FROM teams LEFT JOIN team_members ON team_members.team_id = teams.id
         ${scopeWhere} GROUP BY teams.id, teams.name, teams.is_active ORDER BY teams.id DESC`,
        scopeParams
      );
      const memberWhere = !isAdminManager && visibleTeamIds.length
        ? `WHERE team_members.team_id IN (${visibleTeamIds.map(() => "?").join(",")})`
        : "";
      const [members] = await db.query(
        `SELECT team_members.id, team_members.team_id, team_members.user_id, team_members.role_id,
                teams.name AS team_name, users.username, users.email, users.is_active AS user_is_active,
                roles.name AS role_name, roles.is_active AS role_is_active,
                SUM(CASE WHEN tasks.status <> 'Completed' THEN 1 ELSE 0 END) AS task_count
         FROM team_members
         INNER JOIN teams ON teams.id = team_members.team_id
         INNER JOIN users ON users.id = team_members.user_id
         INNER JOIN roles ON roles.id = team_members.role_id
         LEFT JOIN tasks ON tasks.assignee_user_id = team_members.user_id
           AND tasks.team_id = team_members.team_id
         ${memberWhere}
         GROUP BY team_members.id, team_members.team_id, team_members.user_id, team_members.role_id,
                  teams.name, users.username, users.email, users.is_active, roles.name, roles.is_active
         ORDER BY teams.name ASC, users.username ASC`,
        scopeParams
      );
      let mergedMembers = members;
      if (isAdminManager) {
        const [personalAccounts] = await db.query(
          `SELECT NULL AS id, NULL AS team_id, users.id AS user_id, users.role_id,
                  'Personal' AS team_name, users.username, users.email, users.is_active AS user_is_active,
                  roles.name AS role_name, roles.is_active AS role_is_active,
                  SUM(CASE WHEN tasks.status <> 'Completed' THEN 1 ELSE 0 END) AS task_count
           FROM users
           LEFT JOIN roles ON roles.id = users.role_id
           LEFT JOIN tasks ON tasks.user_id = users.id AND tasks.team_id IS NULL
           WHERE users.account_type = 'personal'
           GROUP BY users.id, users.role_id, users.username, users.email, users.is_active, roles.name, roles.is_active
           ORDER BY users.username ASC`
        );
        mergedMembers = [...members, ...personalAccounts].sort((a, b) => {
          const teamCompare = String(a.team_name || "").localeCompare(String(b.team_name || ""), undefined, { sensitivity: "base" });
          if (teamCompare !== 0) return teamCompare;
          return String(a.username || "").localeCompare(String(b.username || ""), undefined, { sensitivity: "base" });
        });
      }
      const primaryTeamId = !isAdminManager && teams.length ? teams[0].id : null;
      let dashboardStats = { teamMembers: 0, activeTasks: 0, completedTasks: 0 };
      if (primaryTeamId) {
        const [[memberCounts]] = await db.query(
          "SELECT COUNT(*) AS total_members FROM team_members WHERE team_id = ?",
          [primaryTeamId]
        );
        const [[taskCounts]] = await db.query(
          `SELECT
             SUM(CASE WHEN status = 'Completed' THEN 1 ELSE 0 END) AS completed_tasks,
             SUM(CASE WHEN status <> 'Completed' THEN 1 ELSE 0 END) AS active_tasks
           FROM tasks
           LEFT JOIN team_members AS owner_membership
             ON owner_membership.user_id = tasks.user_id
            AND owner_membership.team_id = ?
           LEFT JOIN team_members AS assignee_membership
             ON assignee_membership.user_id = tasks.assignee_user_id
            AND assignee_membership.team_id = ?
           WHERE tasks.team_id = ?
              OR (
                tasks.team_id IS NULL
                AND (owner_membership.user_id IS NOT NULL OR assignee_membership.user_id IS NOT NULL)
              )`,
          [primaryTeamId, primaryTeamId, primaryTeamId]
        );
        dashboardStats = {
          teamMembers: Number(memberCounts?.total_members ?? 0),
          activeTasks: Number(taskCounts?.active_tasks ?? 0),
          completedTasks: Number(taskCounts?.completed_tasks ?? 0),
        };
      }

      return res.render("teams", {
        teams,
        users: [],
        roles: memberAssignableRoles,
        members: mergedMembers,
        canManageMembers: isTeamLeader,
        primaryTeamName: !isAdminManager ? (teams[0]?.name || "My Team") : "",
        dashboardStats,
        error: normalizeTeamsErrorMessage(req.query.error || ""),
        message: req.query.message || "",
      });
    }

    const scoped = buildTaskScopeCondition(scope);
    let teamMembers = [];
    let teamMemberCount = 0;
    let leaderTeams = [];
    let memberRoleId = null;
    const [[stats]] = await db.query(
      `SELECT COUNT(*) AS total_tasks, SUM(CASE WHEN status = 'Completed' THEN 1 ELSE 0 END) AS completed_tasks
       FROM tasks WHERE ${scoped.clause}`,
      scoped.params
    );
    const [recentTasks] = await db.query(
      `SELECT tasks.id, tasks.title, tasks.status, assignee.username AS assignee_username
       FROM tasks
       LEFT JOIN users AS assignee ON assignee.id = tasks.assignee_user_id
       WHERE ${scoped.clause}
       ORDER BY tasks.id DESC
       LIMIT 12`,
      scoped.params
    );
    const [highPriorityTasks] = await db.query(
      `SELECT tasks.id, tasks.title, tasks.status, tasks.due_date, assignee.username AS assignee_username
       FROM tasks
       LEFT JOIN users AS assignee ON assignee.id = tasks.assignee_user_id
       WHERE ${scoped.clause} AND tasks.priority = 'High'
       ORDER BY tasks.id DESC
       LIMIT 8`,
      scoped.params
    );
    let personalStats = { totalTasks: 0, completedTasks: 0, progressPercent: 0 };
    let teamStats = { totalTasks: 0, completedTasks: 0, progressPercent: 0 };

    if (workspaceView === "personal") {
      const [[personalRaw]] = await db.query(
        `SELECT COUNT(*) AS total_tasks, SUM(CASE WHEN status = 'Completed' THEN 1 ELSE 0 END) AS completed_tasks
         FROM tasks WHERE team_id IS NULL AND user_id = ?`,
        [scope.userId]
      );
      const personalTotal = Number(personalRaw?.total_tasks ?? 0);
      const personalCompleted = Number(personalRaw?.completed_tasks ?? 0);
      personalStats = {
        totalTasks: personalTotal,
        completedTasks: personalCompleted,
        progressPercent: personalTotal ? Math.round((personalCompleted / personalTotal) * 100) : 0,
      };
    }

    const totalTasks = Number(stats?.total_tasks ?? 0);
    const completedTasks = Number(stats?.completed_tasks ?? 0);
    res.render("home", {
      error: req.query.error || "",
      message: req.query.message || "",
      workspaceView,
      teamMembers,
      teamMemberCount,
      leaderTeams,
      memberRoleId,
      totalTasks,
      completedTasks,
      progressPercent: totalTasks ? Math.round((completedTasks / totalTasks) * 100) : 0,
      recentTasks,
      personalStats,
      teamStats,
      highPriorityTasks,
    });
  } catch (err) { next(err); }
});

// ─── Users & Roles ────────────────────────────────────────────────────────────

app.get("/users-roles", requireUserRoleAdminAccess, async (req, res, next) => {
  try {
    const rolePlaceholders = USER_DIRECTORY_ROLE_NAMES.map(() => "?").join(", ");
    const [roles] = await db.query(
      `SELECT id, name, is_active
       FROM roles
       WHERE name IN (${rolePlaceholders})
       ORDER BY FIELD(name, ${rolePlaceholders})`,
      [...USER_DIRECTORY_ROLE_NAMES, ...USER_DIRECTORY_ROLE_NAMES]
    );
    const accountView = req.query.accounts === "closed" ? "closed" : req.query.accounts === "active" ? "active" : "all";
    const whereClause = accountView === "closed" ? "WHERE users.is_active = 0" : accountView === "active" ? "WHERE users.is_active = 1" : "";
    const [users] = await db.query(
      `SELECT users.id, users.username, users.email, users.account_type, users.role_id, users.is_active, roles.name AS role_name,
              user_teams.team_names
       FROM users
       LEFT JOIN roles ON users.role_id = roles.id
       LEFT JOIN (
         SELECT team_members.user_id, GROUP_CONCAT(DISTINCT teams.name ORDER BY teams.name SEPARATOR ', ') AS team_names
         FROM team_members
         INNER JOIN teams ON teams.id = team_members.team_id
         GROUP BY team_members.user_id
       ) AS user_teams ON user_teams.user_id = users.id
       ${whereClause}
       ORDER BY users.id DESC`
    );
    res.render("users_roles", { roles, users, accountView, error: req.query.error || "", message: req.query.message || "" });
  } catch (err) { next(err); }
});

app.post("/roles/add", requireUserRoleAdminAccess, async (req, res, next) => {
  return res.redirect(`/users-roles?error=${encodeURIComponent("Custom roles are disabled. Use Admin, Team Leader, Personal Account, or Member.")}`);
});

app.post("/roles/toggle/:id", requireUserRoleAdminAccess, async (req, res, next) => {
  return res.redirect(`/users-roles?error=${encodeURIComponent("Role status changes are disabled in this workspace.")}`);
});

app.get("/roles/toggle/:id", requireUserRoleAdminAccess, (_req, res) => {
  res.redirect(`/users-roles?error=${encodeURIComponent("Use the form action (POST) to change role status")}`);
});

app.post("/users/add", requireUserRoleAdminAccess, async (req, res, next) => {
  try {
    const username = (req.body.username || "").trim();
    const email = (req.body.email || "").trim();
    const roleId = Number.parseInt(req.body.role_id, 10);
    const normalizedRoleId = Number.isNaN(roleId) ? null : roleId;
    if (!username || !email) return res.redirect("/users-roles");

    if (normalizedRoleId !== null) {
      const role = await findRoleById(normalizedRoleId);
      if (!role || !role.is_active)
        return res.redirect(`/users-roles?error=${encodeURIComponent("Selected role is inactive or missing")}`);
      if (!isUserDirectoryRoleName(role.name))
        return res.redirect(`/users-roles?error=${encodeURIComponent("Only Admin, Team Leader, Personal Account, or Member can be assigned here")}`);
    }

    await db.query(
      "INSERT INTO users (username, email, password_hash, account_type, role_id, is_active) VALUES (?, ?, ?, 'personal', ?, 1)",
      [username, email, createPasswordHash(DEFAULT_USER_PASSWORD), normalizedRoleId]
    ).catch((err) => {
      if (err.code === "ER_DUP_ENTRY" || err.code === "ER_NO_REFERENCED_ROW_2")
        return res.redirect(`/users-roles?error=${encodeURIComponent("Could not create user with those details")}`);
      throw err;
    });
    res.redirect("/users-roles?message=User%20created.%20Default%20password%20is%20123.");
  } catch (err) { next(err); }
});

app.post("/users/assign-role/:id", requireUserRoleAdminAccess, async (req, res, next) => {
  try {
    const userId = Number.parseInt(req.params.id, 10);
    if (Number.isNaN(userId)) return res.redirect("/users-roles");
    const roleId = Number.parseInt(req.body?.role_id ?? req.query?.role_id, 10);
    const normalizedRoleId = Number.isNaN(roleId) ? null : roleId;

    const targetUser = await findUserWithRole(userId);
    if (!targetUser) return res.redirect(`/users-roles?error=${encodeURIComponent("User not found")}`);

    const isSelf = req.currentUser?.userId === userId;
    const isTargetActiveAdmin = targetUser.role_name === ROLE_NAMES.ADMIN && targetUser.is_active && targetUser.role_is_active;

    if (isSelf && targetUser.role_name === ROLE_NAMES.ADMIN && normalizedRoleId !== (await findRoleById(normalizedRoleId))?.id)
      return res.redirect(`/users-roles?error=${encodeURIComponent("You cannot remove your own Admin role")}`);

    if (isTargetActiveAdmin && normalizedRoleId !== null) {
      const newRole = await findRoleById(normalizedRoleId);
      if (!newRole || !newRole.is_active)
        return res.redirect(`/users-roles?error=${encodeURIComponent("Selected role is inactive or missing")}`);
      if (!isUserDirectoryRoleName(newRole.name))
        return res.redirect(`/users-roles?error=${encodeURIComponent("Only Admin, Team Leader, Personal Account, or Member can be assigned here")}`);
      if (newRole.name !== ROLE_NAMES.ADMIN) {
        const count = await countActiveAdmins();
        if (count <= 1) return res.redirect(`/users-roles?error=${encodeURIComponent("At least one active Admin must remain")}`);
      }
    }

    if (!isTargetActiveAdmin && normalizedRoleId !== null) {
      const newRole = await findRoleById(normalizedRoleId);
      if (!newRole || !newRole.is_active)
        return res.redirect(`/users-roles?error=${encodeURIComponent("Selected role is inactive or missing")}`);
      if (!isUserDirectoryRoleName(newRole.name))
        return res.redirect(`/users-roles?error=${encodeURIComponent("Only Admin, Team Leader, Personal Account, or Member can be assigned here")}`);
    }

    if (isTargetActiveAdmin && normalizedRoleId === null) {
      const count = await countActiveAdmins();
      if (count <= 1) return res.redirect(`/users-roles?error=${encodeURIComponent("At least one active Admin must remain")}`);
    }

    await db.query("UPDATE users SET role_id = ?, is_active = 1 WHERE id = ?", [normalizedRoleId, userId]);
    res.redirect("/users-roles");
  } catch (err) { next(err); }
});

app.get("/users/assign-role/:id", requireUserRoleAdminAccess, (_req, res) => {
  res.redirect(`/users-roles?error=${encodeURIComponent("Use the form action (POST) to assign roles")}`);
});

app.post("/users/toggle/:id", requireUserRoleAdminAccess, async (req, res, next) => {
  try {
    const returnTo = safeReturnTo(req.body.return_to || "/users-roles");
    const userId = Number.parseInt(req.params.id, 10);
    if (Number.isNaN(userId)) return res.redirect(appendQueryValue(returnTo, "error", "Invalid user id"));

    const targetUser = await findUserWithRole(userId);
    if (!targetUser) return res.redirect(appendQueryValue(returnTo, "error", "User not found"));

    const isSelf = req.currentUser?.userId === userId;
    const deactivating = Boolean(targetUser.is_active);
    const isTargetActiveAdmin = targetUser.role_name === ROLE_NAMES.ADMIN && targetUser.is_active && targetUser.role_is_active;

    if (isSelf && deactivating && targetUser.role_name === ROLE_NAMES.ADMIN)
      return res.redirect(appendQueryValue(returnTo, "error", "You cannot deactivate your own Admin account"));

    if (deactivating && isTargetActiveAdmin) {
      const count = await countActiveAdmins();
      if (count <= 1) return res.redirect(appendQueryValue(returnTo, "error", "At least one active Admin must remain"));
    }

    await db.query("UPDATE users SET is_active = CASE WHEN is_active = 1 THEN 0 ELSE 1 END WHERE id = ?", [userId]);
    return res.redirect(returnTo);
  } catch (err) { next(err); }
});

app.get("/users/toggle/:id", requireUserRoleAdminAccess, (_req, res) => {
  res.redirect(`/users-roles?error=${encodeURIComponent("Use the form action (POST) to change user status")}`);
});

app.post("/users/delete/:id", requireUserRoleAdminAccess, async (req, res, next) => {
  try {
    const returnTo = safeReturnTo(req.body.return_to || "/users-roles");
    const userId = Number.parseInt(req.params.id, 10);
    if (Number.isNaN(userId)) return res.redirect(appendQueryValue(returnTo, "error", "Invalid user id"));
    if (req.currentUser?.userId === userId) return res.redirect(appendQueryValue(returnTo, "error", "You cannot delete your own account"));

    const [[user]] = await db.query(
      `SELECT users.id, users.username, users.is_active, users.account_type, roles.name AS role_name
       FROM users
       LEFT JOIN roles ON roles.id = users.role_id
       WHERE users.id = ?
       LIMIT 1`,
      [userId]
    );
    if (!user) return res.redirect(appendQueryValue(returnTo, "error", "User not found"));
    if (user.role_name === ROLE_NAMES.ADMIN) return res.redirect(appendQueryValue(returnTo, "error", "Admin accounts cannot be deleted"));

    await db.query("DELETE FROM tasks WHERE user_id = ? AND team_id IS NULL", [userId]);
    await db.query("UPDATE tasks SET assignee_user_id = NULL WHERE assignee_user_id = ?", [userId]);
    await db.query("DELETE FROM users WHERE id = ?", [userId]);
    invalidateSessionsForUser(userId);
    return res.redirect(appendQueryValue(returnTo, "message", "User account deleted"));
  } catch (err) {
    return next(err);
  }
});

// ─── Teams ────────────────────────────────────────────────────────────────────

app.get("/teams", requireAuth, requireTeamAreaAccess, (req, res) => {
  const queryIndex = req.originalUrl.indexOf("?");
  const suffix = queryIndex >= 0 ? req.originalUrl.slice(queryIndex) : "";
  return res.redirect(`/home${suffix}`);
});

app.post("/teams/add", requireUserRoleAdminAccess, async (req, res, next) => {
  try {
    const name = (req.body.name || "").trim();
    if (!name) return res.redirect("/teams?error=Team%20name%20is%20required");
    await db.query("INSERT INTO teams (name, is_active) VALUES (?, 1)", [name]);
    return res.redirect("/teams?message=Team%20created");
  } catch (err) {
    if (err.code === "ER_DUP_ENTRY") return res.redirect("/teams?error=That%20team%20name%20already%20exists");
    return next(err);
  }
});

app.post("/teams/toggle/:id", requireUserRoleAdminAccess, async (req, res, next) => {
  try {
    const teamId = Number.parseInt(req.params.id, 10);
    if (Number.isNaN(teamId)) return res.redirect("/teams?error=Invalid%20team%20id");
    const [[team]] = await db.query("SELECT id, is_active FROM teams WHERE id = ? LIMIT 1", [teamId]);
    if (!team) return res.redirect("/teams?error=Team%20not%20found");
    await db.query("UPDATE teams SET is_active = CASE WHEN is_active = 1 THEN 0 ELSE 1 END WHERE id = ?", [teamId]);
    return res.redirect(`/teams?message=${encodeURIComponent(team.is_active ? "Team deactivated" : "Team activated")}`);
  } catch (err) {
    return next(err);
  }
});

app.post("/teams/activate/:id", requireUserRoleAdminAccess, async (req, res, next) => {
  try {
    const teamId = Number.parseInt(req.params.id, 10);
    if (Number.isNaN(teamId)) return res.redirect("/teams?error=Invalid%20team%20id");
    const [[team]] = await db.query("SELECT id, is_active FROM teams WHERE id = ? LIMIT 1", [teamId]);
    if (!team) return res.redirect("/teams?error=Team%20not%20found");
    if (team.is_active) return res.redirect("/teams?message=Team%20already%20active");
    await db.query("UPDATE teams SET is_active = 1 WHERE id = ?", [teamId]);
    return res.redirect("/teams?message=Team%20activated");
  } catch (err) {
    return next(err);
  }
});

app.post("/teams/delete/:id", requireUserRoleAdminAccess, async (req, res, next) => {
  try {
    const teamId = Number.parseInt(req.params.id, 10);
    if (Number.isNaN(teamId)) return res.redirect("/teams?error=Invalid%20team%20id");
    const [[team]] = await db.query("SELECT id, is_active, name FROM teams WHERE id = ? LIMIT 1", [teamId]);
    if (!team) return res.redirect("/teams?error=Team%20not%20found");

    await db.query("DELETE FROM tasks WHERE team_id = ?", [teamId]);
    const [usersToReview] = await db.query(
      `SELECT DISTINCT users.id, users.account_type
       FROM users
       INNER JOIN team_members ON team_members.user_id = users.id
       WHERE team_members.team_id = ?`,
      [teamId]
    );
    await db.query("DELETE FROM teams WHERE id = ?", [teamId]);
    for (const user of usersToReview) {
      if (user.account_type !== "team") continue;
      const [[remaining]] = await db.query("SELECT COUNT(*) AS count FROM team_members WHERE user_id = ?", [user.id]);
      if (Number(remaining?.count ?? 0) === 0) {
        await db.query("UPDATE users SET is_active = 0 WHERE id = ?", [user.id]);
        invalidateSessionsForUser(user.id);
      }
    }
    return res.redirect("/teams?message=Team%20deleted");
  } catch (err) {
    return next(err);
  }
});

app.get("/individual-accounts", requireUserRoleAdminAccess, (req, res) => {
  const queryIndex = req.originalUrl.indexOf("?");
  const suffix = queryIndex >= 0 ? req.originalUrl.slice(queryIndex) : "";
  return res.redirect(`/home${suffix}`);
});

app.post("/teams/users/add", requireUserRoleAdminAccess, async (req, res, next) => {
  try {
    const rawTeamName = (req.body.team_name || "").trim();
    const teamIdFromBody = Number.parseInt(req.body.team_id, 10);
    const username = (req.body.username || "").trim();
    const email = (req.body.email || "").trim();
    const roleId = Number.parseInt(req.body.role_id, 10);

    if (Number.isNaN(roleId) || !username || !email || (!rawTeamName && Number.isNaN(teamIdFromBody)))
      return res.redirect("/individual-accounts?error=Team%20name,%20username,%20email,%20and%20role%20are%20required");

    let teamId = Number.isNaN(teamIdFromBody) ? null : teamIdFromBody;
    if (teamId === null && rawTeamName) {
      const [[teamByName]] = await db.query(
        "SELECT id FROM teams WHERE LOWER(name) = LOWER(?) LIMIT 1",
        [rawTeamName]
      );
      if (!teamByName) return res.redirect("/individual-accounts?error=Team%20name%20not%20found");
      teamId = teamByName.id;
    }

    const [[team]] = await db.query("SELECT id, is_active FROM teams WHERE id = ? LIMIT 1", [teamId]);
    if (!team || !team.is_active) return res.redirect("/individual-accounts?error=Selected%20team%20is%20inactive%20or%20missing");

    const role = await findRoleById(roleId);
    if (!role || !role.is_active) return res.redirect("/individual-accounts?error=Selected%20role%20is%20inactive%20or%20missing");
    if (![ROLE_NAMES.TEAM_LEADER, ROLE_NAMES.MEMBER].includes(role.name))
      return res.redirect("/individual-accounts?error=Only%20Team%20Leader%20or%20Member%20roles%20can%20be%20assigned");

    const conn = await db.getConnection();
    try {
      await conn.beginTransaction();
      const [userResult] = await conn.query(
        "INSERT INTO users (username, email, password_hash, account_type, role_id, is_active) VALUES (?, ?, ?, 'team', ?, 1)",
        [username, email, createPasswordHash(DEFAULT_USER_PASSWORD), roleId]
      );
      await conn.query("INSERT INTO team_members (team_id, user_id, role_id) VALUES (?, ?, ?)", [teamId, userResult.insertId, roleId]);
      await conn.commit();
      res.redirect("/individual-accounts?message=User%20account%20created.%20Default%20password%20is%20123.");
    } catch (err) {
      await conn.rollback();
      if (err.code === "ER_DUP_ENTRY") return res.redirect("/individual-accounts?error=That%20email%20is%20already%20in%20use");
      throw err;
    } finally {
      conn.release();
    }
  } catch (err) { next(err); }
});

app.post("/teams/members/add", requireTeamMemberManageAccess, async (req, res, next) => {
  try {
    const teamId = Number.parseInt(req.body.team_id, 10);
    const userId = Number.parseInt(req.body.user_id, 10);
    const roleId = Number.parseInt(req.body.role_id, 10);
    const newUsername = (req.body.new_username || "").trim();
    const newEmail = (req.body.new_email || "").trim();
    const hasExistingUser = !Number.isNaN(userId);
    const isTeamLeader = req.currentUser?.roleName === ROLE_NAMES.TEAM_LEADER;

    if (Number.isNaN(teamId) || Number.isNaN(roleId)) return res.redirect("/teams?error=Please%20select%20team%20and%20role");
    if (!hasExistingUser && !newUsername) return res.redirect("/teams?error=Please%20enter%20member%20name");
    if (!isTeamLeader) return res.redirect("/teams?error=Only%20Team%20Leaders%20can%20add%20members");

    const teamIds = await findUserTeamIds(req.currentUser.userId);
    if (!teamIds.includes(teamId)) {
      return res.redirect("/teams?error=You%20can%20only%20add%20members%20to%20your%20own%20team");
    }

    const [[team]] = await db.query("SELECT id, name, is_active FROM teams WHERE id = ? LIMIT 1", [teamId]);
    if (!team || !team.is_active) return res.redirect("/teams?error=Selected%20team%20is%20inactive%20or%20missing");

    const role = await findRoleById(roleId);
    if (!role || !role.is_active) return res.redirect("/teams?error=Selected%20role%20is%20inactive%20or%20missing");
    if (![ROLE_NAMES.TEAM_LEADER, ROLE_NAMES.MEMBER].includes(role.name))
      return res.redirect("/teams?error=Only%20Team%20Leader%20or%20Member%20roles%20can%20be%20assigned%20here");
    if (role.name !== ROLE_NAMES.MEMBER)
      return res.redirect("/teams?error=Team%20Leaders%20can%20only%20add%20members");

    if (hasExistingUser) {
      const [[existingUser]] = await db.query("SELECT id, username, email, role_id, is_active, account_type FROM users WHERE id = ? LIMIT 1", [userId]);
      if (!existingUser || !existingUser.is_active) return res.redirect("/teams?error=Selected%20user%20is%20inactive%20or%20missing");
      if (existingUser.account_type !== "team") return res.redirect("/teams?error=Only%20team%20accounts%20can%20be%20added%20to%20teams");
      await db.query(
        "INSERT INTO team_members (team_id, user_id, role_id) VALUES (?, ?, ?) ON DUPLICATE KEY UPDATE role_id = VALUES(role_id)",
        [teamId, userId, roleId]
      );
      const { rawToken, tokenHash } = createTeamInviteTokenPair();
      const expiresAt = new Date(Date.now() + TEAM_INVITE_TOKEN_TTL_MS);
      await db.query("UPDATE users SET team_invite_token_hash = ?, team_invite_token_expires_at = ? WHERE id = ?", [tokenHash, expiresAt, userId]);
      const inviteLink = `${APP_BASE_URL}/team-invite/accept?token=${encodeURIComponent(rawToken)}`;
      const sent = await sendTeamInviteEmail({
        toEmail: existingUser.email,
        memberName: existingUser.username,
        inviterName: req.currentUser?.username || "Team Leader",
        teamName: team.name,
        inviteLink,
      });
      return res.redirect(sent
        ? "/teams?message=Team%20member%20saved.%20Invite%20email%20sent."
        : "/teams?message=Team%20member%20saved.%20Invite%20link%20created.");
    }

    if (newEmail) {
      const [[existingByEmail]] = await db.query(
        "SELECT id, username, email, account_type FROM users WHERE LOWER(email) = LOWER(?) LIMIT 1",
        [newEmail]
      );
      if (existingByEmail) {
        if (existingByEmail.account_type !== "team") {
          return res.redirect("/teams?error=That%20email%20belongs%20to%20a%20personal%20account");
        }
        await db.query(
          "INSERT INTO team_members (team_id, user_id, role_id) VALUES (?, ?, ?) ON DUPLICATE KEY UPDATE role_id = VALUES(role_id)",
          [teamId, existingByEmail.id, roleId]
        );
        const { rawToken, tokenHash } = createTeamInviteTokenPair();
        const expiresAt = new Date(Date.now() + TEAM_INVITE_TOKEN_TTL_MS);
        await db.query(
          "UPDATE users SET team_invite_token_hash = ?, team_invite_token_expires_at = ? WHERE id = ?",
          [tokenHash, expiresAt, existingByEmail.id]
        );
        const inviteLink = `${APP_BASE_URL}/team-invite/accept?token=${encodeURIComponent(rawToken)}`;
        const sent = await sendTeamInviteEmail({
          toEmail: existingByEmail.email,
          memberName: existingByEmail.username || newUsername,
          inviterName: req.currentUser?.username || "Team Leader",
          teamName: team.name,
          inviteLink,
        });
        return res.redirect(sent
          ? "/teams?message=Member%20already%20exists.%20Invite%20resent."
          : "/teams?message=Member%20already%20exists.%20Invite%20link%20refreshed.");
      }
    }

    const memberEmail = newEmail || buildMemberPlaceholderEmail(newUsername);
    const conn = await db.getConnection();
    try {
      await conn.beginTransaction();
      const [createResult] = await conn.query(
        "INSERT INTO users (username, email, password_hash, account_type, role_id, is_active) VALUES (?, ?, ?, 'team', ?, 0)",
        [newUsername, memberEmail, createPasswordHash(DEFAULT_USER_PASSWORD), roleId]
      );
      await conn.query("INSERT INTO team_members (team_id, user_id, role_id) VALUES (?, ?, ?)", [teamId, createResult.insertId, roleId]);
      const { tokenHash, rawToken } = createTeamInviteTokenPair();
      const expiresAt = new Date(Date.now() + TEAM_INVITE_TOKEN_TTL_MS);
      await conn.query("UPDATE users SET team_invite_token_hash = ?, team_invite_token_expires_at = ? WHERE id = ?", [tokenHash, expiresAt, createResult.insertId]);
      await conn.commit();
      const inviteLink = `${APP_BASE_URL}/team-invite/accept?token=${encodeURIComponent(rawToken)}`;
      const sent = await sendTeamInviteEmail({
        toEmail: memberEmail,
        memberName: newUsername,
        inviterName: req.currentUser?.username || "Team Leader",
        teamName: team.name,
        inviteLink,
      });
      res.redirect(sent
        ? "/teams?message=Member%20added.%20Invite%20email%20sent."
        : "/teams?message=Member%20added.%20Invite%20link%20created.");
    } catch (err) {
      await conn.rollback();
      if (err.code === "ER_DUP_ENTRY") return res.redirect("/teams?error=That%20email%20is%20already%20in%20use");
      throw err;
    } finally {
      conn.release();
    }
  } catch (err) { next(err); }
});

app.post("/teams/leader/assign", requireTeamMemberManageAccess, async (req, res, next) => {
  let conn;
  try {
    const teamId = Number.parseInt(req.body.team_id, 10);
    const replacementUserId = Number.parseInt(req.body.replacement_user_id, 10);
    const isAdminManager = can(req.currentUser?.roleName, PERMISSIONS.MANAGE_USERS_ROLES);
    const isTeamLeader = req.currentUser?.roleName === ROLE_NAMES.TEAM_LEADER;
    if (Number.isNaN(teamId) || Number.isNaN(replacementUserId)) {
      return res.redirect("/teams?error=Please%20select%20team%20and%20team%20leader%20replacement");
    }
    if (!isAdminManager && !isTeamLeader) {
      return res.redirect("/teams?error=Only%20Team%20Leaders%20or%20Admins%20can%20assign%20a%20team%20leader");
    }

    if (!isAdminManager) {
      const teamIds = await findUserTeamIds(req.currentUser.userId);
      if (!teamIds.includes(teamId)) {
        return res.redirect("/teams?error=You%20can%20only%20assign%20a%20leader%20inside%20your%20own%20team");
      }
    }

    const [[team]] = await db.query("SELECT id, name, is_active FROM teams WHERE id = ? LIMIT 1", [teamId]);
    if (!team || !team.is_active) return res.redirect("/teams?error=Selected%20team%20is%20inactive%20or%20missing");

    const [roleRows] = await db.query(
      "SELECT id, name, is_active FROM roles WHERE name IN (?, ?) AND is_active = 1",
      [ROLE_NAMES.TEAM_LEADER, ROLE_NAMES.MEMBER]
    );
    const teamLeaderRole = roleRows.find((row) => row.name === ROLE_NAMES.TEAM_LEADER) ?? null;
    const memberRole = roleRows.find((row) => row.name === ROLE_NAMES.MEMBER) ?? null;
    if (!teamLeaderRole || !memberRole) {
      return res.redirect("/teams?error=Required%20roles%20are%20missing%20or%20inactive");
    }

    const [[candidate]] = await db.query(
      `SELECT team_members.user_id, team_members.role_id, users.username, users.is_active
       FROM team_members
       INNER JOIN users ON users.id = team_members.user_id
       WHERE team_members.team_id = ? AND team_members.user_id = ?
       LIMIT 1`,
      [teamId, replacementUserId]
    );
    if (!candidate || !candidate.is_active) {
      return res.redirect("/teams?error=Selected%20member%20is%20missing%20or%20inactive");
    }
    if (candidate.role_id !== memberRole.id) {
      return res.redirect("/teams?error=Only%20members%20can%20be%20assigned%20as%20team%20leader");
    }

    conn = await db.getConnection();
    await conn.beginTransaction();

    const [currentLeaders] = await conn.query(
      "SELECT user_id FROM team_members WHERE team_id = ? AND role_id = ? AND user_id <> ?",
      [teamId, teamLeaderRole.id, replacementUserId]
    );
    const demotedLeaderUserIds = currentLeaders.map((row) => row.user_id);

    await conn.query(
      "UPDATE team_members SET role_id = ? WHERE team_id = ? AND role_id = ?",
      [memberRole.id, teamId, teamLeaderRole.id]
    );
    await conn.query(
      "UPDATE team_members SET role_id = ? WHERE team_id = ? AND user_id = ?",
      [teamLeaderRole.id, teamId, replacementUserId]
    );

    if (demotedLeaderUserIds.length) {
      const demotePlaceholders = demotedLeaderUserIds.map(() => "?").join(", ");
      const [stillLeaders] = await conn.query(
        `SELECT user_id
         FROM team_members
         WHERE user_id IN (${demotePlaceholders}) AND role_id = ?
         GROUP BY user_id`,
        [...demotedLeaderUserIds, teamLeaderRole.id]
      );
      const stillLeaderSet = new Set(stillLeaders.map((row) => row.user_id));
      const usersToDemote = demotedLeaderUserIds.filter((userId) => !stillLeaderSet.has(userId));
      if (usersToDemote.length) {
        const userPlaceholders = usersToDemote.map(() => "?").join(", ");
        await conn.query(
          `UPDATE users
           SET role_id = ?
           WHERE id IN (${userPlaceholders})`,
          [memberRole.id, ...usersToDemote]
        );
      }
    }

    await conn.query(
      "UPDATE users SET role_id = ?, is_active = 1 WHERE id = ?",
      [teamLeaderRole.id, replacementUserId]
    );
    await conn.commit();

    return res.redirect(
      `/teams?message=${encodeURIComponent(`${candidate.username || "Selected member"} is now the Team Leader for ${team.name}.`)}`
    );
  } catch (err) {
    if (conn) await conn.rollback();
    return next(err);
  } finally {
    if (conn) conn.release();
  }
});

app.post("/teams/members/remove/:id", requireTeamMemberManageAccess, async (req, res, next) => {
  try {
    const teamMemberId = Number.parseInt(req.params.id, 10);
    const returnTo = req.body?.return_to === "/individual-accounts" ? "/individual-accounts" : "/home";
    if (Number.isNaN(teamMemberId)) return res.redirect(`${returnTo}?error=Invalid%20team%20member%20id`);

    const [[member]] = await db.query(
      `SELECT team_members.id AS team_member_id, team_members.user_id, team_members.team_id,
              users.is_active AS user_is_active, users.account_type, users.username,
              roles.name AS role_name
       FROM team_members
       INNER JOIN users ON users.id = team_members.user_id
       INNER JOIN roles ON roles.id = team_members.role_id
       WHERE team_members.id = ?
       LIMIT 1`,
      [teamMemberId]
    );
    if (!member) return res.redirect(`${returnTo}?error=Team%20member%20not%20found`);
    const isAdminManager = can(req.currentUser?.roleName, PERMISSIONS.MANAGE_USERS_ROLES);
    if (!isAdminManager && member.role_name !== ROLE_NAMES.MEMBER && member.role_name !== ROLE_NAMES.TEAM_LEADER) {
      return res.redirect(`${returnTo}?error=Only%20team%20members%20or%20team%20leaders%20can%20be%20removed%20here`);
    }
    if (isAdminManager && member.role_name === ROLE_NAMES.ADMIN) {
      return res.redirect(`${returnTo}?error=Admin%20accounts%20cannot%20be%20removed%20here`);
    }
    if (member.user_id === req.currentUser?.userId) return res.redirect(`${returnTo}?error=You%20cannot%20remove%20your%20own%20account`);

    if (member.role_name === ROLE_NAMES.TEAM_LEADER && !isAdminManager) {
      return res.redirect(`${returnTo}?error=Only%20admins%20can%20remove%20team%20leaders`);
    }
    if (!isAdminManager) {
      const teamIds = await findUserTeamIds(req.currentUser.userId);
      if (!teamIds.includes(member.team_id)) {
        return res.redirect(`${returnTo}?error=You%20can%20only%20remove%20members%20from%20your%20own%20team`);
      }
    }

    await db.query("DELETE FROM team_members WHERE id = ?", [teamMemberId]);

    const [[remaining]] = await db.query("SELECT COUNT(*) AS count FROM team_members WHERE user_id = ?", [member.user_id]);
    if (Number(remaining?.count ?? 0) === 0 && member.account_type === "team") {
      if (member.user_is_active) {
        await db.query("UPDATE users SET is_active = 0 WHERE id = ?", [member.user_id]);
        invalidateSessionsForUser(member.user_id);
      } else {
        await db.query("DELETE FROM users WHERE id = ? AND is_active = 0", [member.user_id]);
      }
    }

    return res.redirect(`${returnTo}?message=Team%20member%20removed`);
  } catch (err) {
    return next(err);
  }
});

app.post("/teams/members/toggle/:id", requireTeamMemberManageAccess, async (req, res, next) => {
  try {
    const teamMemberId = Number.parseInt(req.params.id, 10);
    const returnTo = req.body?.return_to === "/individual-accounts" ? "/individual-accounts" : "/home";
    if (Number.isNaN(teamMemberId)) return res.redirect(`${returnTo}?error=Invalid%20team%20member%20id`);

    const [[member]] = await db.query(
      `SELECT team_members.id AS team_member_id, team_members.user_id, team_members.team_id,
              users.is_active AS user_is_active, roles.name AS role_name
       FROM team_members
       INNER JOIN users ON users.id = team_members.user_id
       INNER JOIN roles ON roles.id = team_members.role_id
       WHERE team_members.id = ?
       LIMIT 1`,
      [teamMemberId]
    );
    if (!member) return res.redirect(`${returnTo}?error=Team%20member%20not%20found`);

    const isAdminManager = can(req.currentUser?.roleName, PERMISSIONS.MANAGE_USERS_ROLES);
    if (!isAdminManager && member.role_name !== ROLE_NAMES.MEMBER) {
      return res.redirect(`${returnTo}?error=Only%20team%20members%20can%20be%20updated%20here`);
    }
    if (member.role_name === ROLE_NAMES.ADMIN) {
      return res.redirect(`${returnTo}?error=Admin%20accounts%20cannot%20be%20updated%20here`);
    }

    const deactivating = Boolean(member.user_is_active);
    if (deactivating && member.user_id === req.currentUser?.userId) {
      return res.redirect(`${returnTo}?error=You%20cannot%20deactivate%20your%20own%20account`);
    }

    if (!isAdminManager) {
      const teamIds = await findUserTeamIds(req.currentUser.userId);
      if (!teamIds.includes(member.team_id)) {
        return res.redirect(`${returnTo}?error=You%20can%20only%20update%20members%20from%20your%20own%20team`);
      }
    }

    await db.query("UPDATE users SET is_active = CASE WHEN is_active = 1 THEN 0 ELSE 1 END WHERE id = ?", [member.user_id]);
    if (deactivating) invalidateSessionsForUser(member.user_id);

    return res.redirect(`${returnTo}?message=${deactivating ? "Team%20member%20deactivated" : "Team%20member%20activated"}`);
  } catch (err) {
    return next(err);
  }
});

async function activateMemberAccount(req, res, next, getUserIdFn) {
  try {
    const id = Number.parseInt(req.params.id, 10);
    const returnTo = req.body?.return_to === "/individual-accounts" ? "/individual-accounts" : "/home";
    if (Number.isNaN(id)) return res.redirect(`${returnTo}?error=Invalid%20id`);

    const userId = await getUserIdFn(id);
    if (!userId) return res.redirect(`${returnTo}?error=Team%20member%20not%20found`);

    const [[user]] = await db.query("SELECT id, is_active FROM users WHERE id = ? LIMIT 1", [userId]);
    if (!user) return res.redirect(`${returnTo}?error=User%20not%20found`);
    if (user.is_active) return res.redirect(`${returnTo}?message=Member%20account%20is%20already%20active`);

    await db.query("UPDATE users SET is_active = 1 WHERE id = ?", [userId]);
    res.redirect(`${returnTo}?message=Member%20account%20activated`);
  } catch (err) { next(err); }
}

app.post("/teams/members/activate/:id", requireUserRoleAdminAccess, (req, res, next) =>
  activateMemberAccount(req, res, next, async (memberId) => {
    const [[row]] = await db.query("SELECT users.id FROM team_members INNER JOIN users ON users.id = team_members.user_id WHERE team_members.id = ? LIMIT 1", [memberId]);
    return row?.id ?? null;
  })
);

app.post("/teams/members/activate-user/:id", requireUserRoleAdminAccess, (req, res, next) =>
  activateMemberAccount(req, res, next, async (userId) => {
    const [[row]] = await db.query("SELECT users.id FROM users INNER JOIN team_members ON team_members.user_id = users.id WHERE users.id = ? LIMIT 1", [userId]);
    return row?.id ?? null;
  })
);

// ─── Account ──────────────────────────────────────────────────────────────────

app.post("/account/close", requireTaskReadAccess, async (req, res, next) => {
  try {
    const userId = req.currentUser?.userId;
    if (!userId) return res.redirect("/login");

    const targetUser = await findUserWithRole(userId);
    if (!targetUser) return res.redirect(`/home?error=${encodeURIComponent("User account not found")}`);

    const isActiveAdmin = targetUser.role_name === ROLE_NAMES.ADMIN && targetUser.is_active && targetUser.role_is_active;
    if (isActiveAdmin) {
      const count = await countActiveAdmins();
      if (count <= 1) return res.redirect(`/home?error=${encodeURIComponent("At least one active Admin must remain")}`);
    }

    await db.query("UPDATE users SET is_active = 0 WHERE id = ?", [userId]);
    invalidateSessionsForUser(userId);
    destroySession(req, res);
    res.redirect(`/login?message=${encodeURIComponent("Your account has been closed. Contact Admin if you need it reopened.")}`);
  } catch (err) { next(err); }
});

// ─── Error Handler ────────────────────────────────────────────────────────────

app.use((err, _req, res, _next) => {
  const details = err?.stack || err?.message || String(err);
  console.error("Unhandled error:", details);
  appendLogLine(SERVER_ERR_LOG_PATH, `Unhandled error: ${details}`);
  if (process.env.NODE_ENV === "production") {
    return res.status(500).send("Something went wrong. Please try again.");
  }
  return res.status(500).send(`Something went wrong. Please try again.\n\n${details}`);
});

// ─── Bootstrap ───────────────────────────────────────────────────────────────

module.exports = { app, port, initDatabase };
