const fs = require("fs");
const path = require("path");

function loadDotEnv() {
  const envPath = path.join(__dirname, ".env");
  if (!fs.existsSync(envPath)) return;
  const raw = fs.readFileSync(envPath, "utf8");
  for (const line of raw.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    const eqIndex = trimmed.indexOf("=");
    if (eqIndex <= 0) continue;
    const key = trimmed.slice(0, eqIndex).trim();
    if (!key) continue;
    let value = trimmed.slice(eqIndex + 1).trim();
    if ((value.startsWith("\"") && value.endsWith("\"")) || (value.startsWith("'") && value.endsWith("'"))) {
      value = value.slice(1, -1);
    }
    // Local project .env should win over inherited shell/system env vars.
    process.env[key] = value;
  }
}

loadDotEnv();

const { app, port, initDatabase } = require("./index");
const host = process.env.HOST || "0.0.0.0";
const dbRetryDelayMs = Number.parseInt(process.env.DB_INIT_RETRY_MS || "5000", 10);

async function initializeDatabaseWithRetry() {
  for (;;) {
    try {
      await initDatabase();
      console.log("Database initialization completed");
      return;
    } catch (err) {
      console.error("Failed to initialize database, retrying...", err);
      await new Promise((resolve) => setTimeout(resolve, dbRetryDelayMs));
    }
  }
}

app.listen(port, host, () => {
  console.log(`Server listening on ${host}:${port}`);
  initializeDatabaseWithRetry().catch((err) => {
    console.error("Unexpected database initialization error:", err);
  });
});
