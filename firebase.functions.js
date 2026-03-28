"use strict";

const { onRequest } = require("firebase-functions/v2/https");
const { app, initDatabase } = require("./index");

let dbInitPromise = null;

function ensureDatabaseInitialized() {
  if (!dbInitPromise) {
    dbInitPromise = initDatabase();
  }
  return dbInitPromise;
}

exports.app = onRequest({ region: "us-central1" }, async (req, res) => {
  try {
    await ensureDatabaseInitialized();
  } catch (error) {
    console.error("Database initialization failed:", error);
    return res.status(500).send("Server is starting up. Please try again shortly.");
  }

  return app(req, res);
});
