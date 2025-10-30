import express from "express";
import bodyParser from "body-parser";
import { Fido2Lib } from "fido2-lib";
import path from "path";
import fs from "fs";
import { fileURLToPath } from "url";
import https from "https";

// --- Fix for __dirname in ES Modules ---
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
app.use(bodyParser.json());

// --- Log all requests ---
app.use((req, res, next) => {
  console.log(`🔥 ${req.method} ${req.url} at ${new Date().toISOString()}`);
  next();
});

// --- FIDO2 Setup ---
const fido = new Fido2Lib({
  rpId: "passkey.local",
  rpName: "My Local Passkey App",
  timeout: 60000,
  challengeSize: 64,
  attestation: "none",
});

// --- Mock “database” ---
const users = new Map();
let currentRegisterChallenge = null;
let currentLoginChallenge = null;

// --- Registration Challenge ---
app.get("/register-challenge", async (req, res) => {
  try {
    const registrationOptions = await fido.attestationOptions();
    registrationOptions.user = {
      id: Buffer.from("1234"),
      name: "testuser",
      displayName: "Test User",
    };

    currentRegisterChallenge = registrationOptions.challenge;

    registrationOptions.challenge = Buffer.from(currentRegisterChallenge).toString("base64");
    registrationOptions.user.id = Buffer.from(registrationOptions.user.id).toString("base64");

    res.json(registrationOptions);
  } catch (e) {
    console.error("❌ Error creating registration challenge:", e);
    res.status(500).json({ error: e.toString() });
  }
});

// --- Login Challenge ---
app.get("/login-challenge", async (req, res) => {
  try {
    const assertionOptions = await fido.assertionOptions();
    assertionOptions.allowCredentials = [];
    currentLoginChallenge = assertionOptions.challenge;
    assertionOptions.challenge = Buffer.from(currentLoginChallenge).toString("base64");
    res.json(assertionOptions);
  } catch (e) {
    console.error("❌ Error creating login challenge:", e);
    res.status(500).json({ error: e.toString() });
  }
});

// --- Verify Registration ---
app.post("/verify-register", async (req, res) => {
  try {
    const attRes = await fido.attestationResult(req.body, {
      challenge: currentRegisterChallenge,
      origin: process.env.APP_ORIGIN || "https://passkey.local",
      factor: "either",
    });

    users.set("testuser", attRes.authnrData);
    console.log("✅ Registration verified");
    res.json({ status: "ok" });
  } catch (e) {
    console.error("❌ Registration verification failed:", e);
    res.status(400).json({ status: "failed", error: e.toString() });
  }
});

// --- Verify Login ---
app.post("/verify-login", async (req, res) => {
  try {
    const userData = users.get("testuser");
    if (!userData) {
      return res.status(400).json({ status: "failed", error: "No registered user" });
    }

    await fido.assertionResult(req.body, {
      challenge: currentLoginChallenge,
      origin: process.env.APP_ORIGIN || "https://passkey.local",
      factor: "either",
      publicKey: userData.credentialPublicKey,
      prevCounter: userData.counter,
      userHandle: userData.userHandle,
    });

    console.log("✅ Login verified");
    res.json({ status: "ok" });
  } catch (e) {
    console.error("❌ Login failed:", e);
    res.status(400).json({ status: "failed", error: e.toString() });
  }
});

// --- Apple association file ---
app.get("/.well-known/apple-app-site-association", (req, res) => {
  res.setHeader("Content-Type", "application/json");
  res.send(`{
    "activitycontinuation": {
      "apps": ["AB33BBCCU7.passkey.local"]
    },
    "webcredentials": {
      "apps": ["AB33BBCCU7.passkey.local"]
    }
  }`);
});

// --- Root route ---
app.get("/", (req, res) => {
  console.log("🚀 Root endpoint hit");
  res.send("Hello from Passkey Server on Heroku or Local!");
});

// --- Server Setup ---
const PORT = process.env.PORT || 3000;
const isHeroku = !!process.env.DYNO;

if (isHeroku) {
  // --- Running on Heroku (HTTP only) ---
  app.listen(PORT, () => {
    console.log(`✅ Server running on Heroku (HTTP) port ${PORT}`);
  });
} else {
  // --- Running locally (HTTPS) ---
  const options = {
    key: fs.readFileSync(path.join(__dirname, "./passkey.local+1-key.pem")),
    cert: fs.readFileSync(path.join(__dirname, "./passkey.local+1.pem")),
  };

  https.createServer(options, app).listen(PORT, () => {
    console.log(`✅ Local HTTPS server running at https://passkey.local:${PORT}`);
  });
}
