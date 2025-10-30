import express from "express";
import https from "https";
import fs from "fs";
import bodyParser from "body-parser";
import { Fido2Lib } from "fido2-lib";
import bonjour from "bonjour";
import path from "path";
import { fileURLToPath } from "url";

// --- Fix for __dirname in ES Modules ---
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// --- Bonjour setup (advertises your server to the network) ---
const bonjourService = bonjour();
const app = express();
app.use(bodyParser.json());

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
      origin: "https://passkey.local",
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
      origin: "https://passkey.local",
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

app.get("/.well-known/apple-app-site-association", (req, res) => {
  res.setHeader("Content-Type", "application/json");
  res.send(`{
  "activitycontinuation": {
        "apps": [
            "AB33BBCCU7.passkey.local"
        ]
    },
  "webcredentials": {
    "apps": ["AB33BBCCU7.passkey.local"]
  }
}
`);  // Hardcode the JSON for testing
});

// --- HTTPS Setup ---
const options = {
  key: fs.readFileSync("./passkey.local+1-key.pem"),
  cert: fs.readFileSync("./passkey.local+1.pem"),
};

// --- Start Server ---
https.createServer(options, app).listen(443, "0.0.0.0", () => {
  console.log("✅ Server running at https://passkey.local");
});

// --- Bonjour Service ---
bonjourService.publish({ name: 'Passkey Server', type: 'https', port: 443, host: 'passkey.local' });
console.log("✅ Bonjour service published");
