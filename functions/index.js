// ══════════════════════════════════════════════════════════════════
//  4E WORKSHOP SCHEDULER — FIREBASE CLOUD FUNCTIONS (Gen 2)
//  - PIN verification (server-side, never exposes hash to client)
//  - Zoom Server-to-Server OAuth
//  Credentials via functions/.env (process.env)
// ══════════════════════════════════════════════════════════════════

const { onRequest } = require("firebase-functions/v2/https");
const admin = require("firebase-admin");
const crypto = require("crypto");

admin.initializeApp();
const db = admin.firestore();

// Zoom credentials from .env
const ZOOM_ACCOUNT_ID    = process.env.ZOOM_ACCOUNT_ID;
const ZOOM_CLIENT_ID     = process.env.ZOOM_CLIENT_ID;
const ZOOM_CLIENT_SECRET = process.env.ZOOM_CLIENT_SECRET;

const ALLOWED_ORIGINS = [
  "https://sean4e.github.io",
  "http://localhost:5500",
  "http://127.0.0.1:5500",
];

// ── Helpers ──
let cachedToken = null;
let tokenExpiry = 0;

function sha256(str) {
  return crypto.createHash("sha256").update(str).digest("hex");
}

function handleCors(req, res) {
  const origin = req.headers.origin || "";
  const allowed = ALLOWED_ORIGINS.some(o => origin === o || origin.startsWith(o + "/"));
  res.set("Access-Control-Allow-Origin", allowed ? origin : ALLOWED_ORIGINS[0]);
  res.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  res.set("Access-Control-Allow-Headers", "Content-Type");
  res.set("Access-Control-Max-Age", "3600");
  if (req.method === "OPTIONS") { res.status(204).send(""); return false; }
  return true;
}

// Rate limiting: track failed attempts per IP
const attempts = new Map(); // ip -> { count, lockedUntil }
function checkRateLimit(ip) {
  const record = attempts.get(ip);
  if (!record) return true;
  if (record.lockedUntil && Date.now() < record.lockedUntil) return false;
  if (record.lockedUntil && Date.now() >= record.lockedUntil) { attempts.delete(ip); return true; }
  return true;
}
function recordFailedAttempt(ip) {
  const record = attempts.get(ip) || { count: 0 };
  record.count++;
  if (record.count >= 5) { record.lockedUntil = Date.now() + 5 * 60 * 1000; } // 5 min lockout
  attempts.set(ip, record);
}
function clearAttempts(ip) { attempts.delete(ip); }

// ══════════════════════════════════════════════════════
//  PIN VERIFICATION — server-side, hash never sent to client
// ══════════════════════════════════════════════════════

// Verify admin PIN — returns a session token if correct
exports.verifyAdminPin = onRequest({ region: "europe-west1" }, async (req, res) => {
  if (!handleCors(req, res)) return;
  const { pin } = req.body;
  const ip = req.ip || req.headers["x-forwarded-for"] || "unknown";

  if (!checkRateLimit(ip)) {
    res.status(429).json({ error: "Too many attempts. Locked for 5 minutes." });
    return;
  }

  if (!pin || pin.length !== 4) { res.status(400).json({ error: "Invalid PIN" }); return; }

  try {
    const doc = await db.collection("config").doc("admin").get();
    if (!doc.exists || !doc.data().pinHash) {
      // First time — create the PIN
      const hash = sha256(pin);
      await db.collection("config").doc("admin").set({ pinHash: hash });
      // Generate session token
      const token = crypto.randomBytes(32).toString("hex");
      await db.collection("sessions").doc(token).set({ role: "admin", createdAt: admin.firestore.FieldValue.serverTimestamp(), expiresAt: Date.now() + 2 * 60 * 60 * 1000 });
      clearAttempts(ip);
      res.json({ success: true, token, isNew: true });
      return;
    }

    const hash = sha256(pin);
    if (hash === doc.data().pinHash) {
      const token = crypto.randomBytes(32).toString("hex");
      await db.collection("sessions").doc(token).set({ role: "admin", createdAt: admin.firestore.FieldValue.serverTimestamp(), expiresAt: Date.now() + 2 * 60 * 60 * 1000 });
      clearAttempts(ip);
      res.json({ success: true, token });
    } else {
      recordFailedAttempt(ip);
      const record = attempts.get(ip);
      const remaining = 5 - (record?.count || 0);
      res.status(401).json({ error: "Incorrect PIN", remaining: Math.max(0, remaining) });
    }
  } catch (err) {
    res.status(500).json({ error: "Server error" });
  }
});

// Verify supervisor PIN — checks all groups, returns group info + token
exports.verifySupervisorPin = onRequest({ region: "europe-west1" }, async (req, res) => {
  if (!handleCors(req, res)) return;
  const { pin } = req.body;
  const ip = req.ip || req.headers["x-forwarded-for"] || "unknown";

  if (!checkRateLimit(ip)) {
    res.status(429).json({ error: "Too many attempts. Locked for 5 minutes." });
    return;
  }

  if (!pin || pin.length !== 4) { res.status(400).json({ error: "Invalid PIN" }); return; }

  try {
    const hash = sha256(pin);
    const snap = await db.collection("groups").get();
    const match = snap.docs.find(d => d.data().supervisorPinHash === hash);

    if (match) {
      const token = crypto.randomBytes(32).toString("hex");
      await db.collection("sessions").doc(token).set({ role: "supervisor", groupId: match.id, createdAt: admin.firestore.FieldValue.serverTimestamp(), expiresAt: Date.now() + 2 * 60 * 60 * 1000 });
      clearAttempts(ip);
      res.json({ success: true, token, groupId: match.id, groupName: match.data().name });
    } else {
      recordFailedAttempt(ip);
      const record = attempts.get(ip);
      const remaining = 5 - (record?.count || 0);
      res.status(401).json({ error: "PIN not recognised", remaining: Math.max(0, remaining) });
    }
  } catch (err) {
    res.status(500).json({ error: "Server error" });
  }
});

// Change admin PIN (requires valid session token)
exports.changeAdminPin = onRequest({ region: "europe-west1" }, async (req, res) => {
  if (!handleCors(req, res)) return;
  const { token, newPin } = req.body;
  if (!token || !newPin || newPin.length !== 4) { res.status(400).json({ error: "Invalid request" }); return; }

  try {
    const sess = await db.collection("sessions").doc(token).get();
    if (!sess.exists || sess.data().role !== "admin" || Date.now() > sess.data().expiresAt) {
      res.status(401).json({ error: "Invalid or expired session" }); return;
    }
    const hash = sha256(newPin);
    await db.collection("config").doc("admin").set({ pinHash: hash });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: "Server error" });
  }
});

// ══════════════════════════════════════════════════════
//  ZOOM FUNCTIONS
// ══════════════════════════════════════════════════════
async function getZoomToken() {
  if (cachedToken && Date.now() < tokenExpiry - 60000) return cachedToken;
  const basicAuth = Buffer.from(`${ZOOM_CLIENT_ID}:${ZOOM_CLIENT_SECRET}`).toString("base64");
  const response = await fetch("https://zoom.us/oauth/token", {
    method: "POST",
    headers: { "Authorization": `Basic ${basicAuth}`, "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ grant_type: "account_credentials", account_id: ZOOM_ACCOUNT_ID }),
  });
  const data = await response.json();
  if (!response.ok) throw new Error(`Zoom token error: ${data.reason || JSON.stringify(data)}`);
  cachedToken = data.access_token;
  tokenExpiry = Date.now() + (data.expires_in * 1000);
  return cachedToken;
}

exports.checkZoom = onRequest({ region: "europe-west1" }, async (req, res) => {
  if (!handleCors(req, res)) return;
  try {
    const token = await getZoomToken();
    const userRes = await fetch("https://api.zoom.us/v2/users/me", { headers: { "Authorization": `Bearer ${token}` } });
    const userData = await userRes.json();
    if (!userRes.ok) { res.status(500).json({ connected: false, error: userData.message }); return; }
    res.json({ connected: true, email: userData.email, name: (userData.first_name || "") + " " + (userData.last_name || "") });
  } catch (err) { res.status(500).json({ connected: false, error: err.message }); }
});

exports.createMeeting = onRequest({ region: "europe-west1" }, async (req, res) => {
  if (!handleCors(req, res)) return;
  const { topic, start_time, duration, settings } = req.body;
  if (!topic || !start_time) { res.status(400).json({ error: "Missing topic or start_time" }); return; }
  try {
    const token = await getZoomToken();
    const meetingRes = await fetch("https://api.zoom.us/v2/users/me/meetings", {
      method: "POST",
      headers: { "Authorization": `Bearer ${token}`, "Content-Type": "application/json" },
      body: JSON.stringify({
        topic, type: 2, start_time, duration: duration || 30, timezone: "Europe/Dublin",
        settings: { waiting_room: settings?.waiting_room ?? true, meeting_authentication: false, auto_recording: settings?.auto_recording || "none", join_before_host: true, ...(settings?.passcode ? { passcode: settings.passcode } : {}) },
      }),
    });
    const data = await meetingRes.json();
    if (!meetingRes.ok) { res.status(meetingRes.status).json({ error: "Failed to create meeting", details: data }); return; }
    res.json({ success: true, join_url: data.join_url, meeting_id: data.id, passcode: data.password || "", start_url: data.start_url });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

exports.deleteMeeting = onRequest({ region: "europe-west1" }, async (req, res) => {
  if (!handleCors(req, res)) return;
  const { meeting_id } = req.body;
  if (!meeting_id || !/^\d+$/.test(String(meeting_id))) { res.status(400).json({ error: "Invalid meeting_id" }); return; }
  try {
    const token = await getZoomToken();
    const delRes = await fetch(`https://api.zoom.us/v2/meetings/${meeting_id}`, { method: "DELETE", headers: { "Authorization": `Bearer ${token}` } });
    if (delRes.status === 204 || delRes.ok) { res.json({ success: true }); }
    else { const data = await delRes.json(); res.status(delRes.status).json({ error: "Failed to delete", details: data }); }
  } catch (err) { res.status(500).json({ error: err.message }); }
});
