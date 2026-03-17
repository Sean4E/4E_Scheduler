// ══════════════════════════════════════════════════════════════════
//  4E WORKSHOP SCHEDULER — FIREBASE CLOUD FUNCTIONS (Gen 2)
//  Zoom Server-to-Server OAuth — no user login needed.
//  Credentials via functions/.env (process.env)
// ══════════════════════════════════════════════════════════════════

const { onRequest } = require("firebase-functions/v2/https");
const admin = require("firebase-admin");

admin.initializeApp();

// Zoom credentials from .env
const ZOOM_ACCOUNT_ID    = process.env.ZOOM_ACCOUNT_ID;
const ZOOM_CLIENT_ID     = process.env.ZOOM_CLIENT_ID;
const ZOOM_CLIENT_SECRET = process.env.ZOOM_CLIENT_SECRET;

// Allowed origins
const ALLOWED_ORIGINS = [
  "https://sean4e.github.io",
  "http://localhost:5500",
  "http://127.0.0.1:5500",
];

// Token cache
let cachedToken = null;
let tokenExpiry = 0;

async function getZoomToken() {
  if (cachedToken && Date.now() < tokenExpiry - 60000) return cachedToken;

  const basicAuth = Buffer.from(`${ZOOM_CLIENT_ID}:${ZOOM_CLIENT_SECRET}`).toString("base64");
  const response = await fetch("https://zoom.us/oauth/token", {
    method: "POST",
    headers: {
      "Authorization": `Basic ${basicAuth}`,
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: new URLSearchParams({
      grant_type: "account_credentials",
      account_id: ZOOM_ACCOUNT_ID,
    }),
  });

  const data = await response.json();
  if (!response.ok) throw new Error(`Zoom token error: ${data.reason || JSON.stringify(data)}`);

  cachedToken = data.access_token;
  tokenExpiry = Date.now() + (data.expires_in * 1000);
  return cachedToken;
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

// ── zoomCheck ──
exports.checkZoom = onRequest({ region: "europe-west1" }, async (req, res) => {
  if (!handleCors(req, res)) return;
  try {
    const token = await getZoomToken();
    const userRes = await fetch("https://api.zoom.us/v2/users/me", {
      headers: { "Authorization": `Bearer ${token}` },
    });
    const userData = await userRes.json();
    if (!userRes.ok) { res.status(500).json({ connected: false, error: userData.message }); return; }
    res.json({ connected: true, email: userData.email, name: (userData.first_name || "") + " " + (userData.last_name || "") });
  } catch (err) {
    res.status(500).json({ connected: false, error: err.message });
  }
});

// ── zoomCreateMeeting ──
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
        settings: {
          waiting_room: settings?.waiting_room ?? true,
          meeting_authentication: false,
          auto_recording: settings?.auto_recording || "none",
          join_before_host: true,
          ...(settings?.passcode ? { passcode: settings.passcode } : {}),
        },
      }),
    });
    const data = await meetingRes.json();
    if (!meetingRes.ok) { res.status(meetingRes.status).json({ error: "Failed to create meeting", details: data }); return; }
    res.json({ success: true, join_url: data.join_url, meeting_id: data.id, passcode: data.password || "", start_url: data.start_url });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── zoomDeleteMeeting ──
exports.deleteMeeting = onRequest({ region: "europe-west1" }, async (req, res) => {
  if (!handleCors(req, res)) return;
  const { meeting_id } = req.body;
  if (!meeting_id || !/^\d+$/.test(String(meeting_id))) { res.status(400).json({ error: "Invalid meeting_id" }); return; }
  try {
    const token = await getZoomToken();
    const delRes = await fetch(`https://api.zoom.us/v2/meetings/${meeting_id}`, {
      method: "DELETE", headers: { "Authorization": `Bearer ${token}` },
    });
    if (delRes.status === 204 || delRes.ok) { res.json({ success: true }); }
    else { const data = await delRes.json(); res.status(delRes.status).json({ error: "Failed to delete", details: data }); }
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});
