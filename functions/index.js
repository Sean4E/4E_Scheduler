// ══════════════════════════════════════════════════════════════════
//  4E WORKSHOP SCHEDULER — FIREBASE CLOUD FUNCTIONS
//  Zoom Server-to-Server OAuth — no user login needed.
//  Credentials are stored here (server-side only).
// ══════════════════════════════════════════════════════════════════

const functions = require("firebase-functions");
const admin = require("firebase-admin");
const fetch = require("node-fetch");

admin.initializeApp();
const db = admin.firestore();

// Zoom Server-to-Server credentials (safe here, never sent to client)
const ZOOM_ACCOUNT_ID    = "wDoYqXjNQ5upGx6If9EQsw";
const ZOOM_CLIENT_ID     = "9fw0xTu0StKj2OPZpP6fVQ";
const ZOOM_CLIENT_SECRET = "Nog9ZuKLVHQ29gm4cN7B0XYrLlsnU6PQ";

// Cache token in memory to avoid re-fetching on every call
let cachedToken = null;
let tokenExpiry = 0;

// ──────────────────────────────────────────────────────
//  getZoomToken — Server-to-Server OAuth (account_credentials)
//  No user login, no redirect. Just works.
// ──────────────────────────────────────────────────────
async function getZoomToken() {
  // Return cached token if still valid (with 60s buffer)
  if (cachedToken && Date.now() < tokenExpiry - 60000) {
    return cachedToken;
  }

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
  if (!response.ok) {
    throw new Error(`Zoom token error: ${data.reason || JSON.stringify(data)}`);
  }

  cachedToken = data.access_token;
  tokenExpiry = Date.now() + (data.expires_in * 1000);
  return cachedToken;
}

// CORS helper
function setCors(res) {
  res.set("Access-Control-Allow-Origin", "*");
  res.set("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.set("Access-Control-Allow-Headers", "Content-Type");
}

// ──────────────────────────────────────────────────────
//  zoomStatus — Check if Zoom is reachable
// ──────────────────────────────────────────────────────
exports.zoomStatus = functions.https.onRequest(async (req, res) => {
  setCors(res);
  if (req.method === "OPTIONS") { res.status(204).send(""); return; }

  try {
    const token = await getZoomToken();
    // Fetch current user info to confirm connection
    const userRes = await fetch("https://api.zoom.us/v2/users/me", {
      headers: { "Authorization": `Bearer ${token}` },
    });
    const userData = await userRes.json();
    if (!userRes.ok) {
      res.status(500).json({ connected: false, error: userData.message });
      return;
    }
    res.json({
      connected: true,
      email: userData.email,
      name: userData.first_name + " " + userData.last_name,
      account_id: ZOOM_ACCOUNT_ID,
    });
  } catch (err) {
    console.error("zoomStatus error:", err);
    res.status(500).json({ connected: false, error: err.message });
  }
});

// ──────────────────────────────────────────────────────
//  zoomCreateMeeting — Create a scheduled Zoom meeting
// ──────────────────────────────────────────────────────
exports.zoomCreateMeeting = functions.https.onRequest(async (req, res) => {
  setCors(res);
  if (req.method === "OPTIONS") { res.status(204).send(""); return; }

  const { topic, start_time, duration, settings } = req.body;
  if (!topic || !start_time) {
    res.status(400).json({ error: "Missing topic or start_time" });
    return;
  }

  try {
    const token = await getZoomToken();

    const meetingSettings = {
      waiting_room:     settings?.waiting_room ?? true,
      meeting_authentication: false,
      auto_recording:   settings?.auto_recording || "none",
      join_before_host: true,
    };
    if (settings?.passcode) {
      meetingSettings.passcode = settings.passcode;
    }

    const meetingRes = await fetch("https://api.zoom.us/v2/users/me/meetings", {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${token}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        topic,
        type:       2,
        start_time,
        duration:   duration || 30,
        timezone:   "Europe/Dublin",
        settings:   meetingSettings,
      }),
    });

    const data = await meetingRes.json();
    if (!meetingRes.ok) {
      res.status(meetingRes.status).json({ error: "Failed to create meeting", details: data });
      return;
    }

    res.json({
      success:    true,
      join_url:   data.join_url,
      meeting_id: data.id,
      passcode:   data.password || "",
      start_url:  data.start_url,
    });
  } catch (err) {
    console.error("zoomCreateMeeting error:", err);
    res.status(500).json({ error: err.message });
  }
});

// ──────────────────────────────────────────────────────
//  zoomDeleteMeeting — Delete/cancel a Zoom meeting
// ──────────────────────────────────────────────────────
exports.zoomDeleteMeeting = functions.https.onRequest(async (req, res) => {
  setCors(res);
  if (req.method === "OPTIONS") { res.status(204).send(""); return; }

  const { meeting_id } = req.body;
  if (!meeting_id) {
    res.status(400).json({ error: "Missing meeting_id" });
    return;
  }

  try {
    const token = await getZoomToken();
    const delRes = await fetch(`https://api.zoom.us/v2/meetings/${meeting_id}`, {
      method: "DELETE",
      headers: { "Authorization": `Bearer ${token}` },
    });

    if (delRes.status === 204 || delRes.ok) {
      res.json({ success: true });
    } else {
      const data = await delRes.json();
      res.status(delRes.status).json({ error: "Failed to delete meeting", details: data });
    }
  } catch (err) {
    console.error("zoomDeleteMeeting error:", err);
    res.status(500).json({ error: err.message });
  }
});
