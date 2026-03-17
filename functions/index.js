// ══════════════════════════════════════════════════════════════════
//  4E WORKSHOP SCHEDULER — FIREBASE CLOUD FUNCTIONS
//  Zoom OAuth token exchange, refresh, and meeting creation.
//  The Zoom Client Secret is stored here (server-side only).
// ══════════════════════════════════════════════════════════════════

const functions = require("firebase-functions");
const admin = require("firebase-admin");
const fetch = require("node-fetch");

admin.initializeApp();
const db = admin.firestore();

// Zoom credentials — Client Secret is safe here (never sent to client)
const ZOOM_ACCOUNT_ID    = "wDoYqXjNQ5upGx6If9EQsw";
const ZOOM_CLIENT_ID     = "9fw0xTu0StKj2OPZpP6fVQ";
const ZOOM_CLIENT_SECRET = "Nog9ZuKLVHQ29gm4cN7B0XYrLlsnU6PQ";

// ──────────────────────────────────────────────────────
//  zoomOAuth — Exchange authorization code for tokens
// ──────────────────────────────────────────────────────
exports.zoomOAuth = functions.https.onRequest(async (req, res) => {
  res.set("Access-Control-Allow-Origin", "*");
  res.set("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.set("Access-Control-Allow-Headers", "Content-Type");
  if (req.method === "OPTIONS") { res.status(204).send(""); return; }

  const { code, redirect_uri } = req.body;
  if (!code || !redirect_uri) {
    res.status(400).json({ error: "Missing code or redirect_uri" });
    return;
  }

  try {
    const basicAuth = Buffer.from(`${ZOOM_CLIENT_ID}:${ZOOM_CLIENT_SECRET}`).toString("base64");
    const response = await fetch("https://zoom.us/oauth/token", {
      method: "POST",
      headers: {
        "Authorization": `Basic ${basicAuth}`,
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code,
        redirect_uri,
      }),
    });

    const data = await response.json();
    if (!response.ok) {
      res.status(response.status).json({ error: data.reason || "Token exchange failed", details: data });
      return;
    }

    // Store tokens in Firestore (base64-encode for minimal obfuscation)
    await db.collection("config").doc("zoom").set({
      access_token:  Buffer.from(data.access_token).toString("base64"),
      refresh_token: Buffer.from(data.refresh_token).toString("base64"),
      expires_at:    Date.now() + (data.expires_in * 1000),
      scope:         data.scope || "",
      connected:     true,
      connectedAt:   admin.firestore.FieldValue.serverTimestamp(),
    });

    res.json({ success: true });
  } catch (err) {
    console.error("zoomOAuth error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// ──────────────────────────────────────────────────────
//  zoomRefresh — Refresh the access token
// ──────────────────────────────────────────────────────
exports.zoomRefresh = functions.https.onRequest(async (req, res) => {
  res.set("Access-Control-Allow-Origin", "*");
  res.set("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.set("Access-Control-Allow-Headers", "Content-Type");
  if (req.method === "OPTIONS") { res.status(204).send(""); return; }

  try {
    const doc = await db.collection("config").doc("zoom").get();
    if (!doc.exists || !doc.data().refresh_token) {
      res.status(400).json({ error: "Zoom not connected — no refresh token found" });
      return;
    }

    const refreshToken = Buffer.from(doc.data().refresh_token, "base64").toString("utf-8");
    const basicAuth = Buffer.from(`${ZOOM_CLIENT_ID}:${ZOOM_CLIENT_SECRET}`).toString("base64");

    const response = await fetch("https://zoom.us/oauth/token", {
      method: "POST",
      headers: {
        "Authorization": `Basic ${basicAuth}`,
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: new URLSearchParams({
        grant_type: "refresh_token",
        refresh_token: refreshToken,
      }),
    });

    const data = await response.json();
    if (!response.ok) {
      res.status(response.status).json({ error: data.reason || "Token refresh failed", details: data });
      return;
    }

    await db.collection("config").doc("zoom").update({
      access_token:  Buffer.from(data.access_token).toString("base64"),
      refresh_token: Buffer.from(data.refresh_token).toString("base64"),
      expires_at:    Date.now() + (data.expires_in * 1000),
    });

    res.json({ success: true, access_token: data.access_token });
  } catch (err) {
    console.error("zoomRefresh error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// ──────────────────────────────────────────────────────
//  zoomCreateMeeting — Create a Zoom meeting
// ──────────────────────────────────────────────────────
exports.zoomCreateMeeting = functions.https.onRequest(async (req, res) => {
  res.set("Access-Control-Allow-Origin", "*");
  res.set("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.set("Access-Control-Allow-Headers", "Content-Type");
  if (req.method === "OPTIONS") { res.status(204).send(""); return; }

  const { topic, start_time, duration, settings } = req.body;
  if (!topic || !start_time) {
    res.status(400).json({ error: "Missing topic or start_time" });
    return;
  }

  try {
    // Get stored access token
    const doc = await db.collection("config").doc("zoom").get();
    if (!doc.exists || !doc.data().access_token) {
      res.status(400).json({ error: "Zoom not connected" });
      return;
    }

    let accessToken = Buffer.from(doc.data().access_token, "base64").toString("utf-8");

    // If token is expired, refresh it first
    if (doc.data().expires_at && Date.now() >= doc.data().expires_at) {
      const refreshToken = Buffer.from(doc.data().refresh_token, "base64").toString("utf-8");
      const basicAuth = Buffer.from(`${ZOOM_CLIENT_ID}:${ZOOM_CLIENT_SECRET}`).toString("base64");
      const refreshRes = await fetch("https://zoom.us/oauth/token", {
        method: "POST",
        headers: {
          "Authorization": `Basic ${basicAuth}`,
          "Content-Type": "application/x-www-form-urlencoded",
        },
        body: new URLSearchParams({
          grant_type: "refresh_token",
          refresh_token: refreshToken,
        }),
      });
      const refreshData = await refreshRes.json();
      if (!refreshRes.ok) {
        res.status(500).json({ error: "Failed to refresh Zoom token", details: refreshData });
        return;
      }
      accessToken = refreshData.access_token;
      await db.collection("config").doc("zoom").update({
        access_token:  Buffer.from(refreshData.access_token).toString("base64"),
        refresh_token: Buffer.from(refreshData.refresh_token).toString("base64"),
        expires_at:    Date.now() + (refreshData.expires_in * 1000),
      });
    }

    // Create the meeting
    const meetingSettings = {
      waiting_room:     settings?.waiting_room ?? true,
      meeting_authentication: false,
      auto_recording:   settings?.auto_recording || "none",
      join_before_host: false,
    };
    if (settings?.passcode) {
      meetingSettings.passcode = settings.passcode;
    }

    const meetingRes = await fetch("https://api.zoom.us/v2/users/me/meetings", {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${accessToken}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        topic:      topic,
        type:       2, // scheduled meeting
        start_time: start_time,
        duration:   duration || 30,
        timezone:   "Europe/Dublin",
        settings:   meetingSettings,
      }),
    });

    const meetingData = await meetingRes.json();
    if (!meetingRes.ok) {
      res.status(meetingRes.status).json({ error: "Failed to create Zoom meeting", details: meetingData });
      return;
    }

    res.json({
      success:    true,
      join_url:   meetingData.join_url,
      meeting_id: meetingData.id,
      passcode:   meetingData.password || "",
      start_url:  meetingData.start_url,
    });
  } catch (err) {
    console.error("zoomCreateMeeting error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});
