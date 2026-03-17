// ══════════════════════════════════════════════════════════════════
//  4E WORKSHOP SCHEDULER — FIREBASE CLOUD FUNCTIONS (Gen 2)
//
//  Server-side automation:
//  - PIN verification (never exposes hash to client)
//  - Google Calendar via Service Account (always-on, no user sign-in)
//  - Zoom via Server-to-Server OAuth (always-on)
//  - Firestore trigger: auto-creates events when slots are booked
//
//  Credentials: functions/.env + functions/service-account-key.json
// ══════════════════════════════════════════════════════════════════

const { onRequest } = require("firebase-functions/v2/https");
const { onDocumentWritten } = require("firebase-functions/v2/firestore");
const admin = require("firebase-admin");
const crypto = require("crypto");
const { google } = require("googleapis");
const path = require("path");

admin.initializeApp();
const db = admin.firestore();

// ── Config from .env ──
const ZOOM_ACCOUNT_ID    = process.env.ZOOM_ACCOUNT_ID;
const ZOOM_CLIENT_ID     = process.env.ZOOM_CLIENT_ID;
const ZOOM_CLIENT_SECRET = process.env.ZOOM_CLIENT_SECRET;
const GOOGLE_CALENDAR_ID = process.env.GOOGLE_CALENDAR_ID || "primary";
const EMAILJS_PRIVATE_KEY = process.env.EMAILJS_PRIVATE_KEY;

const ALLOWED_ORIGINS = [
  "https://sean4e.github.io",
  "http://localhost:5500",
  "http://127.0.0.1:5500",
];

const REGION = "europe-west1";

// ══════════════════════════════════════════════════════
//  HELPERS
// ══════════════════════════════════════════════════════
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

// Rate limiting
const attempts = new Map();
function checkRateLimit(ip) {
  const r = attempts.get(ip);
  if (!r) return true;
  if (r.lockedUntil && Date.now() < r.lockedUntil) return false;
  if (r.lockedUntil) { attempts.delete(ip); return true; }
  return true;
}
function recordFail(ip) {
  const r = attempts.get(ip) || { count: 0 };
  r.count++;
  if (r.count >= 5) r.lockedUntil = Date.now() + 5 * 60 * 1000;
  attempts.set(ip, r);
}
function clearFails(ip) { attempts.delete(ip); }

// ══════════════════════════════════════════════════════
//  GOOGLE CALENDAR — Service Account (always-on)
// ══════════════════════════════════════════════════════
let calendarClient = null;

function getCalendar() {
  if (calendarClient) return calendarClient;
  const keyPath = path.join(__dirname, "service-account-key.json");
  const auth = new google.auth.GoogleAuth({
    keyFile: keyPath,
    scopes: ["https://www.googleapis.com/auth/calendar"],
  });
  calendarClient = google.calendar({ version: "v3", auth });
  return calendarClient;
}

async function createCalendarEvent({ title, description, startTime, endTime, attendeeEmail, location, reminderMinutes, colorId, visibility, showAs }) {
  try {
    const calendar = getCalendar();
    const event = {
      summary: title,
      description: (description || "") + (attendeeEmail ? "\n\nParticipant: " + attendeeEmail : ""),
      start: { dateTime: startTime, timeZone: "Europe/Dublin" },
      end: { dateTime: endTime, timeZone: "Europe/Dublin" },
      reminders: { useDefault: false, overrides: [{ method: "popup", minutes: reminderMinutes || 30 }] },
    };
    // Note: Service accounts on personal Gmail can't add attendees (requires Workspace)
    // The event is created on admin's calendar. Participant gets notified via EmailJS or .ics download.
    if (location) event.location = location;
    // Apply optional calendar settings
    if (colorId) event.colorId = String(colorId);
    if (visibility && visibility !== "default") event.visibility = visibility;
    if (showAs) event.transparency = showAs === "free" ? "transparent" : "opaque";

    const res = await calendar.events.insert({
      calendarId: GOOGLE_CALENDAR_ID,
      resource: event,
      sendUpdates: "none",
    });
    return { eventId: res.data.id, htmlLink: res.data.htmlLink };
  } catch (err) {
    console.error("Calendar create error:", err.message);
    return null;
  }
}

async function deleteCalendarEvent(eventId) {
  try {
    const calendar = getCalendar();
    await calendar.events.delete({ calendarId: GOOGLE_CALENDAR_ID, eventId, sendUpdates: "all" });
    return true;
  } catch (err) {
    console.error("Calendar delete error:", err.message);
    return false;
  }
}

// ══════════════════════════════════════════════════════
//  ZOOM — Server-to-Server OAuth (always-on)
// ══════════════════════════════════════════════════════
let zoomToken = null;
let zoomExpiry = 0;

async function getZoomToken() {
  if (zoomToken && Date.now() < zoomExpiry - 60000) return zoomToken;
  const basicAuth = Buffer.from(`${ZOOM_CLIENT_ID}:${ZOOM_CLIENT_SECRET}`).toString("base64");
  const response = await fetch("https://zoom.us/oauth/token", {
    method: "POST",
    headers: { "Authorization": `Basic ${basicAuth}`, "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ grant_type: "account_credentials", account_id: ZOOM_ACCOUNT_ID }),
  });
  const data = await response.json();
  if (!response.ok) throw new Error(`Zoom token error: ${data.reason || JSON.stringify(data)}`);
  zoomToken = data.access_token;
  zoomExpiry = Date.now() + (data.expires_in * 1000);
  return zoomToken;
}

async function createZoomMeetingServer({ topic, startTime, duration, waitingRoom, passcode, autoRecord, muteOnEntry, joinBeforeHost }) {
  try {
    const token = await getZoomToken();
    const settings = {
      waiting_room: waitingRoom ?? true,
      meeting_authentication: false,
      auto_recording: autoRecord ? "cloud" : "none",
      join_before_host: joinBeforeHost ?? true,
      mute_upon_entry: muteOnEntry ?? false,
    };
    if (passcode) settings.passcode = crypto.randomBytes(3).toString("hex");

    const res = await fetch("https://api.zoom.us/v2/users/me/meetings", {
      method: "POST",
      headers: { "Authorization": `Bearer ${token}`, "Content-Type": "application/json" },
      body: JSON.stringify({ topic, type: 2, start_time: startTime, duration: duration || 30, timezone: "Europe/Dublin", settings }),
    });
    const data = await res.json();
    if (!res.ok) { console.error("Zoom create error:", data); return null; }
    return { joinUrl: data.join_url, meetingId: data.id, passcode: data.password || "", startUrl: data.start_url };
  } catch (err) {
    console.error("Zoom create error:", err.message);
    return null;
  }
}

// ══════════════════════════════════════════════════════
//  FIRESTORE TRIGGER — Auto-create events on booking
// ══════════════════════════════════════════════════════
exports.onBookingChange = onDocumentWritten(
  { document: "participants/{participantId}", region: REGION },
  async (event) => {
    const before = event.data?.before?.data();
    const after = event.data?.after?.data();
    if (!after) return; // document deleted

    const beforeSlots = (before?.bookedSlots || []).map(e => typeof e === "string" ? e : e.slotId);
    const afterSlots = (after.bookedSlots || []).map(e => typeof e === "string" ? e : e.slotId);

    // Find newly booked slots
    const newBookings = afterSlots.filter(s => !beforeSlots.includes(s));
    // Find cancelled slots
    const cancelled = beforeSlots.filter(s => !afterSlots.includes(s));

    if (!newBookings.length && !cancelled.length) return;

    // Load integration config
    const configDoc = await db.collection("config").doc("integrations").get();
    const config = configDoc.exists ? configDoc.data() : {};
    const calEnabled = config.calProvider === "google" && config.gcal?.autoCreate;
    const zoomEnabled = config.meetProvider === "zoom";

    // Load zoom settings
    const zoomDoc = await db.collection("config").doc("zoom").get();
    const zoomConfig = zoomDoc.exists ? zoomDoc.data() : {};

    const participantId = event.params.participantId;

    // Handle new bookings
    for (const slotId of newBookings) {
      const slotDoc = await db.collection("slots").doc(slotId).get();
      if (!slotDoc.exists) continue;
      const slot = { id: slotId, ...slotDoc.data() };

      // Get group for meeting link fallback
      const groupDoc = slot.groupId && slot.groupId !== "all" ? await db.collection("groups").doc(slot.groupId).get() : null;
      const group = groupDoc?.exists ? groupDoc.data() : null;
      const meetLink = slot.meetingLink || group?.meetingLink || "";

      // Calculate times
      const [h, m] = slot.time.split(":").map(Number);
      const dur = slot.duration || 30;
      const start = new Date(slot.date + "T" + String(h).padStart(2, "0") + ":" + String(m).padStart(2, "0") + ":00");
      const end = new Date(start.getTime() + dur * 60000);

      // Create Zoom meeting if enabled and no existing link
      let finalMeetLink = meetLink;
      const zoomSettings = config.zoom || {};
      if (zoomEnabled && !finalMeetLink && zoomConfig.connected) {
        const meetMode = group?.meetMode || "individual";
        if (meetMode === "individual") {
          const zoom = await createZoomMeetingServer({
            topic: "4E Workshop — " + after.name,
            startTime: start.toISOString(),
            duration: dur,
            waitingRoom: zoomSettings.waitingRoom ?? zoomConfig.waitingRoom ?? true,
            passcode: zoomSettings.passcode ?? zoomConfig.passcode ?? true,
            autoRecord: zoomSettings.autoRecord ?? zoomConfig.autoRecord ?? false,
            muteOnEntry: zoomSettings.muteOnEntry ?? false,
            joinBeforeHost: zoomSettings.joinBeforeHost ?? true,
          });
          if (zoom) {
            finalMeetLink = zoom.joinUrl;
            await db.collection("slots").doc(slotId).update({
              meetingLink: zoom.joinUrl,
              zoomMeetingId: zoom.meetingId,
            });
          }
        }
      }

      // Create Google Calendar event if enabled
      if (calEnabled) {
        const titleTemplate = config.gcal?.titleTemplate || "4E Workshop — {participant}";
        const descTemplate = config.gcal?.descTemplate || "{group} — {label}";
        const title = titleTemplate.replace("{participant}", after.name).replace("{group}", group?.name || "").replace("{label}", slot.label || "");
        const desc = descTemplate.replace("{participant}", after.name).replace("{group}", group?.name || "").replace("{label}", slot.label || "");

        const result = await createCalendarEvent({
          title,
          description: desc + (finalMeetLink ? "\n\nJoin Meeting: " + finalMeetLink : ""),
          startTime: start.toISOString(),
          endTime: end.toISOString(),
          attendeeEmail: after.email || null,
          location: finalMeetLink || null,
          reminderMinutes: config.gcal?.reminderMinutes || 30,
          colorId: config.gcal?.eventColor || null,
          visibility: config.gcal?.visibility || null,
          showAs: config.gcal?.showAs || null,
        });

        if (result) {
          // Store event ID in the participant's bookedSlots entry
          const updatedSlots = (after.bookedSlots || []).map(e => {
            const id = typeof e === "string" ? e : e.slotId;
            if (id === slotId) {
              const entry = typeof e === "string" ? { slotId: e, status: "booked", notes: "" } : { ...e };
              entry.gcalEventId = result.eventId;
              return entry;
            }
            return e;
          });
          await db.collection("participants").doc(participantId).update({ bookedSlots: updatedSlots });
        }
      }

      // Send email invite via EmailJS if enabled
      if (config.autoSendEmail && after.email) {
        try {
          const ejsDoc = await db.collection("config").doc("emailjs").get();
          const ejs = ejsDoc.exists ? ejsDoc.data() : {};
          if (ejs.enabled && ejs.serviceId && ejs.templateId && ejs.publicKey) {
            // Format date and time for email
            const dateStr = start.toLocaleDateString("en-GB", { weekday: "long", day: "numeric", month: "long", year: "numeric", timeZone: "Europe/Dublin" });
            const timeStr = start.toLocaleTimeString("en-GB", { hour: "2-digit", minute: "2-digit", timeZone: "Europe/Dublin" });

            // Generate .ics content
            const pad2 = n => String(n).padStart(2, "0");
            const icsDate = d => d.getUTCFullYear() + pad2(d.getUTCMonth()+1) + pad2(d.getUTCDate()) + "T" + pad2(d.getUTCHours()) + pad2(d.getUTCMinutes()) + pad2(d.getUTCSeconds()) + "Z";
            const uid = slotId + "-" + participantId + "@4escheduler";
            const icsContent = [
              "BEGIN:VCALENDAR",
              "VERSION:2.0",
              "PRODID:-//4E Workshop Scheduler//EN",
              "CALSCALE:GREGORIAN",
              "METHOD:REQUEST",
              "BEGIN:VEVENT",
              "UID:" + uid,
              "DTSTART:" + icsDate(start),
              "DTEND:" + icsDate(end),
              "SUMMARY:" + (slot.label || "4E Workshop Session"),
              "DESCRIPTION:" + (group?.name || "") + " — " + (slot.label || "Workshop Session") + (finalMeetLink ? "\\nJoin: " + finalMeetLink : ""),
              finalMeetLink ? "LOCATION:" + finalMeetLink : "",
              "STATUS:CONFIRMED",
              "ORGANIZER;CN=4E Workshop:mailto:noreply@4escheduler.com",
              "ATTENDEE;CN=" + after.name + ";RSVP=TRUE:mailto:" + after.email,
              "BEGIN:VALARM",
              "TRIGGER:-PT30M",
              "ACTION:DISPLAY",
              "DESCRIPTION:Reminder",
              "END:VALARM",
              "END:VEVENT",
              "END:VCALENDAR"
            ].filter(Boolean).join("\r\n");

            const templateParams = {
              to_email: after.email,
              to_name: after.name,
              session_title: slot.label || "4E Workshop Session",
              session_date: dateStr,
              session_time: timeStr,
              session_duration: String(dur),
              group_name: group?.name || "",
              meeting_link: finalMeetLink || "",
              scheduler_link: "https://sean4e.github.io/4E_Scheduler/",
              participant_code: after.code || "",
              ics_content: icsContent,
            };

            const emailResp = await fetch("https://api.emailjs.com/api/v1.0/email/send", {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({
                service_id: ejs.serviceId,
                template_id: ejs.templateId,
                user_id: ejs.publicKey,
                template_params: templateParams,
                accessToken: EMAILJS_PRIVATE_KEY,
              }),
            });

            if (emailResp.ok) {
              console.log("Email invite sent to", after.email, "for slot", slotId);
              // Mark invite as sent on the booking entry
              const currentDoc = await db.collection("participants").doc(participantId).get();
              if (currentDoc.exists) {
                const currentSlots = (currentDoc.data().bookedSlots || []).map(e => {
                  const id = typeof e === "string" ? e : e.slotId;
                  if (id === slotId) {
                    const entry = typeof e === "string" ? { slotId: e, status: "booked", notes: "" } : { ...e };
                    entry.inviteSent = true;
                    return entry;
                  }
                  return e;
                });
                await db.collection("participants").doc(participantId).update({ bookedSlots: currentSlots });
              }
            } else {
              console.error("EmailJS send failed:", await emailResp.text());
            }
          }
        } catch (emailErr) {
          console.error("Email invite error:", emailErr.message);
        }
      }
    }

    // Handle cancellations — delete calendar events
    if (cancelled.length && before) {
      for (const slotId of cancelled) {
        const oldEntry = (before.bookedSlots || []).find(e => {
          const id = typeof e === "string" ? e : e.slotId;
          return id === slotId;
        });
        if (oldEntry && typeof oldEntry === "object" && oldEntry.gcalEventId) {
          await deleteCalendarEvent(oldEntry.gcalEventId);
        }
      }
    }
  }
);

// ══════════════════════════════════════════════════════
//  PIN VERIFICATION
// ══════════════════════════════════════════════════════
exports.verifyAdminPin = onRequest({ region: REGION }, async (req, res) => {
  if (!handleCors(req, res)) return;
  const { pin } = req.body;
  const ip = req.ip || req.headers["x-forwarded-for"] || "unknown";
  if (!checkRateLimit(ip)) { res.status(429).json({ error: "Too many attempts. Locked for 5 minutes." }); return; }
  if (!pin || pin.length !== 4) { res.status(400).json({ error: "Invalid PIN" }); return; }
  try {
    const doc = await db.collection("config").doc("admin").get();
    if (!doc.exists || !doc.data().pinHash) {
      const hash = sha256(pin);
      await db.collection("config").doc("admin").set({ pinHash: hash });
      const token = crypto.randomBytes(32).toString("hex");
      await db.collection("sessions").doc(token).set({ role: "admin", createdAt: admin.firestore.FieldValue.serverTimestamp(), expiresAt: Date.now() + 2 * 3600000 });
      clearFails(ip);
      res.json({ success: true, token, isNew: true });
      return;
    }
    const hash = sha256(pin);
    if (hash === doc.data().pinHash) {
      const token = crypto.randomBytes(32).toString("hex");
      await db.collection("sessions").doc(token).set({ role: "admin", createdAt: admin.firestore.FieldValue.serverTimestamp(), expiresAt: Date.now() + 2 * 3600000 });
      clearFails(ip);
      res.json({ success: true, token });
    } else {
      recordFail(ip);
      const r = attempts.get(ip);
      res.status(401).json({ error: "Incorrect PIN", remaining: Math.max(0, 5 - (r?.count || 0)) });
    }
  } catch (err) { res.status(500).json({ error: "Server error" }); }
});

exports.verifySupervisorPin = onRequest({ region: REGION }, async (req, res) => {
  if (!handleCors(req, res)) return;
  const { pin } = req.body;
  const ip = req.ip || req.headers["x-forwarded-for"] || "unknown";
  if (!checkRateLimit(ip)) { res.status(429).json({ error: "Too many attempts. Locked for 5 minutes." }); return; }
  if (!pin || pin.length !== 4) { res.status(400).json({ error: "Invalid PIN" }); return; }
  try {
    const hash = sha256(pin);
    const snap = await db.collection("groups").get();
    const match = snap.docs.find(d => d.data().supervisorPinHash === hash);
    if (match) {
      const token = crypto.randomBytes(32).toString("hex");
      await db.collection("sessions").doc(token).set({ role: "supervisor", groupId: match.id, createdAt: admin.firestore.FieldValue.serverTimestamp(), expiresAt: Date.now() + 2 * 3600000 });
      clearFails(ip);
      res.json({ success: true, token, groupId: match.id, groupName: match.data().name });
    } else {
      recordFail(ip);
      const r = attempts.get(ip);
      res.status(401).json({ error: "PIN not recognised", remaining: Math.max(0, 5 - (r?.count || 0)) });
    }
  } catch (err) { res.status(500).json({ error: "Server error" }); }
});

exports.changeAdminPin = onRequest({ region: REGION }, async (req, res) => {
  if (!handleCors(req, res)) return;
  const { token, newPin } = req.body;
  if (!token || !newPin || newPin.length !== 4) { res.status(400).json({ error: "Invalid request" }); return; }
  try {
    const sess = await db.collection("sessions").doc(token).get();
    if (!sess.exists || sess.data().role !== "admin" || Date.now() > sess.data().expiresAt) {
      res.status(401).json({ error: "Invalid or expired session" }); return;
    }
    await db.collection("config").doc("admin").set({ pinHash: sha256(newPin) });
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: "Server error" }); }
});

// ══════════════════════════════════════════════════════
//  ZOOM ENDPOINTS (for manual triggers / status check)
// ══════════════════════════════════════════════════════
exports.checkZoom = onRequest({ region: REGION }, async (req, res) => {
  if (!handleCors(req, res)) return;
  try {
    const token = await getZoomToken();
    const r = await fetch("https://api.zoom.us/v2/users/me", { headers: { "Authorization": `Bearer ${token}` } });
    const d = await r.json();
    if (!r.ok) { res.status(500).json({ connected: false, error: d.message }); return; }
    res.json({ connected: true, email: d.email, name: (d.first_name || "") + " " + (d.last_name || "") });
  } catch (err) { res.status(500).json({ connected: false, error: err.message }); }
});

exports.createMeeting = onRequest({ region: REGION }, async (req, res) => {
  if (!handleCors(req, res)) return;
  const { topic, start_time, duration, settings } = req.body;
  if (!topic || !start_time) { res.status(400).json({ error: "Missing topic or start_time" }); return; }
  try {
    const result = await createZoomMeetingServer({ topic, startTime: start_time, duration, waitingRoom: settings?.waiting_room, passcode: !!settings?.passcode, autoRecord: settings?.auto_recording === "cloud" });
    if (result) res.json({ success: true, join_url: result.joinUrl, meeting_id: result.meetingId, passcode: result.passcode, start_url: result.startUrl });
    else res.status(500).json({ error: "Failed to create meeting" });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

exports.deleteMeeting = onRequest({ region: REGION }, async (req, res) => {
  if (!handleCors(req, res)) return;
  const { meeting_id } = req.body;
  if (!meeting_id || !/^\d+$/.test(String(meeting_id))) { res.status(400).json({ error: "Invalid meeting_id" }); return; }
  try {
    const token = await getZoomToken();
    const r = await fetch(`https://api.zoom.us/v2/meetings/${meeting_id}`, { method: "DELETE", headers: { "Authorization": `Bearer ${token}` } });
    if (r.status === 204 || r.ok) res.json({ success: true });
    else { const d = await r.json(); res.status(r.status).json({ error: "Failed to delete", details: d }); }
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ── Calendar status check ──
exports.checkCalendar = onRequest({ region: REGION }, async (req, res) => {
  if (!handleCors(req, res)) return;
  try {
    const calendar = getCalendar();
    // Use events.list instead of calendarList.get (works for shared calendars)
    const r = await calendar.events.list({ calendarId: GOOGLE_CALENDAR_ID, maxResults: 1, timeMin: new Date().toISOString() });
    res.json({ connected: true, calendarId: GOOGLE_CALENDAR_ID, email: process.env.GOOGLE_SERVICE_ACCOUNT_EMAIL });
  } catch (err) {
    res.status(500).json({ connected: false, error: err.message, hint: "Share your Google Calendar with: " + (process.env.GOOGLE_SERVICE_ACCOUNT_EMAIL || "the service account email") });
  }
});
