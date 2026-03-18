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
const GOOGLE_CALENDAR_ID  = process.env.GOOGLE_CALENDAR_ID || "primary";
const GOOGLE_CLIENT_ID    = process.env.GOOGLE_CLIENT_ID;
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;
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
//  GOOGLE CALENDAR — Admin's OAuth2 (refresh token, always-on)
//  Creates events AS the admin, can add attendees, Google sends invites
// ══════════════════════════════════════════════════════

async function getCalendarAsAdmin() {
  // Load stored refresh token from Firestore
  const doc = await db.collection("config").doc("googleAuth").get();
  if (!doc.exists || !doc.data().refreshToken) {
    throw new Error("Google Calendar not connected — admin needs to connect in Settings");
  }

  const oauth2Client = new google.auth.OAuth2(GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET);
  oauth2Client.setCredentials({ refresh_token: doc.data().refreshToken });

  return google.calendar({ version: "v3", auth: oauth2Client });
}

async function createCalendarEvent({ title, description, startTime, endTime, attendeeEmail, location, reminderMinutes, colorId, visibility, showAs }) {
  try {
    const calendar = await getCalendarAsAdmin();
    const event = {
      summary: title,
      description: description || "",
      start: { dateTime: startTime, timeZone: "Europe/Dublin" },
      end: { dateTime: endTime, timeZone: "Europe/Dublin" },
      reminders: { useDefault: false, overrides: [{ method: "popup", minutes: reminderMinutes || 30 }] },
    };
    // Add participant as attendee — Google sends invite from admin's Gmail automatically
    if (attendeeEmail) {
      event.attendees = [{ email: attendeeEmail }];
    }
    if (location) event.location = location;
    if (colorId) event.colorId = String(colorId);
    if (visibility && visibility !== "default") event.visibility = visibility;
    if (showAs) event.transparency = showAs === "free" ? "transparent" : "opaque";

    const res = await calendar.events.insert({
      calendarId: GOOGLE_CALENDAR_ID,
      resource: event,
      sendUpdates: attendeeEmail ? "all" : "none", // Google sends invite email
    });
    return { eventId: res.data.id, htmlLink: res.data.htmlLink };
  } catch (err) {
    console.error("Calendar create error:", err.message);
    return null;
  }
}

async function deleteCalendarEvent(eventId) {
  try {
    const calendar = await getCalendarAsAdmin();
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

      // Send email invite via Gmail API (from admin's Gmail, with .ics attachment)
      if (after.email) {
        try {
          const dateStr = start.toLocaleDateString("en-GB", { weekday: "long", day: "numeric", month: "long", year: "numeric", timeZone: "Europe/Dublin" });
          const timeStr = start.toLocaleTimeString("en-GB", { hour: "2-digit", minute: "2-digit", timeZone: "Europe/Dublin" });
          const titleTemplate = config.gcal?.titleTemplate || "4E Workshop — {participant}";
          const eventTitle = titleTemplate.replace("{participant}", after.name).replace("{group}", group?.name || "").replace("{label}", slot.label || "");

          // Generate .ics content
          const pad2 = n => String(n).padStart(2, "0");
          const icsDate = d => d.getUTCFullYear() + pad2(d.getUTCMonth()+1) + pad2(d.getUTCDate()) + "T" + pad2(d.getUTCHours()) + pad2(d.getUTCMinutes()) + pad2(d.getUTCSeconds()) + "Z";
          const icsUid = slotId + "-" + participantId + "@4escheduler";
          const organizerEmail = GOOGLE_CALENDAR_ID;
          const icsContent = [
            "BEGIN:VCALENDAR",
            "VERSION:2.0",
            "PRODID:-//4E Workshop Scheduler//EN",
            "CALSCALE:GREGORIAN",
            "METHOD:REQUEST",
            "BEGIN:VEVENT",
            "UID:" + icsUid,
            "DTSTART:" + icsDate(start),
            "DTEND:" + icsDate(end),
            "SUMMARY:" + eventTitle,
            "DESCRIPTION:" + (group?.name || "") + " — " + (slot.label || "Workshop Session") + (finalMeetLink ? "\\nJoin: " + finalMeetLink : ""),
            finalMeetLink ? "LOCATION:" + finalMeetLink : "",
            "STATUS:CONFIRMED",
            "ORGANIZER;CN=4E Workshops:mailto:" + organizerEmail,
            "ATTENDEE;CN=" + after.name + ";RSVP=TRUE;PARTSTAT=NEEDS-ACTION:mailto:" + after.email,
            "BEGIN:VALARM",
            "TRIGGER:-PT" + (config.gcal?.reminderMinutes || 30) + "M",
            "ACTION:DISPLAY",
            "DESCRIPTION:Reminder",
            "END:VALARM",
            "END:VEVENT",
            "END:VCALENDAR"
          ].filter(Boolean).join("\r\n");

          // Build MIME email with .ics attachment
          const selfServiceInfo = group?.allowSelfService
            ? `\n\nYour booking code: ${after.code || ""}\nView or change your booking: https://sean4e.github.io/4E_Scheduler/`
            : "";
          const boundary = "boundary_" + Date.now();
          const htmlBody = `<div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;background:#1a1a2e;color:#f0eeff;border-radius:12px;overflow:hidden">
  <div style="background:linear-gradient(135deg,#7c3aed,#22d3ee);padding:24px 32px">
    <h1 style="margin:0;font-size:22px;color:#fff">4E Workshop Session</h1>
  </div>
  <div style="padding:24px 32px">
    <p style="font-size:16px;margin:0 0 8px">Hi <strong>${after.name}</strong>,</p>
    <p style="color:#9d98be;margin:0 0 24px">Your session has been booked:</p>
    <div style="background:rgba(255,255,255,.06);border:1px solid rgba(255,255,255,.1);border-radius:10px;padding:18px;margin-bottom:20px">
      <div style="font-size:18px;font-weight:bold;margin-bottom:6px">${eventTitle}</div>
      <div style="color:#a78bfa;font-size:14px;margin-bottom:4px">📅 ${dateStr}</div>
      <div style="color:#22d3ee;font-size:14px;margin-bottom:4px">🕐 ${timeStr} · ${dur} minutes</div>
      ${group?.name ? `<div style="color:#9d98be;font-size:13px">📁 ${group.name}</div>` : ""}
    </div>
    ${finalMeetLink ? `<div style="margin-bottom:20px"><a href="${finalMeetLink}" style="display:inline-block;background:linear-gradient(135deg,#7c3aed,#22d3ee);color:#fff;padding:12px 24px;border-radius:8px;text-decoration:none;font-weight:bold;font-size:14px">Join Meeting</a><p style="color:#9d98be;font-size:12px;margin-top:8px">${finalMeetLink}</p></div>` : ""}
    ${group?.allowSelfService ? `<div style="background:rgba(34,211,238,.08);border:1px solid rgba(34,211,238,.2);border-radius:8px;padding:14px;margin-bottom:20px"><div style="font-size:12px;color:#22d3ee;margin-bottom:6px">YOUR BOOKING CODE</div><div style="font-family:monospace;font-size:18px;letter-spacing:3px;font-weight:bold">${after.code || ""}</div><a href="https://sean4e.github.io/4E_Scheduler/" style="color:#22d3ee;font-size:12px;margin-top:8px;display:inline-block">View or change your booking →</a></div>` : ""}
    <p style="color:#4a4868;font-size:11px;margin-top:24px">4E Virtual Design · Workshop Scheduler</p>
  </div>
</div>`;

          const rawEmail = [
            `From: 4E Workshops <${organizerEmail}>`,
            `To: ${after.name} <${after.email}>`,
            `Subject: ${eventTitle} — ${dateStr}`,
            "MIME-Version: 1.0",
            `Content-Type: multipart/mixed; boundary="${boundary}"`,
            "",
            `--${boundary}`,
            "Content-Type: multipart/alternative; boundary=\"alt_" + boundary + "\"",
            "",
            "--alt_" + boundary,
            "Content-Type: text/plain; charset=UTF-8",
            "",
            `Hi ${after.name},\n\nYour session has been booked:\n${eventTitle}\n${dateStr} at ${timeStr} (${dur} min)\n${finalMeetLink ? "Join: " + finalMeetLink + "\n" : ""}${selfServiceInfo}\n\n— 4E Workshops`,
            "",
            "--alt_" + boundary,
            "Content-Type: text/html; charset=UTF-8",
            "",
            htmlBody,
            "",
            "--alt_" + boundary + "--",
            "",
            `--${boundary}`,
            "Content-Type: text/calendar; charset=UTF-8; method=REQUEST",
            "Content-Transfer-Encoding: base64",
            "Content-Disposition: attachment; filename=\"invite.ics\"",
            "",
            Buffer.from(icsContent).toString("base64"),
            "",
            `--${boundary}--`,
          ].join("\r\n");

          // Send via Gmail API using admin's refresh token
          const authDoc = await db.collection("config").doc("googleAuth").get();
          if (authDoc.exists && authDoc.data().refreshToken) {
            const oauth2 = new google.auth.OAuth2(GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET);
            oauth2.setCredentials({ refresh_token: authDoc.data().refreshToken });
            const gmail = google.gmail({ version: "v1", auth: oauth2 });

            const encodedMessage = Buffer.from(rawEmail).toString("base64")
              .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

            await gmail.users.messages.send({
              userId: "me",
              requestBody: { raw: encodedMessage },
            });
            console.log("Gmail invite sent to", after.email, "for slot", slotId);

            // Mark invite as sent
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
            console.log("Gmail not available — admin needs to reconnect Google Calendar");
          }
        } catch (emailErr) {
          console.error("Gmail invite error:", emailErr.message);
        }
      }
    }

    // Handle cancellations — delete calendar events + send cancellation email
    if (cancelled.length && before) {
      for (const slotId of cancelled) {
        const oldEntry = (before.bookedSlots || []).find(e => {
          const id = typeof e === "string" ? e : e.slotId;
          return id === slotId;
        });
        if (oldEntry && typeof oldEntry === "object" && oldEntry.gcalEventId) {
          await deleteCalendarEvent(oldEntry.gcalEventId);
        }

        // Send cancellation email via Gmail
        const participantEmail = (after || before).email;
        const participantName = (after || before).name;
        if (participantEmail) {
          try {
            const slotDoc = await db.collection("slots").doc(slotId).get();
            if (slotDoc.exists) {
              const slot = slotDoc.data();
              const [h, m] = slot.time.split(":").map(Number);
              const cancelStart = new Date(slot.date + "T" + String(h).padStart(2,"0") + ":" + String(m).padStart(2,"0") + ":00");
              const dateStr = cancelStart.toLocaleDateString("en-GB", { weekday: "long", day: "numeric", month: "long", year: "numeric", timeZone: "Europe/Dublin" });
              const timeStr = cancelStart.toLocaleTimeString("en-GB", { hour: "2-digit", minute: "2-digit", timeZone: "Europe/Dublin" });

              const cancelHtml = `<div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;background:#1a1a2e;color:#f0eeff;border-radius:12px;overflow:hidden">
  <div style="background:linear-gradient(135deg,#ef4444,#dc2626);padding:24px 32px">
    <h1 style="margin:0;font-size:22px;color:#fff">Session Cancelled</h1>
  </div>
  <div style="padding:24px 32px">
    <p style="font-size:16px;margin:0 0 8px">Hi <strong>${participantName}</strong>,</p>
    <p style="color:#9d98be;margin:0 0 24px">Your session has been cancelled:</p>
    <div style="background:rgba(239,68,68,.08);border:1px solid rgba(239,68,68,.2);border-radius:10px;padding:18px;margin-bottom:20px">
      <div style="font-size:18px;font-weight:bold;margin-bottom:6px;text-decoration:line-through">${slot.label || "Workshop Session"}</div>
      <div style="color:#f87171;font-size:14px">📅 ${dateStr} · 🕐 ${timeStr}</div>
    </div>
    <p style="color:#9d98be;font-size:14px">If you need to rebook, please contact your supervisor or trainer.</p>
    <p style="color:#4a4868;font-size:11px;margin-top:24px">4E Virtual Design · Workshop Scheduler</p>
  </div>
</div>`;

              const authDoc = await db.collection("config").doc("googleAuth").get();
              if (authDoc.exists && authDoc.data().refreshToken) {
                const oauth2 = new google.auth.OAuth2(GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET);
                oauth2.setCredentials({ refresh_token: authDoc.data().refreshToken });
                const gmail = google.gmail({ version: "v1", auth: oauth2 });

                const cancelRaw = [
                  `From: 4E Workshops <${GOOGLE_CALENDAR_ID}>`,
                  `To: ${participantName} <${participantEmail}>`,
                  `Subject: Session Cancelled — ${slot.label || "Workshop"} on ${dateStr}`,
                  "MIME-Version: 1.0",
                  "Content-Type: text/html; charset=UTF-8",
                  "",
                  cancelHtml,
                ].join("\r\n");

                const encodedCancel = Buffer.from(cancelRaw).toString("base64")
                  .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

                await gmail.users.messages.send({ userId: "me", requestBody: { raw: encodedCancel } });
                console.log("Cancellation email sent to", participantEmail, "for slot", slotId);
              }
            }
          } catch (cancelErr) {
            console.error("Cancellation email error:", cancelErr.message);
          }
        }
      }
    }
  }
);

// ══════════════════════════════════════════════════════
//  SEND WELCOME EMAIL (Gmail API)
// ══════════════════════════════════════════════════════
exports.sendWelcomeEmail = onRequest({ region: REGION }, async (req, res) => {
  if (!handleCors(req, res)) return;
  const { participantName, participantEmail, participantCode, groupName, allowSelfService } = req.body;

  if (!participantEmail) { res.status(400).json({ error: "No email provided" }); return; }

  try {
    const authDoc = await db.collection("config").doc("googleAuth").get();
    if (!authDoc.exists || !authDoc.data().refreshToken) {
      res.status(400).json({ error: "Google Calendar not connected" }); return;
    }

    const oauth2 = new google.auth.OAuth2(GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET);
    oauth2.setCredentials({ refresh_token: authDoc.data().refreshToken });
    const gmail = google.gmail({ version: "v1", auth: oauth2 });

    const htmlBody = `<div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;background:#1a1a2e;color:#f0eeff;border-radius:12px;overflow:hidden">
  <div style="background:linear-gradient(135deg,#7c3aed,#22d3ee);padding:24px 32px">
    <h1 style="margin:0;font-size:22px;color:#fff">Welcome to 4E Workshops</h1>
  </div>
  <div style="padding:24px 32px">
    <p style="font-size:16px;margin:0 0 8px">Hi <strong>${participantName}</strong>,</p>
    <p style="color:#9d98be;margin:0 0 24px">You've been added to the 4E Workshop Scheduler${groupName ? " as part of <strong>" + groupName + "</strong>" : ""}.</p>
    <div style="background:rgba(34,211,238,.08);border:1px solid rgba(34,211,238,.2);border-radius:10px;padding:20px;margin-bottom:20px;text-align:center">
      <div style="font-size:12px;color:#22d3ee;margin-bottom:8px;letter-spacing:2px">YOUR ACCESS CODE</div>
      <div style="font-family:monospace;font-size:28px;letter-spacing:5px;font-weight:bold;margin-bottom:12px">${participantCode}</div>
      <a href="https://sean4e.github.io/4E_Scheduler/" style="display:inline-block;background:linear-gradient(135deg,#7c3aed,#22d3ee);color:#fff;padding:12px 24px;border-radius:8px;text-decoration:none;font-weight:bold;font-size:14px">Open Scheduler</a>
    </div>
    ${allowSelfService ? '<p style="color:#9d98be;font-size:13px;margin-bottom:16px">You can use your code to view your sessions and change your booking times.</p>' : '<p style="color:#9d98be;font-size:13px;margin-bottom:16px">Use your code to view your upcoming sessions and meeting details.</p>'}
    <p style="color:#4a4868;font-size:11px;margin-top:24px">4E Virtual Design · Workshop Scheduler</p>
  </div>
</div>`;

    const rawEmail = [
      `From: 4E Workshops <${GOOGLE_CALENDAR_ID}>`,
      `To: ${participantName} <${participantEmail}>`,
      `Subject: Welcome to 4E Workshops — Your Access Code`,
      "MIME-Version: 1.0",
      "Content-Type: text/html; charset=UTF-8",
      "",
      htmlBody,
    ].join("\r\n");

    const encoded = Buffer.from(rawEmail).toString("base64")
      .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

    await gmail.users.messages.send({ userId: "me", requestBody: { raw: encoded } });
    console.log("Welcome email sent to", participantEmail);
    res.json({ success: true });
  } catch (err) {
    console.error("Welcome email error:", err.message);
    res.status(500).json({ error: err.message });
  }
});

// ══════════════════════════════════════════════════════
//  SEND REMINDERS (Gmail API — sessions in next 24hrs)
// ══════════════════════════════════════════════════════
exports.sendReminders = onRequest({ region: REGION }, async (req, res) => {
  if (!handleCors(req, res)) return;

  try {
    const authDoc = await db.collection("config").doc("googleAuth").get();
    if (!authDoc.exists || !authDoc.data().refreshToken) {
      res.status(400).json({ error: "Google Calendar not connected" }); return;
    }

    const oauth2 = new google.auth.OAuth2(GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET);
    oauth2.setCredentials({ refresh_token: authDoc.data().refreshToken });
    const gmail = google.gmail({ version: "v1", auth: oauth2 });

    // Find all sessions in the next 24-48 hours
    const now = new Date();
    const tomorrow = new Date(now.getTime() + 24 * 60 * 60 * 1000);
    const dayAfter = new Date(now.getTime() + 48 * 60 * 60 * 1000);
    const tomorrowDate = tomorrow.toISOString().split("T")[0];

    // Get slots for tomorrow
    const slotsSnap = await db.collection("slots").where("date", "==", tomorrowDate).get();
    if (slotsSnap.empty) { res.json({ sent: 0, message: "No sessions tomorrow" }); return; }

    const slotMap = {};
    slotsSnap.forEach(d => { slotMap[d.id] = { id: d.id, ...d.data() }; });

    // Get all participants
    const partsSnap = await db.collection("participants").get();
    let sent = 0;

    for (const pDoc of partsSnap.docs) {
      const p = pDoc.data();
      if (!p.email || !p.bookedSlots?.length) continue;

      for (const entry of p.bookedSlots) {
        const slotId = typeof entry === "string" ? entry : entry.slotId;
        const slot = slotMap[slotId];
        if (!slot) continue;

        // Skip if already reminded
        if (typeof entry === "object" && entry.reminded) continue;

        const [h, m] = slot.time.split(":").map(Number);
        const sessionTime = new Date(slot.date + "T" + String(h).padStart(2,"0") + ":" + String(m).padStart(2,"0") + ":00");
        const dateStr = sessionTime.toLocaleDateString("en-GB", { weekday: "long", day: "numeric", month: "long", year: "numeric", timeZone: "Europe/Dublin" });
        const timeStr = sessionTime.toLocaleTimeString("en-GB", { hour: "2-digit", minute: "2-digit", timeZone: "Europe/Dublin" });
        const dur = slot.duration || 30;
        const meetLink = slot.meetingLink || "";

        // Get group
        let groupName = "";
        if (slot.groupId && slot.groupId !== "all") {
          const gDoc = await db.collection("groups").doc(slot.groupId).get();
          if (gDoc.exists) groupName = gDoc.data().name || "";
        }

        const configDoc = await db.collection("config").doc("integrations").get();
        const config = configDoc.exists ? configDoc.data() : {};
        const titleTemplate = config.gcal?.titleTemplate || "4E Workshop — {participant}";
        const eventTitle = titleTemplate.replace("{participant}", p.name).replace("{group}", groupName).replace("{label}", slot.label || "");

        const htmlBody = `<div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;background:#1a1a2e;color:#f0eeff;border-radius:12px;overflow:hidden">
  <div style="background:linear-gradient(135deg,#fb923c,#f87171);padding:24px 32px">
    <h1 style="margin:0;font-size:22px;color:#fff">Session Reminder</h1>
  </div>
  <div style="padding:24px 32px">
    <p style="font-size:16px;margin:0 0 8px">Hi <strong>${p.name}</strong>,</p>
    <p style="color:#9d98be;margin:0 0 24px">Your session is coming up tomorrow:</p>
    <div style="background:rgba(255,255,255,.06);border:1px solid rgba(255,255,255,.1);border-radius:10px;padding:18px;margin-bottom:20px">
      <div style="font-size:18px;font-weight:bold;margin-bottom:6px">${eventTitle}</div>
      <div style="color:#a78bfa;font-size:14px;margin-bottom:4px">📅 ${dateStr}</div>
      <div style="color:#22d3ee;font-size:14px;margin-bottom:4px">🕐 ${timeStr} · ${dur} min</div>
      ${groupName ? `<div style="color:#9d98be;font-size:13px">📁 ${groupName}</div>` : ""}
    </div>
    ${meetLink ? `<a href="${meetLink}" style="display:inline-block;background:linear-gradient(135deg,#7c3aed,#22d3ee);color:#fff;padding:12px 24px;border-radius:8px;text-decoration:none;font-weight:bold;font-size:14px">Join Meeting</a>` : ""}
    <p style="color:#4a4868;font-size:11px;margin-top:24px">4E Virtual Design · Workshop Scheduler</p>
  </div>
</div>`;

        const rawEmail = [
          `From: 4E Workshops <${GOOGLE_CALENDAR_ID}>`,
          `To: ${p.name} <${p.email}>`,
          `Subject: Reminder: ${eventTitle} tomorrow at ${timeStr}`,
          "MIME-Version: 1.0",
          "Content-Type: text/html; charset=UTF-8",
          "",
          htmlBody,
        ].join("\r\n");

        const encoded = Buffer.from(rawEmail).toString("base64")
          .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

        await gmail.users.messages.send({ userId: "me", requestBody: { raw: encoded } });
        console.log("Reminder sent to", p.email, "for slot", slotId);

        // Mark as reminded
        const updatedSlots = (p.bookedSlots || []).map(e => {
          const id = typeof e === "string" ? e : e.slotId;
          if (id === slotId) {
            const obj = typeof e === "string" ? { slotId: e, status: "booked", notes: "" } : { ...e };
            obj.reminded = true;
            return obj;
          }
          return e;
        });
        await db.collection("participants").doc(pDoc.id).update({ bookedSlots: updatedSlots });
        sent++;
      }
    }

    res.json({ sent, message: `${sent} reminder${sent !== 1 ? "s" : ""} sent` });
  } catch (err) {
    console.error("Reminder error:", err.message);
    res.status(500).json({ error: err.message });
  }
});

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
// Google OAuth token exchange — admin connects once, we store refresh token
exports.googleAuth = onRequest({ region: REGION }, async (req, res) => {
  if (!handleCors(req, res)) return;
  const { code, redirect_uri } = req.body;
  if (!code) { res.status(400).json({ error: "Missing auth code" }); return; }

  try {
    // Use 'postmessage' for popup-based code flow
    const oauth2Client = new google.auth.OAuth2(GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, "postmessage");
    const { tokens } = await oauth2Client.getToken(code);

    if (!tokens.refresh_token) {
      res.status(400).json({ error: "No refresh token received. Try revoking access at myaccount.google.com/permissions and reconnecting." });
      return;
    }

    // Get user email
    oauth2Client.setCredentials(tokens);
    const oauth2 = google.oauth2({ version: "v2", auth: oauth2Client });
    const userInfo = await oauth2.userinfo.get();

    // Store refresh token securely in Firestore (only Cloud Functions can read this)
    await db.collection("config").doc("googleAuth").set({
      refreshToken: tokens.refresh_token,
      email: userInfo.data.email,
      connectedAt: admin.firestore.FieldValue.serverTimestamp(),
    });

    res.json({ success: true, email: userInfo.data.email });
  } catch (err) {
    console.error("Google OAuth error:", err.message);
    res.status(500).json({ error: err.message });
  }
});

exports.checkCalendar = onRequest({ region: REGION }, async (req, res) => {
  if (!handleCors(req, res)) return;
  try {
    const doc = await db.collection("config").doc("googleAuth").get();
    if (!doc.exists || !doc.data().refreshToken) {
      res.json({ connected: false, hint: "Click Connect to sign in with Google" });
      return;
    }
    // Verify token still works
    const calendar = await getCalendarAsAdmin();
    await calendar.events.list({ calendarId: GOOGLE_CALENDAR_ID, maxResults: 1, timeMin: new Date().toISOString() });
    res.json({ connected: true, calendarId: GOOGLE_CALENDAR_ID, email: doc.data().email });
  } catch (err) {
    res.status(500).json({ connected: false, error: err.message, hint: "Reconnect Google Calendar in Settings" });
  }
});

exports.disconnectCalendar = onRequest({ region: REGION }, async (req, res) => {
  if (!handleCors(req, res)) return;
  try {
    await db.collection("config").doc("googleAuth").delete();
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});
