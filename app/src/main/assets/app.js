const { useState, useEffect, useCallback, useMemo, useRef } = React;

// ─── Secure ID generation (Fix #15 — no more predictable sequential IDs) ──────
// crypto.randomUUID() is available in all modern browsers and Tauri's WebView.
// IDs are now unpredictable — an attacker cannot forge completion keys by guessing.
function generateId() {
  return crypto.randomUUID();
}

// ─── SHA-256 helper (Fix #9 — backup integrity) ───────────────────────────────
// Uses the Web Crypto API (available in all modern browsers and Tauri's webview).
// Every value written to storage is accompanied by its SHA-256 checksum.
// On load, the checksum is recomputed and compared — mismatch triggers a warning
// so the user knows the file may be corrupted or tampered with before bad data
// silently overwrites good state.
async function sha256(str) {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(str));
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, "0")).join("");
}

// ─── Tauri persistence (falls back to localStorage in plain browser) ──────────
// SECURITY NOTE: localStorage is unencrypted. The Tauri store path is preferred.
// The fallback exists only for browser-based development/testing — in production
// the Tauri store is always available and this branch is never reached.
let _tauriStore = null;
async function getStore() {
  if (_tauriStore) return _tauriStore;
  try {
    const {
      Store
    } = await import("@tauri-apps/plugin-store");
    _tauriStore = await Store.load("zenflow.json", {
      autoSave: true
    });
    return _tauriStore;
  } catch {
    return null;
  }
}

// Raw read/write — used internally by the checksum layer
async function _rawGet(key) {
  const s = await getStore();
  if (s) {
    return await s.get(key);
  }
  // Fix #10: use correct "zenflow:" namespace (not stale "momentum:"), and wrap
  // JSON.parse in try/catch so malformed/tampered data never crashes the app.
  try {
    const r = localStorage.getItem("zenflow:" + key);
    return r ? JSON.parse(r) : undefined;
  } catch (err) {
    console.warn(`[Zenflow] localStorage parse error for key "${key}":`, err);
    return undefined;
  }
}
async function _rawSet(key, value) {
  const s = await getStore();
  if (s) {
    await s.set(key, value);
  } else {
    // Fix #10: correct namespace + stringify errors caught
    try {
      localStorage.setItem("zenflow:" + key, JSON.stringify(value));
    } catch (err) {
      console.warn(`[Zenflow] localStorage write error for key "${key}":`, err);
    }
  }
}

// Integrity-checked read: verifies SHA-256 on load, warns on mismatch
async function persistGet(key, fallback) {
  try {
    const envelope = await _rawGet(key);
    if (envelope === undefined || envelope === null) return fallback;

    // Legacy values (written before Fix #9) have no checksum — accept and migrate
    if (typeof envelope !== "object" || !("__v" in envelope) || !("__c" in envelope)) {
      return envelope ?? fallback;
    }
    const {
      __v: value,
      __c: storedHash
    } = envelope;
    const serialised = JSON.stringify(value);
    const computedHash = await sha256(serialised);
    if (computedHash !== storedHash) {
      // Integrity failure — warn in console and return fallback rather than bad data
      console.error(`[Zenflow] Integrity check FAILED for key "${key}".\n` + `  Stored hash:   ${storedHash}\n` + `  Computed hash: ${computedHash}\n` + `  The stored value may be corrupted or tampered with. Falling back to default.`);
      // Surface warning to user via a custom event the App component listens to
      window.dispatchEvent(new CustomEvent("zenflow:integrity-fail", {
        detail: {
          key
        }
      }));
      return fallback;
    }
    return value ?? fallback;
  } catch (err) {
    console.warn(`[Zenflow] persistGet error for key "${key}":`, err);
    return fallback;
  }
}

// Integrity-checked write: stores value + SHA-256 checksum together
async function persistSet(key, value) {
  try {
    const serialised = JSON.stringify(value);
    const hash = await sha256(serialised);
    await _rawSet(key, {
      __v: value,
      __c: hash
    });
  } catch (err) {
    console.warn(`[Zenflow] persistSet error for key "${key}":`, err);
  }
}

// ─── Fonts ────────────────────────────────────────────────────────────────────
// Fonts are now bundled via @fontsource in main.jsx (Fix #7).
// No Google Fonts network call — zero IP logging, fully offline.

// ─── Input Sanitisation (Fix #8) ─────────────────────────────────────────────
// All user-supplied text is run through sanitiseText before being stored.
// React JSX already prevents XSS in rendering, but sanitising at the storage
// layer means any future feature (export, rich text, web preview) is safe by
// default — latent risk eliminated at the source, not patched at each render site.
function sanitiseText(raw) {
  if (typeof raw !== "string") return raw;
  return raw
  // Strip HTML/script tags
  .replace(/<[^>]*>/g, "")
  // Remove javascript: and data: URI schemes
  .replace(/javascript\s*:/gi, "").replace(/data\s*:/gi, "")
  // Remove null bytes
  .replace(/\0/g, "")
  // Trim to reasonable max length (prevents storage DoS)
  .slice(0, 2000).trim();
}
// Sanitise an entire habit form object before saving
function sanitiseHabitForm(form) {
  return {
    ...form,
    name: sanitiseText(form.name ?? ""),
    desc: sanitiseText(form.desc ?? ""),
    icon: sanitiseText(form.icon ?? ""),
    color: /^#[0-9a-fA-F]{6}$/.test(form.color) ? form.color : "#10b981",
    freq: ["daily", "weekly"].includes(form.freq) ? form.freq : "daily"
  };
}

// ─── Data ────────────────────────────────────────────────────────────────────
const INITIAL_HABITS = [];
const SEED_COMPLETIONS = {};
const QUOTES = [{
  text: "You don't rise to the level of your goals. You fall to the level of your systems.",
  author: "James Clear"
}, {
  text: "We are what we repeatedly do. Excellence is not an act, but a habit.",
  author: "Aristotle"
}, {
  text: "The secret of getting ahead is getting started.",
  author: "Mark Twain"
}, {
  text: "Small daily improvements are the key to staggering long-term results.",
  author: "Robin Sharma"
}, {
  text: "Motivation gets you going, but habit gets you there.",
  author: "Jim Ryun"
}, {
  text: "Success is the sum of small efforts repeated day in and day out.",
  author: "Robert Collier"
}, {
  text: "Discipline is choosing between what you want now and what you want most.",
  author: "Abraham Lincoln"
}, {
  text: "A year from now you may wish you had started today.",
  author: "Karen Lamb"
}, {
  text: "Don't watch the clock; do what it does. Keep going.",
  author: "Sam Levenson"
}, {
  text: "Do something today that your future self will thank you for.",
  author: "Sean Patrick Flanery"
}, {
  text: "Either you run the day or the day runs you.",
  author: "Jim Rohn"
}, {
  text: "The journey of a thousand miles begins with one step.",
  author: "Lao Tzu"
}];
const TEMPLATES = [{
  icon: "☀️",
  name: "Morning Routine",
  color: "#f59e0b",
  desc: "Start with intention — hydrate, stretch, and set your focus.",
  freq: "daily"
}, {
  icon: "💪",
  name: "Workout",
  color: "#f43f5e",
  desc: "Get your body moving — gym, run, yoga, or any exercise.",
  freq: "daily"
}, {
  icon: "🧘",
  name: "Meditation",
  color: "#a855f7",
  desc: "10 minutes of calm to clear your mind and reduce stress.",
  freq: "daily"
}, {
  icon: "📚",
  name: "Read 20 Pages",
  color: "#3b82f6",
  desc: "Read at least 20 pages of a book every day.",
  freq: "daily"
}, {
  icon: "💧",
  name: "Drink 8 Glasses",
  color: "#0ea5e9",
  desc: "Drink at least 2 litres of water throughout the day.",
  freq: "daily"
}, {
  icon: "😴",
  name: "Sleep by 10 PM",
  color: "#6366f1",
  desc: "Protect your recovery — be in bed with lights off by 10 PM.",
  freq: "daily"
}, {
  icon: "✍️",
  name: "Journaling",
  color: "#10b981",
  desc: "Reflect on your day — wins, lessons, gratitude.",
  freq: "daily"
}, {
  icon: "📵",
  name: "No Social Media",
  color: "#d946ef",
  desc: "Stay off social platforms — stay present.",
  freq: "daily"
}, {
  icon: "📋",
  name: "Weekly Review",
  color: "#f59e0b",
  desc: "Review goals, wins, and plan for the coming week.",
  freq: "weekly"
}, {
  icon: "🚿",
  name: "Cold Shower",
  color: "#0ea5e9",
  desc: "Build resilience and boost energy.",
  freq: "daily"
}];
const MILESTONE_META = {
  7: {
    label: "One Week Warrior",
    icon: "🔥",
    color: "#f59e0b"
  },
  30: {
    label: "Monthly Master",
    icon: "🏆",
    color: "#a855f7"
  },
  100: {
    label: "Century Champion",
    icon: "💎",
    color: "#00e5ff"
  },
  365: {
    label: "Year-Long Legend",
    icon: "⭐",
    color: "#ffd600"
  }
};
const MILESTONE_DAYS = [7, 30, 100, 365];
const PRESET_COLORS = ["#10b981", "#3b82f6", "#8b5cf6", "#d946ef", "#f43f5e", "#f59e0b", "#0ea5e9", "#ec4899"];

// ─── XP & Levels ─────────────────────────────────────────────────────────────
const XP_PER_COMPLETION = 10;
const XP_PER_STREAK_DAY = 2;
const XP_STREAK_BONUS = {
  7: 50,
  30: 200,
  100: 500,
  365: 2000
};
const LEVELS = [{
  level: 1,
  xp: 0,
  title: "Beginner",
  icon: "🌱"
}, {
  level: 2,
  xp: 100,
  title: "Starter",
  icon: "🌿"
}, {
  level: 3,
  xp: 250,
  title: "Consistent",
  icon: "⚡"
}, {
  level: 4,
  xp: 500,
  title: "Committed",
  icon: "🔥"
}, {
  level: 5,
  xp: 900,
  title: "Dedicated",
  icon: "💪"
}, {
  level: 6,
  xp: 1400,
  title: "Disciplined",
  icon: "🏆"
}, {
  level: 7,
  xp: 2100,
  title: "Elite",
  icon: "💎"
}, {
  level: 8,
  xp: 3000,
  title: "Master",
  icon: "🌟"
}, {
  level: 9,
  xp: 4200,
  title: "Legend",
  icon: "👑"
}, {
  level: 10,
  xp: 6000,
  title: "Unstoppable",
  icon: "⭐"
}];
const ACHIEVEMENTS = [{
  id: "first_check",
  icon: "✅",
  label: "First Step",
  desc: "Complete your first habit",
  check: (h, c) => Object.keys(c).length >= 1
}, {
  id: "week_streak",
  icon: "🔥",
  label: "Week Warrior",
  desc: "7-day streak on any habit",
  check: (h, c) => h.some(x => getStreak(x.id, c, x.freq) >= 7)
}, {
  id: "month_streak",
  icon: "🏆",
  label: "Monthly Master",
  desc: "30-day streak on any habit",
  check: (h, c) => h.some(x => getStreak(x.id, c, x.freq) >= 30)
}, {
  id: "all_done",
  icon: "🌟",
  label: "Perfect Day",
  desc: "Complete all habits in one day",
  check: (h, c) => {
    const td = today();
    return h.length > 0 && h.every(x => c[`${x.id}:${td}`]);
  }
}, {
  id: "five_habits",
  icon: "📋",
  label: "Habit Collector",
  desc: "Track 5 or more habits",
  check: (h, c) => h.length >= 5
}, {
  id: "century",
  icon: "💯",
  label: "Century Club",
  desc: "100 total completions",
  check: (h, c) => Object.keys(c).length >= 100
}, {
  id: "early_bird",
  icon: "🌅",
  label: "Early Bird",
  desc: "Use the app 7 days in a row",
  check: (h, c) => {
    const now = new Date();
    let s = 0;
    for (let i = 0; i < 7; i++) {
      const d = new Date(now);
      d.setDate(d.getDate() - i);
      if (h.some(x => c[`${x.id}:${fmt(d)}`])) s++;
    }
    return s >= 7;
  }
}, {
  id: "variety",
  icon: "🎯",
  label: "Well Rounded",
  desc: "Have habits in 3+ categories",
  check: (h, c) => new Set(h.map(x => x.icon)).size >= 3
}];
function computeXP(habits, completions) {
  let xp = 0;
  Object.keys(completions).forEach(() => {
    xp += XP_PER_COMPLETION;
  });
  habits.forEach(h => {
    const streak = getLongestStreak(h.id, completions, h.freq);
    xp += streak * XP_PER_STREAK_DAY;
    Object.entries(XP_STREAK_BONUS).forEach(([days, bonus]) => {
      if (streak >= parseInt(days)) xp += bonus;
    });
  });
  return xp;
}
function getLevel(xp) {
  let lvl = LEVELS[0];
  for (const l of LEVELS) {
    if (xp >= l.xp) lvl = l;else break;
  }
  const next = LEVELS.find(l => l.xp > xp);
  const pct = next ? (xp - lvl.xp) / (next.xp - lvl.xp) : 1;
  return {
    ...lvl,
    xp,
    nextXp: next?.xp ?? lvl.xp,
    pct,
    next
  };
}
const fmt = d => d.toISOString().split("T")[0];
const today = () => fmt(new Date());
function getStreak(habitId, completions, freq) {
  let streak = 0,
    d = new Date();
  const step = freq === "weekly" ? 7 : 1;
  while (true) {
    const key = `${habitId}:${fmt(d)}`;
    if (completions[key]) {
      streak++;
      d.setDate(d.getDate() - step);
    } else break;
  }
  return streak;
}
function getLongestStreak(habitId, completions, freq) {
  let max = 0,
    cur = 0;
  const sorted = Object.keys(completions).filter(k => k.startsWith(`${habitId}:`)).map(k => k.split(":")[1]).sort();
  sorted.forEach((d, i) => {
    cur++;
    const next = sorted[i + 1];
    const gap = next ? (new Date(next) - new Date(d)) / 86400000 : 999;
    const expected = freq === "weekly" ? 7 : 1;
    if (gap > expected + 0.5) {
      max = Math.max(max, cur);
      cur = 0;
    }
  });
  return Math.max(max, cur);
}
function getCalendarData(habitCount, completions, year, month) {
  const map = {};
  Object.keys(completions).forEach(k => {
    const [hid, date] = k.split(":");
    const [y, m] = date.split("-").map(Number);
    if (y === year && m === month) {
      map[date] = (map[date] || 0) + 1;
    }
  });
  return map;
}
function computeStats(habits, completions) {
  const td = today();
  const completedToday = habits.filter(h => completions[`${h.id}:${td}`]).length;
  const streaks = habits.map(h => getStreak(h.id, completions, h.freq));
  const longestActive = Math.max(0, ...streaks);
  let perfectDays = 0;
  for (let i = 0; i < 30; i++) {
    const d = new Date();
    d.setDate(d.getDate() - i);
    const ds = fmt(d);
    if (habits.every(h => completions[`${h.id}:${ds}`])) perfectDays++;
  }
  return {
    completedToday,
    total: habits.length,
    longestActive,
    perfectDays
  };
}
function exportCSV(habits, completions) {
  // Fix #5: Warn user the file will be unencrypted plain text before proceeding
  const confirmed = window.confirm("⚠️  Privacy Notice — Export Warning\n\n" + "Your habit data will be saved as an unencrypted plain-text CSV file.\n\n" + "Anyone with access to that file can read your full habit history. " + "Avoid storing it in shared cloud folders or sending it over unencrypted channels.\n\n" + "Continue with export?");
  if (!confirmed) return;
  const td = today();
  const rows = [["ID", "Name", "Icon", "Color", "Frequency", "Description", "Current Streak", "Longest Streak", "Completed Today", "Created At"]];
  habits.forEach(h => {
    rows.push([h.id, h.name, h.icon, h.color, h.freq, h.desc || "", getStreak(h.id, completions, h.freq), getLongestStreak(h.id, completions, h.freq), completions[`${h.id}:${td}`] ? "Yes" : "No", h.createdAt]);
  });
  const notes = [[], ["=== COMPLETION NOTES ==="], ["Habit", "Date", "Note"]];
  Object.entries(completions).forEach(([k, v]) => {
    if (v.note) {
      const [hid, date] = k.split(":");
      const h = habits.find(x => x.id == hid);
      if (h) notes.push([h.name, date, v.note]);
    }
  });
  const csv = [...rows, ...notes].map(r => r.map(c => `"${String(c).replace(/"/g, '""')}"`).join(",")).join("\n");
  const a = Object.assign(document.createElement("a"), {
    href: URL.createObjectURL(new Blob([csv], {
      type: "text/csv"
    })),
    download: `zenflow-${td}.csv`
  });
  a.click();
}

// ─── Confetti ─────────────────────────────────────────────────────────────────
function Confetti({
  active,
  onDone
}) {
  const pieces = useMemo(() => active ? Array.from({
    length: 72
  }, (_, i) => ({
    id: i,
    left: Math.random() * 100,
    color: ["#a855f7", "#f43f5e", "#3b82f6", "#ffd600", "#10b981", "#d946ef", "#f59e0b", "#0ea5e9"][i % 8],
    dur: 1.8 + Math.random() * 1.5,
    sway: 0.7 + Math.random() * 0.8,
    delay: Math.random() * 0.7,
    size: 6 + Math.random() * 9,
    round: Math.random() > 0.5
  })) : [], [active]);
  useEffect(() => {
    if (active && onDone) {
      const t = setTimeout(onDone, 3500);
      return () => clearTimeout(t);
    }
  }, [active, onDone]);
  if (!active) return null;
  return /*#__PURE__*/React.createElement("div", {
    style: {
      position: "fixed",
      inset: 0,
      pointerEvents: "none",
      zIndex: 9999,
      overflow: "hidden"
    }
  }, pieces.map(p => /*#__PURE__*/React.createElement("div", {
    key: p.id,
    style: {
      position: "absolute",
      top: -20,
      left: `${p.left}%`,
      width: p.size,
      height: p.size,
      backgroundColor: p.color,
      borderRadius: p.round ? "50%" : 2,
      animation: `cf-fall ${p.dur}s ${p.delay}s ease-in forwards, cf-sway ${p.sway}s ${p.delay}s ease-in-out infinite`
    }
  })));
}

// ─── Toast ────────────────────────────────────────────────────────────────────
function Toast({
  msg,
  onHide
}) {
  useEffect(() => {
    if (msg) {
      const t = setTimeout(onHide, 3800);
      return () => clearTimeout(t);
    }
  }, [msg, onHide]);
  return /*#__PURE__*/React.createElement("div", {
    style: {
      position: "fixed",
      top: 20,
      right: 20,
      zIndex: 1000,
      background: "var(--card)",
      border: "1px solid var(--primary)",
      borderRadius: 14,
      padding: "12px 16px",
      maxWidth: 280,
      transform: msg ? "translateY(0)" : "translateY(-80px)",
      opacity: msg ? 1 : 0,
      transition: "all .35s cubic-bezier(.34,1.56,.64,1)",
      pointerEvents: msg ? "auto" : "none"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      fontWeight: 600,
      color: "var(--primary)",
      marginBottom: 3,
      fontSize: 13
    }
  }, msg?.title), /*#__PURE__*/React.createElement("div", {
    style: {
      fontSize: 12,
      color: "var(--muted)"
    }
  }, msg?.body));
}

// ─── Pages ────────────────────────────────────────────────────────────────────

function QuoteCard({
  allQuotes
}) {
  const pool = allQuotes && allQuotes.length > 0 ? allQuotes : QUOTES;
  const q = pool[Math.floor(Date.now() / 86400000) % pool.length];
  return /*#__PURE__*/React.createElement("div", {
    style: {
      background: "var(--card)",
      borderRadius: 14,
      border: "1px solid var(--border)",
      borderLeft: "3px solid var(--primary)",
      padding: "14px 16px",
      marginBottom: 20,
      display: "flex",
      gap: 12
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      fontSize: 18,
      flexShrink: 0,
      marginTop: 1
    }
  }, "\uD83D\uDCAC"), /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("div", {
    style: {
      fontSize: 13,
      fontStyle: "italic",
      color: "var(--text)",
      lineHeight: 1.6,
      marginBottom: 5
    }
  }, "\"", q.text, "\""), /*#__PURE__*/React.createElement("div", {
    style: {
      fontSize: 11,
      color: "var(--muted)"
    }
  }, "\u2014 ", q.author)));
}
function StatCards({
  stats
}) {
  const cards = [{
    label: "Today's Progress",
    val: `${stats.completedToday}/${stats.total}`,
    sub: "habits done",
    color: "var(--primary)",
    pct: stats.total ? stats.completedToday / stats.total : 0
  }, {
    label: "Longest Streak",
    val: stats.longestActive,
    sub: "days active",
    color: "#d946ef",
    pct: Math.min(stats.longestActive / 30, 1)
  }, {
    label: "Perfect Days",
    val: stats.perfectDays,
    sub: "this month",
    color: "#ffd600",
    pct: Math.min(stats.perfectDays / 20, 1)
  }];
  return /*#__PURE__*/React.createElement("div", {
    style: {
      display: "grid",
      gridTemplateColumns: "repeat(3,1fr)",
      gap: 10,
      marginBottom: 20
    }
  }, cards.map(c => /*#__PURE__*/React.createElement("div", {
    key: c.label,
    style: {
      background: "var(--card)",
      border: "1px solid var(--border)",
      borderRadius: 14,
      padding: "14px 14px 12px"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      fontSize: 11,
      color: "var(--muted)",
      marginBottom: 6
    }
  }, c.label), /*#__PURE__*/React.createElement("div", {
    style: {
      fontSize: 22,
      fontWeight: 700,
      color: c.color,
      lineHeight: 1
    }
  }, c.val), /*#__PURE__*/React.createElement("div", {
    style: {
      fontSize: 10,
      color: "var(--muted)",
      marginTop: 3,
      marginBottom: 8
    }
  }, c.sub), /*#__PURE__*/React.createElement("div", {
    style: {
      height: 3,
      background: "var(--border)",
      borderRadius: 2,
      overflow: "hidden"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      height: "100%",
      width: `${c.pct * 100}%`,
      background: c.color,
      borderRadius: 2,
      transition: "width .7s ease"
    }
  })))));
}
function MilestoneBadges({
  streak
}) {
  const earned = MILESTONE_DAYS.filter(d => streak >= d);
  if (!earned.length) return null;
  return /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      gap: 5,
      flexWrap: "wrap",
      marginTop: 5
    }
  }, earned.map(d => {
    const m = MILESTONE_META[d];
    return /*#__PURE__*/React.createElement("span", {
      key: d,
      style: {
        fontSize: 10,
        fontWeight: 600,
        padding: "2px 7px",
        borderRadius: 20,
        background: `${m.color}22`,
        color: m.color,
        border: `1px solid ${m.color}44`
      },
      title: m.label
    }, m.icon, " ", d, "d");
  }));
}
function NoteModal({
  habitName,
  existingNote,
  onConfirm,
  onSkip
}) {
  const [note, setNote] = useState(existingNote || "");
  return /*#__PURE__*/React.createElement("div", {
    style: {
      position: "fixed",
      inset: 0,
      background: "#00000070",
      display: "flex",
      alignItems: "center",
      justifyContent: "center",
      zIndex: 500
    },
    onClick: onSkip
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      background: "var(--surface)",
      border: "1px solid var(--border)",
      borderRadius: 18,
      padding: 22,
      width: 320
    },
    onClick: e => e.stopPropagation()
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      alignItems: "center",
      gap: 8,
      marginBottom: 6
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      fontSize: 18
    }
  }, "\uD83D\uDCDD"), /*#__PURE__*/React.createElement("span", {
    style: {
      fontWeight: 600,
      fontSize: 15
    }
  }, "Add a note")), /*#__PURE__*/React.createElement("div", {
    style: {
      fontSize: 12,
      color: "var(--muted)",
      marginBottom: 12
    }
  }, "Anything worth noting about ", /*#__PURE__*/React.createElement("strong", {
    style: {
      color: "var(--text)"
    }
  }, habitName), " today?"), /*#__PURE__*/React.createElement("textarea", {
    autoFocus: true,
    value: note,
    onChange: e => setNote(e.target.value),
    placeholder: "Felt great, nailed it! \uD83D\uDCAA",
    rows: 3,
    style: {
      width: "100%",
      background: "var(--bg)",
      border: "1px solid var(--border)",
      borderRadius: 10,
      color: "var(--text)",
      fontSize: 13,
      padding: "9px 11px",
      resize: "none",
      fontFamily: "inherit",
      boxSizing: "border-box",
      outline: "none"
    },
    onFocus: e => e.target.style.borderColor = "var(--primary)",
    onBlur: e => e.target.style.borderColor = "var(--border)"
  }), /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      gap: 8,
      marginTop: 12,
      justifyContent: "flex-end"
    }
  }, /*#__PURE__*/React.createElement("button", {
    onClick: onSkip,
    style: {
      padding: "7px 16px",
      borderRadius: 20,
      border: "1px solid var(--border)",
      background: "none",
      color: "var(--muted)",
      cursor: "pointer",
      fontSize: 12
    }
  }, "Skip"), /*#__PURE__*/React.createElement("button", {
    onClick: () => onConfirm(note),
    style: {
      padding: "7px 18px",
      borderRadius: 20,
      border: "none",
      background: "var(--primary)",
      color: "#071810",
      cursor: "pointer",
      fontSize: 12,
      fontWeight: 600
    }
  }, "Save & Complete"))));
}

// ─── Premium Dark Weekly Tracker Card ────────────────────────────────────────
const TRACKER_HABITS = [{
  name: "Water",
  accent: "#38bdf8",
  dim: "rgba(56,189,248,.15)",
  border: "rgba(56,189,248,.28)"
}, {
  name: "Workout",
  accent: "#f472b6",
  dim: "rgba(244,114,182,.15)",
  border: "rgba(244,114,182,.28)"
}, {
  name: "Read",
  accent: "#a78bfa",
  dim: "rgba(167,139,250,.15)",
  border: "rgba(167,139,250,.28)"
}, {
  name: "Writing",
  accent: "#34d399",
  dim: "rgba(52,211,153,.15)",
  border: "rgba(52,211,153,.28)"
}, {
  name: "Healthy Eating",
  accent: "#fb923c",
  dim: "rgba(251,146,60,.15)",
  border: "rgba(251,146,60,.28)"
}, {
  name: "Sleep",
  accent: "#818cf8",
  dim: "rgba(129,140,248,.15)",
  border: "rgba(129,140,248,.28)"
}];
const WEEK_DAY_LABELS = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];

// Returns ISO week key like "2026-W22" and the Mon–Sun date strings for this week
function getCurrentWeekInfo() {
  const now = new Date();
  const day = now.getDay(); // 0=Sun..6=Sat
  const monday = new Date(now);
  monday.setDate(now.getDate() - (day + 6) % 7); // roll back to Monday
  monday.setHours(0, 0, 0, 0);
  const dates = Array.from({
    length: 7
  }, (_, i) => {
    const d = new Date(monday);
    d.setDate(monday.getDate() + i);
    return fmt(d);
  });

  // ISO week number
  const jan4 = new Date(monday.getFullYear(), 0, 4);
  const weekNum = Math.ceil(((monday - jan4) / 86400000 + jan4.getDay() + 1) / 7);
  const key = `tracker:${monday.getFullYear()}-W${String(weekNum).padStart(2, "0")}`;
  return {
    key,
    dates,
    monday
  };
}

// Fuzzy-match a tracker row name to a real habit
function matchHabit(trackerName, habits) {
  const t = trackerName.toLowerCase();
  // keywords per tracker row
  const keywords = {
    "water": ["water", "drink", "hydrat"],
    "workout": ["workout", "gym", "run", "exercise", "train", "jog", "walk", "sport", "fit"],
    "read": ["read", "book", "pages"],
    "writing": ["writ", "journal", "diary", "note"],
    "healthy eating": ["eat", "food", "diet", "nutrition", "meal", "veggie", "fruit"],
    "sleep": ["sleep", "bed", "rest", "nap"]
  };
  const kws = keywords[t] ?? [t];
  return habits.filter(h => kws.some(k => h.name.toLowerCase().includes(k)));
}
function WeeklyTrackerCard({
  habits,
  completions
}) {
  const {
    dates
  } = getCurrentWeekInfo();
  const todayStr = fmt(new Date());
  const [todos, setTodos] = useState(Array(7).fill(""));
  const [notes, setNotes] = useState(Array(7).fill(""));
  const {
    key: weekKey
  } = getCurrentWeekInfo();
  const [loaded, setLoaded] = useState(false);

  // Load saved todos/notes for this week
  useEffect(() => {
    (async () => {
      const saved = await persistGet(weekKey, null);
      if (saved) {
        setTodos(saved.todos ?? Array(7).fill(""));
        setNotes(saved.notes ?? Array(7).fill(""));
      } else {
        setTodos(Array(7).fill(""));
        setNotes(Array(7).fill(""));
      }
      setLoaded(true);
    })();
  }, [weekKey]);
  useEffect(() => {
    if (!loaded) return;
    persistSet(weekKey, {
      todos,
      notes
    });
  }, [todos, notes, loaded, weekKey]);

  // Auto-compute grid from real completions — no manual toggle
  const grid = useMemo(() => {
    return TRACKER_HABITS.map(th => {
      const matched = matchHabit(th.name, habits);
      return dates.map(ds => {
        if (matched.length === 0) return false;
        // Tick if ANY matched habit was completed that day
        return matched.some(h => !!completions[`${h.id}:${ds}`]);
      });
    });
  }, [habits, completions, dates]);
  return /*#__PURE__*/React.createElement("div", {
    style: {
      background: "linear-gradient(145deg,#0e0e1a 0%,#111120 60%,#0d0d18 100%)",
      borderRadius: 20,
      padding: "26px 24px 22px",
      border: "1px solid rgba(255,255,255,.07)",
      marginBottom: 24,
      position: "relative",
      overflow: "hidden"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      position: "absolute",
      top: -80,
      right: -60,
      width: 260,
      height: 260,
      borderRadius: "50%",
      background: "radial-gradient(circle,rgba(168,85,247,.12) 0%,transparent 70%)",
      pointerEvents: "none"
    }
  }), /*#__PURE__*/React.createElement("div", {
    style: {
      position: "absolute",
      bottom: -60,
      left: 40,
      width: 200,
      height: 200,
      borderRadius: "50%",
      background: "radial-gradient(circle,rgba(20,184,166,.07) 0%,transparent 70%)",
      pointerEvents: "none"
    }
  }), /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      alignItems: "center",
      justifyContent: "space-between",
      marginBottom: 22,
      position: "relative"
    }
  }, /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("div", {
    style: {
      fontSize: 10,
      fontWeight: 500,
      letterSpacing: "0.14em",
      textTransform: "uppercase",
      color: "rgba(255,255,255,.28)",
      marginBottom: 5
    }
  }, "Weekly"), /*#__PURE__*/React.createElement("div", {
    style: {
      fontFamily: "'Syne', sans-serif",
      fontWeight: 800,
      fontSize: 18,
      letterSpacing: "0.1em",
      textTransform: "uppercase",
      background: "linear-gradient(90deg,#e8e0ff,#c4b5fd,#a78bfa)",
      WebkitBackgroundClip: "text",
      WebkitTextFillColor: "transparent"
    }
  }, "Habit Tracker")), /*#__PURE__*/React.createElement("div", {
    style: {
      fontSize: 10,
      color: "rgba(255,255,255,.25)",
      letterSpacing: ".06em"
    }
  }, dates[0], " \u2013 ", dates[6])), /*#__PURE__*/React.createElement("div", {
    style: {
      display: "grid",
      gridTemplateColumns: "148px repeat(7,1fr)",
      gap: 5,
      marginBottom: 8,
      position: "relative"
    }
  }, /*#__PURE__*/React.createElement("div", null), dates.map((ds, i) => {
    const isToday = ds === todayStr;
    const isFuture = ds > todayStr;
    return /*#__PURE__*/React.createElement("div", {
      key: i,
      style: {
        textAlign: "center"
      }
    }, /*#__PURE__*/React.createElement("div", {
      style: {
        fontSize: 9,
        fontWeight: 500,
        color: isToday ? "#a78bfa" : "rgba(255,255,255,.25)",
        letterSpacing: "0.08em",
        marginBottom: 2
      }
    }, WEEK_DAY_LABELS[i]), /*#__PURE__*/React.createElement("div", {
      style: {
        fontSize: 11,
        fontWeight: isToday ? 700 : 400,
        color: isToday ? "#a78bfa" : isFuture ? "rgba(255,255,255,.15)" : "rgba(255,255,255,.45)",
        background: isToday ? "rgba(167,139,250,.15)" : "transparent",
        borderRadius: 6,
        padding: "1px 0"
      }
    }, new Date(ds + "T12:00:00").getDate()));
  })), /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      flexDirection: "column",
      gap: 5,
      position: "relative"
    }
  }, TRACKER_HABITS.map((h, ri) => /*#__PURE__*/React.createElement("div", {
    key: h.name,
    style: {
      display: "grid",
      gridTemplateColumns: "148px repeat(7,1fr)",
      gap: 5,
      alignItems: "center"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      background: h.dim,
      borderRadius: 9,
      padding: "7px 13px",
      fontSize: 11,
      fontWeight: 500,
      letterSpacing: "0.06em",
      textTransform: "uppercase",
      color: h.accent,
      border: `1px solid ${h.border}`
    }
  }, h.name), dates.map((ds, ci) => {
    const checked = grid[ri]?.[ci] ?? false;
    const isFuture = ds > todayStr;
    const isToday = ds === todayStr;
    const matched = matchHabit(h.name, habits);
    const hasMatch = matched.length > 0;
    return /*#__PURE__*/React.createElement("div", {
      key: ci,
      title: !hasMatch ? `No habit matched for "${h.name}" — add one in All Habits` : checked ? "Completed ✓" : isFuture ? "Future" : "Not done",
      style: {
        width: 30,
        height: 30,
        borderRadius: "50%",
        margin: "0 auto",
        border: `1.5px solid ${checked ? h.accent : isToday ? "rgba(255,255,255,.2)" : "rgba(255,255,255,.1)"}`,
        background: checked ? h.dim : isToday ? "rgba(255,255,255,.04)" : "rgba(255,255,255,.02)",
        cursor: "default",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        opacity: isFuture ? 0.25 : !hasMatch ? 0.2 : 1,
        transition: "all .18s ease",
        boxShadow: checked ? `0 0 10px -3px ${h.accent}60` : "none"
      }
    }, checked && /*#__PURE__*/React.createElement("svg", {
      width: "13",
      height: "13",
      viewBox: "0 0 14 14",
      fill: "none"
    }, /*#__PURE__*/React.createElement("path", {
      d: "M2.5 7L5.5 10L11.5 4",
      stroke: h.accent,
      strokeWidth: "1.8",
      strokeLinecap: "round",
      strokeLinejoin: "round"
    })));
  })))), /*#__PURE__*/React.createElement("div", {
    style: {
      height: 1,
      background: "linear-gradient(90deg,transparent,rgba(255,255,255,.08) 30%,rgba(255,255,255,.08) 70%,transparent)",
      margin: "20px 0",
      position: "relative"
    }
  }), /*#__PURE__*/React.createElement("div", {
    style: {
      display: "grid",
      gridTemplateColumns: "1fr 1fr",
      gap: 24,
      position: "relative"
    }
  }, [["To Do List", todos, setTodos], ["Notes", notes, setNotes]].map(([title, lines, setLines]) => /*#__PURE__*/React.createElement("div", {
    key: title
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      fontFamily: "'Syne', sans-serif",
      fontSize: 10,
      fontWeight: 700,
      letterSpacing: "0.15em",
      textTransform: "uppercase",
      color: "rgba(255,255,255,.3)",
      marginBottom: 10
    }
  }, title), lines.map((line, i) => /*#__PURE__*/React.createElement("div", {
    key: i,
    style: {
      display: "flex",
      alignItems: "center",
      gap: 8,
      borderBottom: "1px solid rgba(255,255,255,.055)",
      padding: "5px 0"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      width: 4,
      height: 4,
      borderRadius: "50%",
      background: "rgba(167,139,250,.45)",
      flexShrink: 0
    }
  }), /*#__PURE__*/React.createElement("input", {
    value: line,
    onChange: e => setLines(l => l.map((v, j) => j === i ? e.target.value : v)),
    placeholder: "...",
    style: {
      border: "none",
      background: "transparent",
      color: "rgba(255,255,255,.7)",
      fontSize: 12,
      fontWeight: 300,
      flex: 1,
      outline: "none",
      fontFamily: "'DM Sans', sans-serif",
      caretColor: "rgba(167,139,250,.9)"
    }
  })))))));
}

// ─── Weekly Report Modal ──────────────────────────────────────────────────────
function WeeklyReportModal({
  report,
  onClose
}) {
  if (!report) return null;
  const {
    days,
    rate,
    best,
    total,
    maxPossible,
    perfectDays,
    weekNum
  } = report;
  const pct = Math.round(rate * 100);
  const grade = pct >= 90 ? {
    label: "Outstanding",
    icon: "🏆",
    color: "#00ff9f"
  } : pct >= 70 ? {
    label: "Great Week",
    icon: "🌟",
    color: "#3b82f6"
  } : pct >= 50 ? {
    label: "Solid Effort",
    icon: "💪",
    color: "#a855f7"
  } : {
    label: "Keep Going",
    icon: "🔥",
    color: "#f59e0b"
  };
  return /*#__PURE__*/React.createElement("div", {
    style: {
      position: "fixed",
      inset: 0,
      background: "rgba(0,0,0,.75)",
      zIndex: 999,
      display: "flex",
      alignItems: "center",
      justifyContent: "center",
      padding: 20
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      background: "var(--card)",
      border: "1px solid var(--border)",
      borderRadius: 20,
      padding: 28,
      maxWidth: 420,
      width: "100%",
      boxShadow: "0 24px 80px #000a"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      textAlign: "center",
      marginBottom: 22
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      fontSize: 48,
      marginBottom: 8
    }
  }, grade.icon), /*#__PURE__*/React.createElement("div", {
    style: {
      fontSize: 22,
      fontWeight: 800,
      letterSpacing: "-0.5px"
    }
  }, "Week ", weekNum, " Recap"), /*#__PURE__*/React.createElement("div", {
    style: {
      fontSize: 13,
      color: "var(--muted)",
      marginTop: 4
    }
  }, grade.label)), /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      justifyContent: "center",
      marginBottom: 22
    }
  }, /*#__PURE__*/React.createElement(DonutChart, {
    pct: rate,
    color: grade.color,
    size: 110,
    label: `${pct}%`,
    sub: "completion"
  })), /*#__PURE__*/React.createElement("div", {
    style: {
      display: "grid",
      gridTemplateColumns: "repeat(3,1fr)",
      gap: 8,
      marginBottom: 20
    }
  }, [{
    icon: "✅",
    val: total,
    label: "Check-ins"
  }, {
    icon: "⭐",
    val: perfectDays,
    label: "Perfect Days"
  }, {
    icon: "🔥",
    val: best?.label ?? "—",
    label: "Best Day"
  }].map(s => /*#__PURE__*/React.createElement("div", {
    key: s.label,
    style: {
      background: "var(--bg)",
      borderRadius: 12,
      padding: "12px 8px",
      textAlign: "center"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      fontSize: 18
    }
  }, s.icon), /*#__PURE__*/React.createElement("div", {
    style: {
      fontSize: 18,
      fontWeight: 700,
      color: grade.color,
      marginTop: 2
    }
  }, s.val), /*#__PURE__*/React.createElement("div", {
    style: {
      fontSize: 10,
      color: "var(--muted)",
      marginTop: 2
    }
  }, s.label)))), /*#__PURE__*/React.createElement("div", {
    style: {
      marginBottom: 22
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      fontSize: 10,
      fontWeight: 600,
      color: "var(--muted)",
      textTransform: "uppercase",
      letterSpacing: ".08em",
      marginBottom: 10
    }
  }, "Day by Day"), /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      gap: 4,
      alignItems: "flex-end",
      height: 56
    }
  }, days.map((d, i) => {
    const h = d.total > 0 ? d.done / d.total * 48 : 0;
    const col = d.done === d.total && d.total > 0 ? "#00ff9f" : d.done > 0 ? grade.color : "rgba(255,255,255,.08)";
    return /*#__PURE__*/React.createElement("div", {
      key: i,
      style: {
        flex: 1,
        display: "flex",
        flexDirection: "column",
        alignItems: "center",
        gap: 3
      }
    }, /*#__PURE__*/React.createElement("div", {
      style: {
        width: "100%",
        height: `${Math.max(h, d.done > 0 ? 6 : 3)}px`,
        background: col,
        borderRadius: 3,
        transition: "height .5s ease"
      }
    }), /*#__PURE__*/React.createElement("span", {
      style: {
        fontSize: 9,
        color: "var(--muted)"
      }
    }, d.label));
  }))), /*#__PURE__*/React.createElement("div", {
    style: {
      background: `${grade.color}12`,
      border: `1px solid ${grade.color}30`,
      borderRadius: 12,
      padding: "12px 14px",
      marginBottom: 20,
      fontSize: 12,
      color: "var(--text)",
      lineHeight: 1.5,
      textAlign: "center"
    }
  }, pct >= 90 ? "You crushed it this week. Incredible consistency — keep that momentum going! 🚀" : pct >= 70 ? "Strong week! You're building real habits. A little more consistency and you'll be unstoppable." : pct >= 50 ? "More than halfway there. Every check-in counts — push a little harder next week!" : "Every journey starts somewhere. Show up tomorrow and build from here — you've got this."), /*#__PURE__*/React.createElement("button", {
    onClick: onClose,
    style: {
      width: "100%",
      padding: "13px",
      borderRadius: 12,
      border: "none",
      background: grade.color,
      color: "#000",
      fontWeight: 700,
      fontSize: 14,
      cursor: "pointer",
      letterSpacing: ".02em"
    }
  }, "Start New Week \uD83D\uDCAA")));
}

// ─── Infographic Panel ────────────────────────────────────────────────────────
function InfographicPanel({
  habits,
  completions,
  last7,
  totalCompletions,
  bestStreak
}) {
  const now = new Date();
  const td = fmt(now);

  // Percent callouts
  const weekRate = last7 ? Math.round(last7.reduce((s, d) => s + d.val, 0) / 7) : 0;
  const todayDone = habits.filter(h => completions[`${h.id}:${td}`]).length;
  const todayPct = habits.length ? Math.round(todayDone / habits.length * 100) : 0;

  // Last 7 days timeline steps
  const steps = last7 ? last7 : [];

  // People chart — out of 10 people, how many days did you complete all habits?
  const last30Days = Array.from({
    length: 30
  }, (_, i) => {
    const d = new Date(now);
    d.setDate(d.getDate() - (29 - i));
    const ds = fmt(d);
    return habits.length > 0 && habits.every(h => completions[`${h.id}:${ds}`]);
  });
  const perfectDays30 = last30Days.filter(Boolean).length;
  const peopleRatio = Math.round(perfectDays30 / 3); // out of 10

  // Pyramid tiers
  const habitRates = habits.map(h => {
    const done = Object.keys(completions).filter(k => k.startsWith(`${h.id}:`)).length;
    const days = Math.max(1, Math.ceil((now - new Date(h.createdAt || now)) / 86400000));
    return {
      ...h,
      rate: Math.min(done / days, 1)
    };
  }).sort((a, b) => b.rate - a.rate);
  const TIER_COLORS = ["#f59e0b", "#3b82f6", "#a855f7", "#2ecc98", "#f43f5e"];
  return /*#__PURE__*/React.createElement("div", {
    style: {
      background: "var(--card)",
      border: "1px solid var(--border)",
      borderRadius: 14,
      padding: 18,
      marginTop: 10
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      fontSize: 10,
      fontWeight: 700,
      color: "var(--muted)",
      letterSpacing: ".12em",
      textTransform: "uppercase",
      marginBottom: 16
    }
  }, "Progress Infographic"), /*#__PURE__*/React.createElement("div", {
    style: {
      display: "grid",
      gridTemplateColumns: "1fr 1fr 1fr",
      gap: 10,
      marginBottom: 16
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      background: "var(--bg)",
      borderRadius: 12,
      padding: "14px 10px",
      textAlign: "center",
      position: "relative",
      overflow: "hidden"
    }
  }, /*#__PURE__*/React.createElement("svg", {
    width: 60,
    height: 60,
    style: {
      display: "block",
      margin: "0 auto 6px"
    }
  }, /*#__PURE__*/React.createElement("circle", {
    cx: 30,
    cy: 30,
    r: 24,
    fill: "none",
    stroke: "rgba(255,255,255,.08)",
    strokeWidth: 5
  }), /*#__PURE__*/React.createElement("circle", {
    cx: 30,
    cy: 30,
    r: 24,
    fill: "none",
    stroke: "#2ecc98",
    strokeWidth: 5,
    strokeDasharray: `${todayPct / 100 * 150.8} 150.8`,
    strokeLinecap: "round",
    transform: "rotate(-90 30 30)",
    style: {
      transition: "stroke-dasharray .8s ease"
    }
  }), /*#__PURE__*/React.createElement("text", {
    x: 30,
    y: 34,
    textAnchor: "middle",
    fontSize: 11,
    fontWeight: 700,
    fill: "#2ecc98"
  }, todayPct, "%")), /*#__PURE__*/React.createElement("div", {
    style: {
      fontSize: 10,
      color: "var(--muted)",
      lineHeight: 1.3
    }
  }, "Today")), /*#__PURE__*/React.createElement("div", {
    style: {
      background: "var(--bg)",
      borderRadius: 12,
      padding: "14px 10px",
      textAlign: "center"
    }
  }, /*#__PURE__*/React.createElement("svg", {
    width: 60,
    height: 60,
    style: {
      display: "block",
      margin: "0 auto 6px"
    }
  }, /*#__PURE__*/React.createElement("circle", {
    cx: 30,
    cy: 30,
    r: 24,
    fill: "none",
    stroke: "rgba(255,255,255,.08)",
    strokeWidth: 5
  }), /*#__PURE__*/React.createElement("circle", {
    cx: 30,
    cy: 30,
    r: 24,
    fill: "none",
    stroke: "#a855f7",
    strokeWidth: 5,
    strokeDasharray: `${weekRate / 100 * 150.8} 150.8`,
    strokeLinecap: "round",
    transform: "rotate(-90 30 30)",
    style: {
      transition: "stroke-dasharray .8s ease"
    }
  }), /*#__PURE__*/React.createElement("text", {
    x: 30,
    y: 34,
    textAnchor: "middle",
    fontSize: 11,
    fontWeight: 700,
    fill: "#a855f7"
  }, weekRate, "%")), /*#__PURE__*/React.createElement("div", {
    style: {
      fontSize: 10,
      color: "var(--muted)",
      lineHeight: 1.3
    }
  }, "This Week")), /*#__PURE__*/React.createElement("div", {
    style: {
      background: "var(--bg)",
      borderRadius: 12,
      padding: "14px 10px",
      textAlign: "center",
      display: "flex",
      flexDirection: "column",
      alignItems: "center",
      justifyContent: "center"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      fontSize: 28,
      fontWeight: 800,
      color: "#f59e0b",
      lineHeight: 1
    }
  }, bestStreak), /*#__PURE__*/React.createElement("div", {
    style: {
      fontSize: 9,
      color: "#f59e0b",
      letterSpacing: ".08em",
      textTransform: "uppercase",
      marginTop: 2
    }
  }, "Day Streak"), /*#__PURE__*/React.createElement("div", {
    style: {
      fontSize: 9,
      color: "var(--muted)",
      marginTop: 4
    }
  }, "personal best"))), steps.length > 0 && /*#__PURE__*/React.createElement("div", {
    style: {
      marginBottom: 16
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      fontSize: 9,
      color: "var(--muted)",
      letterSpacing: ".1em",
      textTransform: "uppercase",
      marginBottom: 8
    }
  }, "7-Day Timeline"), /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      alignItems: "flex-end",
      gap: 0
    }
  }, steps.map((s, i) => {
    const pct = s.val ?? 0;
    const color = pct >= 100 ? "#2ecc98" : pct >= 60 ? "#3b82f6" : pct >= 30 ? "#f59e0b" : "rgba(255,255,255,.12)";
    const isToday = s.highlight;
    return /*#__PURE__*/React.createElement("div", {
      key: i,
      style: {
        flex: 1,
        display: "flex",
        flexDirection: "column",
        alignItems: "center"
      }
    }, /*#__PURE__*/React.createElement("div", {
      style: {
        width: "100%",
        height: 28,
        background: color,
        position: "relative",
        clipPath: i === 6 ? "none" : "polygon(0 0, calc(100% - 6px) 0, 100% 50%, calc(100% - 6px) 100%, 0 100%)",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        border: isToday ? `1px solid ${color}` : "none",
        boxShadow: isToday ? `0 0 8px ${color}60` : "none"
      }
    }, /*#__PURE__*/React.createElement("span", {
      style: {
        fontSize: 9,
        fontWeight: 700,
        color: pct >= 30 ? "#000" : "var(--muted)"
      }
    }, Math.round(pct), "%")), /*#__PURE__*/React.createElement("div", {
      style: {
        fontSize: 8,
        color: isToday ? "#2ecc98" : "var(--muted)",
        marginTop: 3,
        fontWeight: isToday ? 700 : 400
      }
    }, s.label));
  }))), /*#__PURE__*/React.createElement("div", {
    style: {
      display: "grid",
      gridTemplateColumns: "1fr 1fr",
      gap: 12
    }
  }, /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("div", {
    style: {
      fontSize: 9,
      color: "var(--muted)",
      letterSpacing: ".1em",
      textTransform: "uppercase",
      marginBottom: 8
    }
  }, "Top Habits"), /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      flexDirection: "column",
      gap: 3
    }
  }, habitRates.slice(0, 5).map((h, i) => {
    const widths = ["100%", "82%", "64%", "46%", "30%"];
    return /*#__PURE__*/React.createElement("div", {
      key: h.id,
      style: {
        display: "flex",
        alignItems: "center",
        gap: 6
      }
    }, /*#__PURE__*/React.createElement("div", {
      style: {
        height: 18,
        width: widths[i],
        background: TIER_COLORS[i],
        borderRadius: 3,
        display: "flex",
        alignItems: "center",
        paddingLeft: 6,
        transition: "width .6s ease"
      }
    }, /*#__PURE__*/React.createElement("span", {
      style: {
        fontSize: 9,
        fontWeight: 700,
        color: "#000",
        whiteSpace: "nowrap",
        overflow: "hidden"
      }
    }, h.icon, " ", h.name)), /*#__PURE__*/React.createElement("span", {
      style: {
        fontSize: 9,
        color: TIER_COLORS[i],
        fontWeight: 700,
        flexShrink: 0
      }
    }, Math.round(h.rate * 100), "%"));
  }), habits.length === 0 && /*#__PURE__*/React.createElement("div", {
    style: {
      fontSize: 11,
      color: "var(--muted)"
    }
  }, "No habits yet"))), /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("div", {
    style: {
      fontSize: 9,
      color: "var(--muted)",
      letterSpacing: ".1em",
      textTransform: "uppercase",
      marginBottom: 8
    }
  }, "Perfect Days ", /*#__PURE__*/React.createElement("span", {
    style: {
      color: "#3b82f6"
    }
  }, peopleRatio, "/10"), " ", /*#__PURE__*/React.createElement("span", {
    style: {
      fontStyle: "italic",
      textTransform: "none"
    }
  }, "(last 30d)")), /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      flexWrap: "wrap",
      gap: 4
    }
  }, Array.from({
    length: 10
  }, (_, i) => /*#__PURE__*/React.createElement("div", {
    key: i,
    style: {
      fontSize: 16,
      opacity: i < peopleRatio ? 1 : 0.18,
      filter: i < peopleRatio ? "none" : "grayscale(1)"
    }
  }, "\uD83D\uDC64"))), /*#__PURE__*/React.createElement("div", {
    style: {
      fontSize: 9,
      color: "var(--muted)",
      marginTop: 6,
      lineHeight: 1.5
    }
  }, perfectDays30, " out of 30 days you completed every habit"))), /*#__PURE__*/React.createElement("div", {
    style: {
      marginTop: 16,
      background: "var(--bg)",
      borderRadius: 10,
      padding: "12px 16px",
      display: "flex",
      alignItems: "center",
      gap: 14
    }
  }, /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("div", {
    style: {
      fontSize: 32,
      fontWeight: 800,
      color: "var(--primary)",
      lineHeight: 1
    }
  }, totalCompletions), /*#__PURE__*/React.createElement("div", {
    style: {
      fontSize: 9,
      color: "var(--muted)",
      textTransform: "uppercase",
      letterSpacing: ".1em",
      marginTop: 2
    }
  }, "Total Check-ins")), /*#__PURE__*/React.createElement("div", {
    style: {
      flex: 1,
      height: 2,
      background: "var(--border)",
      borderRadius: 1,
      position: "relative"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      position: "absolute",
      left: 0,
      top: 0,
      height: "100%",
      width: `${Math.min(weekRate, 100)}%`,
      background: "var(--primary)",
      borderRadius: 1,
      transition: "width .8s ease"
    }
  })), /*#__PURE__*/React.createElement("div", {
    style: {
      textAlign: "right"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      fontSize: 32,
      fontWeight: 800,
      color: "#f59e0b",
      lineHeight: 1
    }
  }, weekRate, "%"), /*#__PURE__*/React.createElement("div", {
    style: {
      fontSize: 9,
      color: "var(--muted)",
      textTransform: "uppercase",
      letterSpacing: ".1em",
      marginTop: 2
    }
  }, "Week Rate"))));
}
function InlineAnalytics({
  habits,
  completions
}) {
  const now = new Date();
  const td = today();
  const last7 = Array.from({
    length: 7
  }, (_, i) => {
    const d = new Date(now);
    d.setDate(d.getDate() - (6 - i));
    const ds = fmt(d);
    const done = habits.filter(h => completions[`${h.id}:${ds}`]).length;
    const labels = ["Su", "Mo", "Tu", "We", "Th", "Fr", "Sa"];
    return {
      label: labels[d.getDay()],
      val: habits.length ? done / habits.length * 100 : 0,
      highlight: ds === td
    };
  });
  const last30 = Array.from({
    length: 30
  }, (_, i) => {
    const d = new Date(now);
    d.setDate(d.getDate() - (29 - i));
    return habits.filter(h => completions[`${h.id}:${fmt(d)}`]).length;
  });
  const habitRates = habits.map(h => {
    const total = Object.keys(completions).filter(k => k.startsWith(`${h.id}:`)).length;
    const days = Math.max(1, Math.ceil((now - new Date(h.createdAt)) / 86400000));
    const expected = h.freq === "weekly" ? Math.ceil(days / 7) : days;
    return {
      ...h,
      rate: Math.min(total / expected, 1),
      total
    };
  }).sort((a, b) => b.rate - a.rate);
  const totalCompletions = Object.keys(completions).length;
  const overallRate = last7.reduce((s, d) => s + d.val, 0) / 7;
  const bestStreak = Math.max(0, ...habits.map(h => getLongestStreak(h.id, completions, h.freq)));

  // heatmap: 8 weeks
  const heatCells = Array.from({
    length: 56
  }, (_, i) => {
    const d = new Date(now);
    d.setDate(d.getDate() - (55 - i));
    const ds = fmt(d);
    const done = habits.filter(h => completions[`${h.id}:${ds}`]).length;
    const pct = habits.length ? done / habits.length : 0;
    return {
      ds,
      pct,
      isFuture: ds > td
    };
  });
  const heatColor = (pct, future) => {
    if (future || pct === 0) return "rgba(255,255,255,.05)";
    if (pct >= 1) return "#00ff9f";
    if (pct >= .75) return "#3b82f6";
    if (pct >= .5) return "#a855f7";
    return "#ffd600";
  };
  return /*#__PURE__*/React.createElement("div", {
    style: {
      marginTop: 28
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      fontSize: 11,
      fontWeight: 600,
      color: "var(--muted)",
      letterSpacing: "0.1em",
      textTransform: "uppercase",
      marginBottom: 12
    }
  }, "Analytics"), /*#__PURE__*/React.createElement("div", {
    style: {
      display: "grid",
      gridTemplateColumns: "repeat(3,1fr)",
      gap: 8,
      marginBottom: 10
    }
  }, [{
    label: "Check-ins",
    val: totalCompletions,
    color: "#2ecc98",
    icon: "✅"
  }, {
    label: "Week avg",
    val: `${Math.round(overallRate)}%`,
    color: "#3b82f6",
    icon: "📈"
  }, {
    label: "Best streak",
    val: `${bestStreak}d`,
    color: "#f59e0b",
    icon: "🏆"
  }].map(c => /*#__PURE__*/React.createElement("div", {
    key: c.label,
    style: {
      background: "var(--card)",
      border: "1px solid var(--border)",
      borderRadius: 12,
      padding: "12px 10px"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      fontSize: 16,
      marginBottom: 3
    }
  }, c.icon), /*#__PURE__*/React.createElement("div", {
    style: {
      fontSize: 18,
      fontWeight: 700,
      color: c.color
    }
  }, c.val), /*#__PURE__*/React.createElement("div", {
    style: {
      fontSize: 10,
      color: "var(--muted)",
      marginTop: 2
    }
  }, c.label)))), /*#__PURE__*/React.createElement("div", {
    style: {
      display: "grid",
      gridTemplateColumns: "1fr 1fr",
      gap: 8,
      marginBottom: 10
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      background: "var(--card)",
      border: "1px solid var(--border)",
      borderRadius: 12,
      padding: 14
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      fontSize: 10,
      fontWeight: 600,
      color: "var(--muted)",
      letterSpacing: ".08em",
      textTransform: "uppercase",
      marginBottom: 10
    }
  }, "This Week"), /*#__PURE__*/React.createElement(MiniBarChart, {
    data: last7,
    color: "#2ecc98",
    maxVal: 100
  })), /*#__PURE__*/React.createElement("div", {
    style: {
      background: "var(--card)",
      border: "1px solid var(--border)",
      borderRadius: 12,
      padding: 14
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      fontSize: 10,
      fontWeight: 600,
      color: "var(--muted)",
      letterSpacing: ".08em",
      textTransform: "uppercase",
      marginBottom: 10
    }
  }, "30-Day Trend"), /*#__PURE__*/React.createElement(SparkLine, {
    data: last30,
    color: "#a855f7",
    width: 130,
    height: 52
  }))), /*#__PURE__*/React.createElement("div", {
    style: {
      background: "var(--card)",
      border: "1px solid var(--border)",
      borderRadius: 12,
      padding: 14,
      marginBottom: 10
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      fontSize: 10,
      fontWeight: 600,
      color: "var(--muted)",
      letterSpacing: ".08em",
      textTransform: "uppercase",
      marginBottom: 14
    }
  }, "Completion by Habit"), /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      gap: 16,
      flexWrap: "wrap",
      justifyContent: "center"
    }
  }, habitRates.slice(0, 6).map(h => /*#__PURE__*/React.createElement(DonutChart, {
    key: h.id,
    pct: h.rate,
    color: h.color,
    size: 72,
    label: h.name.split(" ").slice(0, 2).join(" "),
    sub: `${h.total}×`
  })))), /*#__PURE__*/React.createElement("div", {
    style: {
      background: "var(--card)",
      border: "1px solid var(--border)",
      borderRadius: 12,
      padding: 14,
      marginBottom: 10
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      fontSize: 10,
      fontWeight: 600,
      color: "var(--muted)",
      letterSpacing: ".08em",
      textTransform: "uppercase",
      marginBottom: 12
    }
  }, "Habit Rankings"), /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      flexDirection: "column",
      gap: 9
    }
  }, habitRates.map(h => /*#__PURE__*/React.createElement("div", {
    key: h.id
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      justifyContent: "space-between",
      marginBottom: 3
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      fontSize: 12
    }
  }, h.icon, " ", h.name), /*#__PURE__*/React.createElement("span", {
    style: {
      fontSize: 12,
      fontWeight: 700,
      color: h.color
    }
  }, Math.round(h.rate * 100), "%")), /*#__PURE__*/React.createElement("div", {
    style: {
      height: 5,
      background: "var(--border)",
      borderRadius: 3,
      overflow: "hidden"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      height: "100%",
      width: `${h.rate * 100}%`,
      background: `linear-gradient(90deg,${h.color}88,${h.color})`,
      borderRadius: 3,
      transition: "width .7s ease"
    }
  })))))), /*#__PURE__*/React.createElement(InfographicPanel, {
    habits: habits,
    completions: completions,
    last7: last7,
    totalCompletions: totalCompletions,
    bestStreak: bestStreak
  }));
}
function HomePage({
  habits,
  completions,
  onToggle,
  toast,
  allQuotes
}) {
  const [noteFor, setNoteFor] = useState(null);
  const td = today();
  const stats = useMemo(() => computeStats(habits, completions), [habits, completions]);
  const handleCheck = h => {
    if (completions[`${h.id}:${td}`]) {
      onToggle(h.id, td, null);
      return;
    }
    setNoteFor(h);
  };
  const confirmNote = note => {
    onToggle(noteFor.id, td, note);
    setNoteFor(null);
  };
  const greeting = (() => {
    const hr = new Date().getHours();
    return hr < 12 ? "Good morning" : hr < 18 ? "Good afternoon" : "Good evening";
  })();
  return /*#__PURE__*/React.createElement("div", null, noteFor && /*#__PURE__*/React.createElement(NoteModal, {
    habitName: noteFor.name,
    existingNote: "",
    onConfirm: confirmNote,
    onSkip: () => setNoteFor(null)
  }), /*#__PURE__*/React.createElement("div", {
    style: {
      marginBottom: 20
    }
  }, /*#__PURE__*/React.createElement("h1", {
    style: {
      fontSize: 28,
      fontWeight: 800,
      margin: "0 0 4px",
      letterSpacing: "-0.5px"
    }
  }, greeting, "."), /*#__PURE__*/React.createElement("div", {
    style: {
      color: "var(--muted)",
      fontSize: 13
    }
  }, new Date().toLocaleDateString("en-US", {
    weekday: "long",
    month: "long",
    day: "numeric"
  }))), /*#__PURE__*/React.createElement(QuoteCard, {
    allQuotes: allQuotes
  }), /*#__PURE__*/React.createElement(StatCards, {
    stats: stats
  }), /*#__PURE__*/React.createElement(WeeklyTrackerCard, {
    habits: habits,
    completions: completions
  }), /*#__PURE__*/React.createElement("div", {
    style: {
      fontSize: 11,
      fontWeight: 600,
      color: "var(--muted)",
      letterSpacing: "0.1em",
      textTransform: "uppercase",
      marginBottom: 10
    }
  }, "Today's Habits"), /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      flexDirection: "column",
      gap: 8
    }
  }, habits.map(h => {
    const done = !!completions[`${h.id}:${td}`];
    const note = completions[`${h.id}:${td}`]?.note;
    const streak = getStreak(h.id, completions, h.freq);
    return /*#__PURE__*/React.createElement("div", {
      key: h.id,
      style: {
        background: done ? `${h.color}12` : "var(--card)",
        border: `1px solid ${done ? h.color + "30" : "var(--border)"}`,
        borderRadius: 14,
        padding: "13px 15px",
        display: "flex",
        alignItems: "center",
        gap: 13,
        transition: "all .2s"
      }
    }, /*#__PURE__*/React.createElement("button", {
      onClick: () => handleCheck(h),
      style: {
        width: 38,
        height: 38,
        borderRadius: "50%",
        flexShrink: 0,
        border: done ? "none" : `2px solid ${h.color}50`,
        background: done ? h.color : "transparent",
        cursor: "pointer",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        fontSize: 16,
        transition: "all .2s",
        boxShadow: done ? `0 0 14px ${h.color}50` : "none"
      },
      "aria-label": `Toggle ${h.name}`
    }, done ? "✓" : ""), /*#__PURE__*/React.createElement("div", {
      style: {
        flex: 1,
        minWidth: 0
      }
    }, /*#__PURE__*/React.createElement("div", {
      style: {
        fontWeight: 600,
        fontSize: 14,
        marginBottom: note ? 3 : 0
      }
    }, h.icon, " ", h.name), note && /*#__PURE__*/React.createElement("div", {
      style: {
        fontSize: 11,
        color: "var(--muted)",
        fontStyle: "italic"
      }
    }, "\uD83D\uDCDD ", note), /*#__PURE__*/React.createElement(MilestoneBadges, {
      streak: streak
    })), streak > 0 && /*#__PURE__*/React.createElement("div", {
      style: {
        display: "flex",
        alignItems: "center",
        gap: 5,
        background: "var(--bg)",
        padding: "4px 10px",
        borderRadius: 20,
        fontSize: 12,
        color: streak >= 7 ? "#d946ef" : "var(--muted)",
        flexShrink: 0
      }
    }, "\uD83D\uDD25 ", streak, "d"));
  }), habits.length === 0 && /*#__PURE__*/React.createElement("div", {
    style: {
      textAlign: "center",
      padding: "40px 20px",
      color: "var(--muted)",
      border: "1px dashed var(--border)",
      borderRadius: 14
    }
  }, "No habits yet \u2014 create your first one!")), habits.length > 0 && /*#__PURE__*/React.createElement(InlineAnalytics, {
    habits: habits,
    completions: completions
  }));
}
function CalendarPage({
  habits,
  completions
}) {
  const [viewDate, setViewDate] = useState(new Date());
  const [selected, setSelected] = useState(null);
  const td = today();
  const year = viewDate.getFullYear(),
    month = viewDate.getMonth() + 1;
  const calData = useMemo(() => getCalendarData(habits.length, completions, year, month), [completions, year, month]);
  const total = habits.length;
  const firstDay = new Date(year, month - 1, 1);
  const daysInMonth = new Date(year, month, 0).getDate();
  const startOffset = (firstDay.getDay() + 6) % 7;
  const monthDays = Array.from({
    length: daysInMonth
  }, (_, i) => {
    const d = i + 1;
    return `${year}-${String(month).padStart(2, "0")}-${String(d).padStart(2, "0")}`;
  });
  const pastDays = monthDays.filter(d => d <= td);
  const perfectCount = pastDays.filter(d => (calData[d] || 0) >= total && total > 0).length;
  const totalComp = pastDays.reduce((s, d) => s + (calData[d] || 0), 0);
  const avgRate = pastDays.length && total ? Math.round(pastDays.reduce((s, d) => s + (calData[d] || 0) / total, 0) / pastDays.length * 100) : 0;
  const getColor = (count, isFuture) => {
    if (isFuture || !count) return null;
    const r = count / total;
    if (r >= 1) return "#00ff9f";
    if (r >= 0.75) return "#3b82f6";
    if (r >= 0.5) return "#a855f7";
    return "#ffd600";
  };
  return /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("div", {
    style: {
      marginBottom: 20
    }
  }, /*#__PURE__*/React.createElement("h1", {
    style: {
      fontSize: 28,
      fontWeight: 800,
      margin: "0 0 4px",
      letterSpacing: "-0.5px"
    }
  }, "Monthly Calendar"), /*#__PURE__*/React.createElement("div", {
    style: {
      color: "var(--muted)",
      fontSize: 13
    }
  }, "See your full month at a glance.")), /*#__PURE__*/React.createElement("div", {
    style: {
      display: "grid",
      gridTemplateColumns: "repeat(3,1fr)",
      gap: 10,
      marginBottom: 16
    }
  }, [["Perfect Days", perfectCount, "#00ff9f"], ["Total Completions", totalComp, "#3b82f6"], ["Avg. Rate", `${avgRate}%`, "#a855f7"]].map(([l, v, c]) => /*#__PURE__*/React.createElement("div", {
    key: l,
    style: {
      background: "var(--card)",
      border: "1px solid var(--border)",
      borderRadius: 14,
      padding: "14px",
      textAlign: "center"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      fontSize: 22,
      fontWeight: 700,
      color: c
    }
  }, v), /*#__PURE__*/React.createElement("div", {
    style: {
      fontSize: 11,
      color: "var(--muted)",
      marginTop: 4
    }
  }, l)))), /*#__PURE__*/React.createElement("div", {
    style: {
      background: "var(--card)",
      border: "1px solid var(--border)",
      borderRadius: 16,
      padding: "16px"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      alignItems: "center",
      justifyContent: "space-between",
      marginBottom: 14
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      fontWeight: 700,
      fontSize: 15
    }
  }, firstDay.toLocaleDateString("en-US", {
    month: "long",
    year: "numeric"
  })), /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      gap: 6,
      alignItems: "center"
    }
  }, /*#__PURE__*/React.createElement("button", {
    onClick: () => setViewDate(d => new Date(d.getFullYear(), d.getMonth() - 1, 1)),
    style: {
      background: "none",
      border: "1px solid var(--border)",
      borderRadius: 8,
      color: "var(--muted)",
      cursor: "pointer",
      padding: "3px 9px",
      fontSize: 13
    }
  }, "\u2039"), /*#__PURE__*/React.createElement("button", {
    onClick: () => setViewDate(new Date()),
    style: {
      background: "none",
      border: "1px solid var(--border)",
      borderRadius: 8,
      color: "var(--muted)",
      cursor: "pointer",
      padding: "3px 9px",
      fontSize: 11
    }
  }, "Today"), /*#__PURE__*/React.createElement("button", {
    onClick: () => setViewDate(d => new Date(d.getFullYear(), d.getMonth() + 1, 1)),
    disabled: year === new Date().getFullYear() && month === new Date().getMonth() + 1,
    style: {
      background: "none",
      border: "1px solid var(--border)",
      borderRadius: 8,
      color: "var(--muted)",
      cursor: "pointer",
      padding: "3px 9px",
      fontSize: 13,
      opacity: year === new Date().getFullYear() && month === new Date().getMonth() + 1 ? 0.3 : 1
    }
  }, "\u203A"))), /*#__PURE__*/React.createElement("div", {
    style: {
      display: "grid",
      gridTemplateColumns: "repeat(7,1fr)",
      gap: 3,
      marginBottom: 4
    }
  }, ["Mo", "Tu", "We", "Th", "Fr", "Sa", "Su"].map(d => /*#__PURE__*/React.createElement("div", {
    key: d,
    style: {
      textAlign: "center",
      fontSize: 10,
      fontWeight: 600,
      color: "var(--muted)",
      padding: "4px 0"
    }
  }, d))), /*#__PURE__*/React.createElement("div", {
    style: {
      display: "grid",
      gridTemplateColumns: "repeat(7,1fr)",
      gap: 3
    }
  }, Array.from({
    length: startOffset
  }).map((_, i) => /*#__PURE__*/React.createElement("div", {
    key: `e${i}`
  })), monthDays.map(ds => {
    const d = parseInt(ds.split("-")[2]);
    const count = calData[ds] || 0;
    const isFuture = ds > td;
    const isToday = ds === td;
    const color = getColor(count, isFuture);
    const isSel = selected === ds;
    return /*#__PURE__*/React.createElement("div", {
      key: ds,
      onClick: () => !isFuture && setSelected(isSel ? null : ds),
      style: {
        aspectRatio: "1",
        borderRadius: 8,
        display: "flex",
        flexDirection: "column",
        alignItems: "center",
        justifyContent: "center",
        gap: 2,
        cursor: isFuture ? "default" : "pointer",
        background: color ? `${color}28` : isFuture ? "transparent" : "var(--bg)",
        outline: isToday ? `2px solid var(--primary)` : isSel ? "2px solid #ffffff40" : "none",
        outlineOffset: -1,
        opacity: isFuture ? 0.25 : 1,
        transition: ".15s"
      }
    }, /*#__PURE__*/React.createElement("span", {
      style: {
        fontSize: 10,
        fontWeight: isToday ? 700 : 400,
        color: isToday ? "var(--primary)" : "var(--text)"
      }
    }, d), color && /*#__PURE__*/React.createElement("div", {
      style: {
        width: 4,
        height: 4,
        borderRadius: "50%",
        background: color
      }
    }));
  })), selected && (() => {
    const count = calData[selected] || 0;
    const rate = total ? Math.round(count / total * 100) : 0;
    const label = new Date(selected + "T12:00").toLocaleDateString("en-US", {
      weekday: "long",
      month: "long",
      day: "numeric"
    });
    return /*#__PURE__*/React.createElement("div", {
      style: {
        marginTop: 14,
        padding: "12px 14px",
        background: "var(--bg)",
        borderRadius: 10,
        border: "1px solid var(--border)"
      }
    }, /*#__PURE__*/React.createElement("div", {
      style: {
        fontWeight: 600,
        fontSize: 13,
        marginBottom: 8
      }
    }, label), /*#__PURE__*/React.createElement("div", {
      style: {
        display: "flex",
        gap: 20
      }
    }, [["Completed", count, "var(--primary)"], ["Total", total, "var(--text)"], ["Rate", `${rate}%`, rate >= 100 ? "#00ff9f" : "#a855f7"]].map(([l, v, c]) => /*#__PURE__*/React.createElement("div", {
      key: l
    }, /*#__PURE__*/React.createElement("div", {
      style: {
        fontSize: 20,
        fontWeight: 700,
        color: c
      }
    }, v), /*#__PURE__*/React.createElement("div", {
      style: {
        fontSize: 10,
        color: "var(--muted)"
      }
    }, l)))));
  })(), /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      gap: 12,
      marginTop: 12,
      paddingTop: 10,
      borderTop: "1px solid var(--border)",
      flexWrap: "wrap",
      alignItems: "center"
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      fontSize: 10,
      color: "var(--muted)"
    }
  }, "Rate:"), [["#ffd60066", "#ffd600", "< 50%"], ["#a855f766", "#a855f7", "50–75%"], ["#3b82f666", "#3b82f6", "75–99%"], ["#00ff9f66", "#00ff9f", "100% 🎉"]].map(([bg, fg, l]) => /*#__PURE__*/React.createElement("div", {
    key: l,
    style: {
      display: "flex",
      alignItems: "center",
      gap: 4
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      width: 10,
      height: 10,
      borderRadius: 3,
      background: bg
    }
  }), /*#__PURE__*/React.createElement("span", {
    style: {
      fontSize: 10,
      color: "var(--muted)"
    }
  }, l))))));
}
function HabitsListPage({
  habits,
  completions,
  onDelete,
  onEdit,
  onCreate,
  onReorder
}) {
  const td = today();
  const handleExport = () => exportCSV(habits, completions);
  const dragIdx = useRef(null);
  return /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      alignItems: "flex-start",
      justifyContent: "space-between",
      marginBottom: 20,
      flexWrap: "wrap",
      gap: 12
    }
  }, /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("h1", {
    style: {
      fontSize: 28,
      fontWeight: 800,
      margin: "0 0 4px",
      letterSpacing: "-0.5px"
    }
  }, "All Habits"), /*#__PURE__*/React.createElement("div", {
    style: {
      color: "var(--muted)",
      fontSize: 13
    }
  }, "Drag to reorder \xB7 manage your routines.")), /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      gap: 8
    }
  }, /*#__PURE__*/React.createElement("button", {
    onClick: handleExport,
    disabled: !habits.length,
    style: {
      display: "flex",
      alignItems: "center",
      gap: 6,
      padding: "8px 16px",
      borderRadius: 20,
      border: "1px solid var(--border)",
      background: "none",
      color: "var(--muted)",
      cursor: "pointer",
      fontSize: 12,
      fontWeight: 500
    }
  }, "\u2B07 Export CSV"), /*#__PURE__*/React.createElement("button", {
    onClick: onCreate,
    style: {
      display: "flex",
      alignItems: "center",
      gap: 6,
      padding: "8px 18px",
      borderRadius: 20,
      border: "none",
      background: "var(--primary)",
      color: "#071810",
      cursor: "pointer",
      fontSize: 12,
      fontWeight: 700
    }
  }, "+ New Habit"))), /*#__PURE__*/React.createElement("div", {
    style: {
      display: "grid",
      gridTemplateColumns: "repeat(2,minmax(0,1fr))",
      gap: 12
    }
  }, habits.map((h, idx) => {
    const streak = getStreak(h.id, completions, h.freq);
    const longest = getLongestStreak(h.id, completions, h.freq);
    const done = !!completions[`${h.id}:${td}`];
    const total = Object.keys(completions).filter(k => k.startsWith(`${h.id}:`)).length;
    return /*#__PURE__*/React.createElement("div", {
      key: h.id,
      draggable: true,
      onDragStart: () => {
        dragIdx.current = idx;
      },
      onDragOver: e => {
        e.preventDefault();
      },
      onDrop: () => {
        if (dragIdx.current !== null && dragIdx.current !== idx) {
          onReorder(dragIdx.current, idx);
          dragIdx.current = null;
        }
      },
      style: {
        background: "var(--card)",
        border: "1px solid var(--border)",
        borderRadius: 14,
        padding: 16,
        display: "flex",
        flexDirection: "column",
        cursor: "grab"
      },
      onMouseEnter: e => {
        e.currentTarget.querySelector(".hc-acts").style.opacity = 1;
      },
      onMouseLeave: e => {
        e.currentTarget.querySelector(".hc-acts").style.opacity = 0;
      }
    }, /*#__PURE__*/React.createElement("div", {
      style: {
        display: "flex",
        justifyContent: "space-between",
        marginBottom: 10
      }
    }, /*#__PURE__*/React.createElement("div", {
      style: {
        display: "flex",
        alignItems: "center",
        gap: 8
      }
    }, /*#__PURE__*/React.createElement("div", {
      style: {
        width: 40,
        height: 40,
        borderRadius: 10,
        background: `${h.color}22`,
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        fontSize: 20
      }
    }, h.icon), /*#__PURE__*/React.createElement("div", {
      style: {
        fontSize: 10,
        color: "var(--muted)"
      }
    }, "\u283F")), /*#__PURE__*/React.createElement("div", {
      className: "hc-acts",
      style: {
        display: "flex",
        gap: 4,
        opacity: 0,
        transition: ".15s"
      }
    }, /*#__PURE__*/React.createElement("button", {
      onClick: () => onEdit(h),
      style: {
        background: "none",
        border: "1px solid var(--border)",
        borderRadius: 8,
        color: "var(--muted)",
        cursor: "pointer",
        padding: "4px 8px",
        fontSize: 12
      }
    }, "Edit"), /*#__PURE__*/React.createElement("button", {
      onClick: () => onDelete(h.id),
      style: {
        background: "none",
        border: "1px solid var(--border)",
        borderRadius: 8,
        color: "#f43f5e80",
        cursor: "pointer",
        padding: "4px 8px",
        fontSize: 12
      }
    }, "Delete"))), /*#__PURE__*/React.createElement("div", {
      style: {
        fontWeight: 600,
        fontSize: 14,
        marginBottom: 2
      }
    }, h.name), /*#__PURE__*/React.createElement("div", {
      style: {
        fontSize: 11,
        color: "var(--muted)",
        marginBottom: 2,
        textTransform: "capitalize"
      }
    }, h.freq), h.desc && /*#__PURE__*/React.createElement("div", {
      style: {
        fontSize: 11,
        color: "var(--muted)",
        marginBottom: 8,
        lineHeight: 1.5
      }
    }, h.desc), /*#__PURE__*/React.createElement(MilestoneBadges, {
      streak: streak
    }), /*#__PURE__*/React.createElement("div", {
      style: {
        display: "flex",
        gap: 16,
        marginTop: 12,
        paddingTop: 10,
        borderTop: "1px solid var(--border)"
      }
    }, [["Streak", `${streak}d`], ["Longest", `${longest}d`], ["All-time", `${total}×`], ["Today", done ? "✓" : "—"]].map(([l, v]) => /*#__PURE__*/React.createElement("div", {
      key: l
    }, /*#__PURE__*/React.createElement("div", {
      style: {
        fontSize: 13,
        fontWeight: 600
      }
    }, v), /*#__PURE__*/React.createElement("div", {
      style: {
        fontSize: 10,
        color: "var(--muted)"
      }
    }, l)))));
  }), habits.length === 0 && /*#__PURE__*/React.createElement("div", {
    style: {
      gridColumn: "1/-1",
      textAlign: "center",
      padding: "40px 20px",
      color: "var(--muted)",
      border: "1px dashed var(--border)",
      borderRadius: 14
    }
  }, "No habits yet \u2014 create your first one!")));
}
function HabitFormPage({
  habit,
  onSave,
  onCancel
}) {
  const [form, setForm] = useState(habit ? {
    name: habit.name,
    desc: habit.desc || "",
    icon: habit.icon,
    color: habit.color,
    freq: habit.freq
  } : {
    name: "",
    desc: "",
    icon: "🌟",
    color: PRESET_COLORS[0],
    freq: "daily"
  });
  const [showTemplates, setShowTemplates] = useState(!habit);
  const set = (k, v) => setForm(f => ({
    ...f,
    [k]: v
  }));
  return /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("div", {
    style: {
      marginBottom: 20
    }
  }, /*#__PURE__*/React.createElement("h1", {
    style: {
      fontSize: 28,
      fontWeight: 800,
      margin: "0 0 4px",
      letterSpacing: "-0.5px"
    }
  }, habit ? "Edit Habit" : "New Habit"), /*#__PURE__*/React.createElement("div", {
    style: {
      color: "var(--muted)",
      fontSize: 13
    }
  }, habit ? "Update your routine." : "Build a new routine.")), !habit && /*#__PURE__*/React.createElement(React.Fragment, null, /*#__PURE__*/React.createElement("button", {
    onClick: () => setShowTemplates(s => !s),
    style: {
      display: "flex",
      alignItems: "center",
      gap: 6,
      marginBottom: 10,
      background: "none",
      border: "none",
      color: "var(--primary)",
      cursor: "pointer",
      fontSize: 13,
      fontWeight: 600,
      padding: 0
    }
  }, "\u2728 ", showTemplates ? "Hide templates" : "Quick-start from a template"), showTemplates && /*#__PURE__*/React.createElement(React.Fragment, null, /*#__PURE__*/React.createElement("div", {
    style: {
      display: "grid",
      gridTemplateColumns: "repeat(2,1fr)",
      gap: 8,
      marginBottom: 14,
      maxHeight: 240,
      overflowY: "auto"
    }
  }, TEMPLATES.map(t => /*#__PURE__*/React.createElement("button", {
    key: t.name,
    onClick: () => {
      set("name", t.name);
      set("desc", t.desc);
      set("icon", t.icon);
      set("color", t.color);
      set("freq", t.freq);
      setShowTemplates(false);
    },
    style: {
      display: "flex",
      alignItems: "center",
      gap: 10,
      padding: "10px 12px",
      background: "var(--card)",
      border: "1px solid var(--border)",
      borderRadius: 12,
      cursor: "pointer",
      textAlign: "left",
      transition: ".15s"
    },
    onMouseEnter: e => {
      e.currentTarget.style.borderColor = `${t.color}60`;
      e.currentTarget.style.transform = "scale(1.02)";
    },
    onMouseLeave: e => {
      e.currentTarget.style.borderColor = "var(--border)";
      e.currentTarget.style.transform = "scale(1)";
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      width: 32,
      height: 32,
      borderRadius: 8,
      background: `${t.color}22`,
      display: "flex",
      alignItems: "center",
      justifyContent: "center",
      fontSize: 17,
      flexShrink: 0
    }
  }, t.icon), /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("div", {
    style: {
      fontSize: 12,
      fontWeight: 600,
      color: t.color
    }
  }, t.name), /*#__PURE__*/React.createElement("div", {
    style: {
      fontSize: 10,
      color: "var(--muted)",
      textTransform: "capitalize"
    }
  }, t.freq))))), /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      alignItems: "center",
      gap: 10,
      margin: "8px 0 14px"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      flex: 1,
      height: 1,
      background: "var(--border)"
    }
  }), /*#__PURE__*/React.createElement("span", {
    style: {
      fontSize: 11,
      color: "var(--muted)"
    }
  }, "or fill in manually"), /*#__PURE__*/React.createElement("div", {
    style: {
      flex: 1,
      height: 1,
      background: "var(--border)"
    }
  })))), /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      flexDirection: "column",
      gap: 14
    }
  }, [["Name", "name", "text", "Read for 30 minutes"], ["Description", "desc", "text", "Why is this important to you?"]].map(([label, key,, placeholder]) => /*#__PURE__*/React.createElement("div", {
    key: key
  }, /*#__PURE__*/React.createElement("label", {
    style: {
      fontSize: 11,
      color: "var(--muted)",
      display: "block",
      marginBottom: 5
    }
  }, label), key === "desc" ? /*#__PURE__*/React.createElement("textarea", {
    value: form[key],
    onChange: e => set(key, e.target.value),
    placeholder: placeholder,
    rows: 2,
    style: {
      width: "100%",
      background: "var(--bg)",
      border: "1px solid var(--border)",
      borderRadius: 10,
      color: "var(--text)",
      fontSize: 13,
      padding: "9px 11px",
      resize: "none",
      fontFamily: "inherit",
      boxSizing: "border-box",
      outline: "none"
    },
    onFocus: e => e.target.style.borderColor = "var(--primary)",
    onBlur: e => e.target.style.borderColor = "var(--border)"
  }) : /*#__PURE__*/React.createElement("input", {
    type: "text",
    value: form[key],
    onChange: e => set(key, e.target.value),
    placeholder: placeholder,
    style: {
      width: "100%",
      background: "var(--bg)",
      border: "1px solid var(--border)",
      borderRadius: 10,
      color: "var(--text)",
      fontSize: 13,
      padding: "9px 11px",
      fontFamily: "inherit",
      boxSizing: "border-box",
      outline: "none"
    },
    onFocus: e => e.target.style.borderColor = "var(--primary)",
    onBlur: e => e.target.style.borderColor = "var(--border)"
  }))), /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      gap: 12
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      flex: 1
    }
  }, /*#__PURE__*/React.createElement("label", {
    style: {
      fontSize: 11,
      color: "var(--muted)",
      display: "block",
      marginBottom: 5
    }
  }, "Frequency"), /*#__PURE__*/React.createElement("select", {
    value: form.freq,
    onChange: e => set("freq", e.target.value),
    style: {
      width: "100%",
      background: "var(--bg)",
      border: "1px solid var(--border)",
      borderRadius: 10,
      color: "var(--text)",
      fontSize: 13,
      padding: "9px 11px",
      fontFamily: "inherit"
    }
  }, /*#__PURE__*/React.createElement("option", {
    value: "daily"
  }, "Daily"), /*#__PURE__*/React.createElement("option", {
    value: "weekly"
  }, "Weekly"))), /*#__PURE__*/React.createElement("div", {
    style: {
      width: 90
    }
  }, /*#__PURE__*/React.createElement("label", {
    style: {
      fontSize: 11,
      color: "var(--muted)",
      display: "block",
      marginBottom: 5
    }
  }, "Icon"), /*#__PURE__*/React.createElement("input", {
    type: "text",
    value: form.icon,
    onChange: e => set("icon", e.target.value),
    style: {
      width: "100%",
      background: "var(--bg)",
      border: "1px solid var(--border)",
      borderRadius: 10,
      color: "var(--text)",
      fontSize: 20,
      padding: "7px 11px",
      textAlign: "center",
      fontFamily: "inherit",
      boxSizing: "border-box",
      outline: "none"
    },
    onFocus: e => e.target.style.borderColor = "var(--primary)",
    onBlur: e => e.target.style.borderColor = "var(--border)"
  }))), /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("label", {
    style: {
      fontSize: 11,
      color: "var(--muted)",
      display: "block",
      marginBottom: 8
    }
  }, "Color"), /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      gap: 10,
      flexWrap: "wrap"
    }
  }, PRESET_COLORS.map(c => /*#__PURE__*/React.createElement("div", {
    key: c,
    onClick: () => set("color", c),
    style: {
      width: 26,
      height: 26,
      borderRadius: "50%",
      background: c,
      cursor: "pointer",
      outline: form.color === c ? `2.5px solid ${c}` : "none",
      outlineOffset: 2,
      transition: ".15s",
      opacity: form.color === c ? 1 : 0.5
    }
  })))), /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      gap: 10,
      justifyContent: "flex-end",
      paddingTop: 4
    }
  }, onCancel && /*#__PURE__*/React.createElement("button", {
    onClick: onCancel,
    style: {
      padding: "9px 18px",
      borderRadius: 20,
      border: "1px solid var(--border)",
      background: "none",
      color: "var(--muted)",
      cursor: "pointer",
      fontSize: 13
    }
  }, "Cancel"), /*#__PURE__*/React.createElement("button", {
    onClick: () => form.name.trim() && onSave(form),
    style: {
      padding: "9px 22px",
      borderRadius: 20,
      border: "none",
      background: form.name.trim() ? "var(--primary)" : "var(--border)",
      color: form.name.trim() ? "#071810" : "var(--muted)",
      cursor: form.name.trim() ? "pointer" : "not-allowed",
      fontSize: 13,
      fontWeight: 700
    }
  }, habit ? "Save Changes" : "Create Habit"))));
}

// ─── Analytics Page ──────────────────────────────────────────────────────────

function DonutChart({
  pct,
  color,
  size = 80,
  label,
  sub
}) {
  const r = (size - 12) / 2;
  const circ = 2 * Math.PI * r;
  const dash = circ * Math.min(pct, 1);
  return /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      flexDirection: "column",
      alignItems: "center",
      gap: 6
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      position: "relative",
      width: size,
      height: size
    }
  }, /*#__PURE__*/React.createElement("svg", {
    width: size,
    height: size,
    style: {
      transform: "rotate(-90deg)"
    }
  }, /*#__PURE__*/React.createElement("circle", {
    cx: size / 2,
    cy: size / 2,
    r: r,
    fill: "none",
    stroke: "rgba(255,255,255,.07)",
    strokeWidth: 8
  }), /*#__PURE__*/React.createElement("circle", {
    cx: size / 2,
    cy: size / 2,
    r: r,
    fill: "none",
    stroke: color,
    strokeWidth: 8,
    strokeDasharray: `${dash} ${circ}`,
    strokeLinecap: "round",
    style: {
      transition: "stroke-dasharray .8s cubic-bezier(.4,0,.2,1)"
    }
  })), /*#__PURE__*/React.createElement("div", {
    style: {
      position: "absolute",
      inset: 0,
      display: "flex",
      alignItems: "center",
      justifyContent: "center",
      flexDirection: "column"
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      fontSize: size * 0.19,
      fontWeight: 700,
      color,
      lineHeight: 1
    }
  }, Math.round(pct * 100), "%"))), label && /*#__PURE__*/React.createElement("div", {
    style: {
      fontSize: 11,
      fontWeight: 600,
      color: "var(--text)",
      textAlign: "center"
    }
  }, label), sub && /*#__PURE__*/React.createElement("div", {
    style: {
      fontSize: 10,
      color: "var(--muted)",
      textAlign: "center"
    }
  }, sub));
}
function MiniBarChart({
  data,
  color,
  maxVal
}) {
  const max = maxVal ?? Math.max(...data.map(d => d.val), 1);
  return /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      alignItems: "flex-end",
      gap: 3,
      height: 60
    }
  }, data.map((d, i) => /*#__PURE__*/React.createElement("div", {
    key: i,
    style: {
      flex: 1,
      display: "flex",
      flexDirection: "column",
      alignItems: "center",
      gap: 2
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      width: "100%",
      borderRadius: 3,
      height: `${Math.max(d.val / max * 52, d.val > 0 ? 4 : 0)}px`,
      background: d.highlight ? color : `${color}55`,
      transition: "height .5s ease"
    }
  }), /*#__PURE__*/React.createElement("span", {
    style: {
      fontSize: 8,
      color: "var(--muted)"
    }
  }, d.label))));
}
function SparkLine({
  data,
  color,
  width = 200,
  height = 50
}) {
  if (data.length < 2) return null;
  const max = Math.max(...data, 1);
  const pts = data.map((v, i) => {
    const x = i / (data.length - 1) * width;
    const y = height - v / max * (height - 8) - 4;
    return `${x},${y}`;
  }).join(" ");
  const areaPoints = `0,${height} ${pts} ${width},${height}`;
  return /*#__PURE__*/React.createElement("svg", {
    width: width,
    height: height,
    style: {
      overflow: "visible"
    }
  }, /*#__PURE__*/React.createElement("defs", null, /*#__PURE__*/React.createElement("linearGradient", {
    id: `sg-${color.replace("#", "")}`,
    x1: "0",
    y1: "0",
    x2: "0",
    y2: "1"
  }, /*#__PURE__*/React.createElement("stop", {
    offset: "0%",
    stopColor: color,
    stopOpacity: "0.35"
  }), /*#__PURE__*/React.createElement("stop", {
    offset: "100%",
    stopColor: color,
    stopOpacity: "0"
  }))), /*#__PURE__*/React.createElement("polygon", {
    points: areaPoints,
    fill: `url(#sg-${color.replace("#", "")})`
  }), /*#__PURE__*/React.createElement("polyline", {
    points: pts,
    fill: "none",
    stroke: color,
    strokeWidth: "2",
    strokeLinecap: "round",
    strokeLinejoin: "round"
  }));
}
function AnalyticsPage({
  habits,
  completions,
  onShowWeekly
}) {
  const td = today();
  const now = new Date();

  // ── Last 7 days completion rate per day ──────────────────────────────
  const last7 = Array.from({
    length: 7
  }, (_, i) => {
    const d = new Date(now);
    d.setDate(d.getDate() - (6 - i));
    const ds = fmt(d);
    const done = habits.filter(h => completions[`${h.id}:${ds}`]).length;
    const labels = ["Su", "Mo", "Tu", "We", "Th", "Fr", "Sa"];
    return {
      label: labels[d.getDay()],
      val: habits.length ? done / habits.length : 0,
      highlight: ds === td
    };
  });

  // ── Last 30 days daily completion count (for sparkline) ──────────────
  const last30Counts = Array.from({
    length: 30
  }, (_, i) => {
    const d = new Date(now);
    d.setDate(d.getDate() - (29 - i));
    return habits.filter(h => completions[`${h.id}:${fmt(d)}`]).length;
  });

  // ── Per-habit completion rate (all-time) ─────────────────────────────
  const habitRates = habits.map(h => {
    const total = Object.keys(completions).filter(k => k.startsWith(`${h.id}:`)).length;
    const days = Math.max(1, Math.ceil((now - new Date(h.createdAt)) / 86400000));
    const expected = h.freq === "weekly" ? Math.ceil(days / 7) : days;
    return {
      ...h,
      rate: Math.min(total / expected, 1),
      total
    };
  }).sort((a, b) => b.rate - a.rate);

  // ── Overall stats ────────────────────────────────────────────────────
  const allKeys = Object.keys(completions);
  const totalCompletions = allKeys.length;
  const uniqueDays = new Set(allKeys.map(k => k.split(":")[1])).size;
  const overallRate = habits.length ? last7.reduce((s, d) => s + d.val, 0) / 7 : 0;
  const bestStreak = Math.max(0, ...habits.map(h => getLongestStreak(h.id, completions, h.freq)));
  const currentBest = Math.max(0, ...habits.map(h => getStreak(h.id, completions, h.freq)));

  // ── Top habit by streak ──────────────────────────────────────────────
  const topHabit = habitRates[0];
  return /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("div", {
    style: {
      marginBottom: 20,
      display: "flex",
      alignItems: "flex-start",
      justifyContent: "space-between"
    }
  }, /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("h1", {
    style: {
      fontSize: 28,
      fontWeight: 800,
      margin: "0 0 4px",
      letterSpacing: "-0.5px"
    }
  }, "Analytics"), /*#__PURE__*/React.createElement("div", {
    style: {
      color: "var(--muted)",
      fontSize: 13
    }
  }, "Your progress at a glance.")), onShowWeekly && /*#__PURE__*/React.createElement("button", {
    onClick: onShowWeekly,
    style: {
      background: "var(--card)",
      border: "1px solid var(--border)",
      borderRadius: 10,
      padding: "8px 14px",
      fontSize: 12,
      fontWeight: 600,
      color: "var(--text)",
      cursor: "pointer",
      display: "flex",
      alignItems: "center",
      gap: 6,
      flexShrink: 0
    }
  }, "\uD83D\uDCCA Week Summary")), /*#__PURE__*/React.createElement("div", {
    style: {
      display: "grid",
      gridTemplateColumns: "repeat(4,1fr)",
      gap: 10,
      marginBottom: 18
    }
  }, [{
    label: "Total Check-ins",
    val: totalCompletions,
    icon: "✅",
    color: "#2ecc98"
  }, {
    label: "Active Days",
    val: uniqueDays,
    icon: "📅",
    color: "#3b82f6"
  }, {
    label: "Best Streak",
    val: `${bestStreak}d`,
    icon: "🏆",
    color: "#f59e0b"
  }, {
    label: "Current Best",
    val: `${currentBest}d`,
    icon: "🔥",
    color: "#d946ef"
  }].map(c => /*#__PURE__*/React.createElement("div", {
    key: c.label,
    style: {
      background: "var(--card)",
      border: "1px solid var(--border)",
      borderRadius: 14,
      padding: "14px 12px"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      fontSize: 18,
      marginBottom: 4
    }
  }, c.icon), /*#__PURE__*/React.createElement("div", {
    style: {
      fontSize: 20,
      fontWeight: 700,
      color: c.color,
      lineHeight: 1
    }
  }, c.val), /*#__PURE__*/React.createElement("div", {
    style: {
      fontSize: 10,
      color: "var(--muted)",
      marginTop: 4
    }
  }, c.label)))), /*#__PURE__*/React.createElement("div", {
    style: {
      display: "grid",
      gridTemplateColumns: "1fr 1fr",
      gap: 12,
      marginBottom: 12
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      background: "var(--card)",
      border: "1px solid var(--border)",
      borderRadius: 14,
      padding: 16
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      fontSize: 11,
      fontWeight: 600,
      color: "var(--muted)",
      letterSpacing: ".1em",
      textTransform: "uppercase",
      marginBottom: 12
    }
  }, "This Week"), /*#__PURE__*/React.createElement(MiniBarChart, {
    data: last7.map(d => ({
      ...d,
      val: d.val * 100
    })),
    color: "#2ecc98",
    maxVal: 100
  }), /*#__PURE__*/React.createElement("div", {
    style: {
      marginTop: 10,
      fontSize: 11,
      color: "var(--muted)"
    }
  }, "Avg. ", /*#__PURE__*/React.createElement("span", {
    style: {
      color: "#2ecc98",
      fontWeight: 700
    }
  }, Math.round(overallRate * 100), "%"), " completion rate")), /*#__PURE__*/React.createElement("div", {
    style: {
      background: "var(--card)",
      border: "1px solid var(--border)",
      borderRadius: 14,
      padding: 16
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      fontSize: 11,
      fontWeight: 600,
      color: "var(--muted)",
      letterSpacing: ".1em",
      textTransform: "uppercase",
      marginBottom: 12
    }
  }, "30-Day Trend"), /*#__PURE__*/React.createElement(SparkLine, {
    data: last30Counts,
    color: "#a855f7",
    width: 240,
    height: 52
  }), /*#__PURE__*/React.createElement("div", {
    style: {
      marginTop: 10,
      fontSize: 11,
      color: "var(--muted)"
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      color: "#a855f7",
      fontWeight: 700
    }
  }, totalCompletions), " total completions"))), /*#__PURE__*/React.createElement("div", {
    style: {
      background: "var(--card)",
      border: "1px solid var(--border)",
      borderRadius: 14,
      padding: "16px 20px",
      marginBottom: 12
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      fontSize: 11,
      fontWeight: 600,
      color: "var(--muted)",
      letterSpacing: ".1em",
      textTransform: "uppercase",
      marginBottom: 16
    }
  }, "Completion by Habit"), /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      gap: 20,
      flexWrap: "wrap",
      justifyContent: "center"
    }
  }, habitRates.slice(0, 6).map(h => /*#__PURE__*/React.createElement(DonutChart, {
    key: h.id,
    pct: h.rate,
    color: h.color,
    size: 82,
    label: h.name.split(" ").slice(0, 2).join(" "),
    sub: `${h.total} done`
  })), habits.length === 0 && /*#__PURE__*/React.createElement("div", {
    style: {
      color: "var(--muted)",
      fontSize: 13,
      padding: 20
    }
  }, "No habits yet."))), /*#__PURE__*/React.createElement("div", {
    style: {
      background: "var(--card)",
      border: "1px solid var(--border)",
      borderRadius: 14,
      padding: 16,
      marginBottom: 12
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      fontSize: 11,
      fontWeight: 600,
      color: "var(--muted)",
      letterSpacing: ".1em",
      textTransform: "uppercase",
      marginBottom: 14
    }
  }, "Habit Rankings"), /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      flexDirection: "column",
      gap: 10
    }
  }, habitRates.map((h, i) => /*#__PURE__*/React.createElement("div", {
    key: h.id
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      justifyContent: "space-between",
      marginBottom: 4,
      alignItems: "center"
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      fontSize: 12,
      fontWeight: 500
    }
  }, h.icon, " ", h.name), /*#__PURE__*/React.createElement("span", {
    style: {
      fontSize: 12,
      fontWeight: 700,
      color: h.color
    }
  }, Math.round(h.rate * 100), "%")), /*#__PURE__*/React.createElement("div", {
    style: {
      height: 6,
      background: "var(--border)",
      borderRadius: 3,
      overflow: "hidden"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      height: "100%",
      width: `${h.rate * 100}%`,
      background: `linear-gradient(90deg, ${h.color}88, ${h.color})`,
      borderRadius: 3,
      transition: "width .7s ease"
    }
  })))), habits.length === 0 && /*#__PURE__*/React.createElement("div", {
    style: {
      color: "var(--muted)",
      fontSize: 13
    }
  }, "No habits yet."))), /*#__PURE__*/React.createElement(InfographicPanel, {
    habits: habits,
    completions: completions,
    last7: last7.map(d => ({
      ...d,
      val: d.val * 100
    })),
    totalCompletions: totalCompletions,
    bestStreak: bestStreak
  }));
}

// ─── Monthly / Yearly Analytics Page ─────────────────────────────────────────
function MonthlyPage({
  habits,
  completions
}) {
  const now = new Date();
  const [viewYear, setViewYear] = useState(now.getFullYear());
  const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

  // ── Per-month stats for the viewed year ──────────────────────────────
  const monthStats = useMemo(() => MONTHS.map((label, mi) => {
    const daysInMonth = new Date(viewYear, mi + 1, 0).getDate();
    let done = 0,
      possible = 0;
    for (let d = 1; d <= daysInMonth; d++) {
      const ds = `${viewYear}-${String(mi + 1).padStart(2, "0")}-${String(d).padStart(2, "0")}`;
      if (ds > fmt(now)) break;
      habits.forEach(h => {
        if (h.freq === "weekly" && new Date(ds).getDay() !== 1) return;
        possible++;
        if (completions[`${h.id}:${ds}`]) done++;
      });
    }
    return {
      label,
      done,
      possible,
      rate: possible > 0 ? done / possible : 0
    };
  }), [habits, completions, viewYear]);
  const maxDone = Math.max(...monthStats.map(m => m.done), 1);

  // ── Best / worst month ───────────────────────────────────────────────
  const filled = monthStats.filter(m => m.possible > 0);
  const best = filled.length ? filled.reduce((a, b) => b.rate > a.rate ? b : a) : null;
  const worst = filled.length ? filled.reduce((a, b) => b.rate < a.rate ? b : a) : null;
  const totalYear = monthStats.reduce((s, m) => s + m.done, 0);

  // ── Per-habit yearly performance ─────────────────────────────────────
  const habitYear = habits.map(h => {
    const done = Object.keys(completions).filter(k => {
      if (!k.startsWith(`${h.id}:`)) return false;
      return k.split(":")[1].startsWith(`${viewYear}-`);
    }).length;
    return {
      ...h,
      done
    };
  }).sort((a, b) => b.done - a.done);
  return /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      alignItems: "center",
      justifyContent: "space-between",
      marginBottom: 20
    }
  }, /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("h1", {
    style: {
      fontSize: 28,
      fontWeight: 800,
      margin: "0 0 4px",
      letterSpacing: "-0.5px"
    }
  }, "Year in Review"), /*#__PURE__*/React.createElement("div", {
    style: {
      color: "var(--muted)",
      fontSize: 13
    }
  }, "Your full-year habit history.")), /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      alignItems: "center",
      gap: 8
    }
  }, /*#__PURE__*/React.createElement("button", {
    onClick: () => setViewYear(y => y - 1),
    style: {
      background: "var(--card)",
      border: "1px solid var(--border)",
      borderRadius: 8,
      padding: "6px 12px",
      color: "var(--text)",
      cursor: "pointer",
      fontSize: 14
    }
  }, "\u2039"), /*#__PURE__*/React.createElement("span", {
    style: {
      fontWeight: 700,
      fontSize: 16,
      minWidth: 48,
      textAlign: "center"
    }
  }, viewYear), /*#__PURE__*/React.createElement("button", {
    onClick: () => setViewYear(y => Math.min(y + 1, now.getFullYear())),
    disabled: viewYear >= now.getFullYear(),
    style: {
      background: "var(--card)",
      border: "1px solid var(--border)",
      borderRadius: 8,
      padding: "6px 12px",
      color: viewYear >= now.getFullYear() ? "var(--muted)" : "var(--text)",
      cursor: viewYear >= now.getFullYear() ? "default" : "pointer",
      fontSize: 14
    }
  }, "\u203A"))), /*#__PURE__*/React.createElement("div", {
    style: {
      display: "grid",
      gridTemplateColumns: "repeat(3,1fr)",
      gap: 10,
      marginBottom: 14
    }
  }, [{
    icon: "✅",
    label: "Total Check-ins",
    val: totalYear,
    color: "#2ecc98"
  }, {
    icon: "🌟",
    label: "Best Month",
    val: best ? `${best.label} (${Math.round(best.rate * 100)}%)` : "—",
    color: "#f59e0b"
  }, {
    icon: "📈",
    label: "Avg Monthly Rate",
    val: filled.length ? `${Math.round(filled.reduce((s, m) => s + m.rate, 0) / filled.length * 100)}%` : "—",
    color: "#3b82f6"
  }].map(c => /*#__PURE__*/React.createElement("div", {
    key: c.label,
    style: {
      background: "var(--card)",
      border: "1px solid var(--border)",
      borderRadius: 14,
      padding: "14px 12px"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      fontSize: 20,
      marginBottom: 4
    }
  }, c.icon), /*#__PURE__*/React.createElement("div", {
    style: {
      fontSize: 18,
      fontWeight: 700,
      color: c.color,
      lineHeight: 1.1
    }
  }, c.val), /*#__PURE__*/React.createElement("div", {
    style: {
      fontSize: 10,
      color: "var(--muted)",
      marginTop: 4
    }
  }, c.label)))), /*#__PURE__*/React.createElement("div", {
    style: {
      background: "var(--card)",
      border: "1px solid var(--border)",
      borderRadius: 14,
      padding: 16,
      marginBottom: 14
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      fontSize: 11,
      fontWeight: 600,
      color: "var(--muted)",
      letterSpacing: ".1em",
      textTransform: "uppercase",
      marginBottom: 16
    }
  }, "Monthly Completion Rate"), /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      gap: 4,
      alignItems: "flex-end",
      height: 100
    }
  }, monthStats.map((m, i) => {
    const h = m.possible > 0 ? Math.max(m.rate * 88, 4) : 0;
    const isNow = i === now.getMonth() && viewYear === now.getFullYear();
    const isFuture = new Date(viewYear, i, 1) > now;
    const col = isFuture ? "rgba(255,255,255,.06)" : isNow ? "#2ecc98" : m.rate >= .8 ? "#3b82f6" : m.rate >= .5 ? "#a855f7" : m.rate > 0 ? "#ffd600" : "rgba(255,255,255,.08)";
    return /*#__PURE__*/React.createElement("div", {
      key: m.label,
      style: {
        flex: 1,
        display: "flex",
        flexDirection: "column",
        alignItems: "center",
        gap: 4
      }
    }, m.possible > 0 && !isFuture && /*#__PURE__*/React.createElement("div", {
      style: {
        fontSize: 8,
        color: "var(--muted)",
        letterSpacing: 0
      }
    }, Math.round(m.rate * 100), "%"), /*#__PURE__*/React.createElement("div", {
      style: {
        width: "100%",
        height: `${h}px`,
        background: col,
        borderRadius: "3px 3px 0 0",
        transition: "height .5s ease",
        minHeight: isFuture ? 0 : m.possible > 0 ? 4 : 0
      }
    }), /*#__PURE__*/React.createElement("div", {
      style: {
        fontSize: 9,
        color: isNow ? "#2ecc98" : "var(--muted)",
        fontWeight: isNow ? 700 : 400
      }
    }, m.label));
  }))), /*#__PURE__*/React.createElement(InfographicPanel, {
    habits: habits,
    completions: completions,
    last7: null,
    totalCompletions: totalYear,
    bestStreak: Math.max(0, ...habits.map(h => getLongestStreak(h.id, completions, h.freq)))
  }), /*#__PURE__*/React.createElement("div", {
    style: {
      background: "var(--card)",
      border: "1px solid var(--border)",
      borderRadius: 14,
      padding: 16
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      fontSize: 11,
      fontWeight: 600,
      color: "var(--muted)",
      letterSpacing: ".1em",
      textTransform: "uppercase",
      marginBottom: 14
    }
  }, "Habit Leaderboard \u2014 ", viewYear), /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      flexDirection: "column",
      gap: 10
    }
  }, habitYear.map((h, i) => /*#__PURE__*/React.createElement("div", {
    key: h.id,
    style: {
      display: "flex",
      alignItems: "center",
      gap: 12
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      width: 22,
      height: 22,
      borderRadius: "50%",
      background: i < 3 ? ["#f59e0b", "#aaaaaa", "#cd7f32"][i] : "var(--border)",
      display: "flex",
      alignItems: "center",
      justifyContent: "center",
      fontSize: 10,
      fontWeight: 700,
      color: i < 3 ? "#000" : "var(--muted)",
      flexShrink: 0
    }
  }, i + 1), /*#__PURE__*/React.createElement("div", {
    style: {
      fontSize: 18,
      flexShrink: 0
    }
  }, h.icon), /*#__PURE__*/React.createElement("div", {
    style: {
      flex: 1,
      minWidth: 0
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      fontSize: 13,
      fontWeight: 600,
      marginBottom: 3
    }
  }, h.name), /*#__PURE__*/React.createElement("div", {
    style: {
      height: 4,
      background: "var(--border)",
      borderRadius: 2,
      overflow: "hidden"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      height: "100%",
      width: `${habitYear[0].done ? h.done / habitYear[0].done * 100 : 0}%`,
      background: h.color,
      borderRadius: 2,
      transition: "width .6s ease"
    }
  }))), /*#__PURE__*/React.createElement("div", {
    style: {
      fontSize: 13,
      fontWeight: 700,
      color: h.color,
      flexShrink: 0
    }
  }, h.done, "\xD7"))), habits.length === 0 && /*#__PURE__*/React.createElement("div", {
    style: {
      color: "var(--muted)",
      fontSize: 13
    }
  }, "No habits yet."))));
}

// ─── XP Bar (sidebar) ────────────────────────────────────────────────────────
function XPBar({
  habits,
  completions
}) {
  const lvl = getLevel(computeXP(habits, completions));
  return /*#__PURE__*/React.createElement("div", {
    style: {
      padding: "10px 12px",
      margin: "0 8px 8px",
      background: "var(--bg)",
      borderRadius: 12,
      border: "1px solid var(--border)"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      justifyContent: "space-between",
      alignItems: "center",
      marginBottom: 5
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      fontSize: 12,
      fontWeight: 700
    }
  }, lvl.icon, " ", lvl.title), /*#__PURE__*/React.createElement("span", {
    style: {
      fontSize: 10,
      color: "var(--muted)"
    }
  }, "Lv ", lvl.level)), /*#__PURE__*/React.createElement("div", {
    style: {
      height: 5,
      background: "var(--border)",
      borderRadius: 3,
      overflow: "hidden"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      height: "100%",
      width: `${lvl.pct * 100}%`,
      background: "linear-gradient(90deg,var(--primary),var(--accent))",
      borderRadius: 3,
      transition: "width .6s ease"
    }
  })), /*#__PURE__*/React.createElement("div", {
    style: {
      fontSize: 9,
      color: "var(--muted)",
      marginTop: 4
    }
  }, lvl.xp, " XP ", lvl.next ? `· ${lvl.nextXp - lvl.xp} to Lv ${lvl.level + 1}` : "· MAX"));
}

// ─── Achievements Page ────────────────────────────────────────────────────────
function AchievementsPage({
  habits,
  completions
}) {
  const xp = computeXP(habits, completions);
  const lvl = getLevel(xp);
  const unlocked = ACHIEVEMENTS.filter(a => a.check(habits, completions));
  const locked = ACHIEVEMENTS.filter(a => !a.check(habits, completions));
  return /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("div", {
    style: {
      marginBottom: 20
    }
  }, /*#__PURE__*/React.createElement("h1", {
    style: {
      fontSize: 28,
      fontWeight: 800,
      margin: "0 0 4px",
      letterSpacing: "-0.5px"
    }
  }, "Achievements"), /*#__PURE__*/React.createElement("div", {
    style: {
      color: "var(--muted)",
      fontSize: 13
    }
  }, "Your progress and rewards.")), /*#__PURE__*/React.createElement("div", {
    style: {
      background: "linear-gradient(135deg,#1a1a3e,#0f1f3d)",
      border: "1px solid #3b82f630",
      borderRadius: 18,
      padding: "24px 22px",
      marginBottom: 16
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      alignItems: "center",
      gap: 16,
      marginBottom: 18
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      fontSize: 48
    }
  }, lvl.icon), /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("div", {
    style: {
      fontSize: 22,
      fontWeight: 800
    }
  }, lvl.title), /*#__PURE__*/React.createElement("div", {
    style: {
      fontSize: 13,
      color: "var(--muted)"
    }
  }, "Level ", lvl.level, " \xB7 ", xp, " XP total"))), /*#__PURE__*/React.createElement("div", {
    style: {
      height: 8,
      background: "rgba(255,255,255,.08)",
      borderRadius: 4,
      overflow: "hidden",
      marginBottom: 6
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      height: "100%",
      width: `${lvl.pct * 100}%`,
      background: "linear-gradient(90deg,#2ecc98,#a855f7)",
      borderRadius: 4,
      transition: "width .8s ease"
    }
  })), /*#__PURE__*/React.createElement("div", {
    style: {
      fontSize: 11,
      color: "var(--muted)"
    }
  }, lvl.next ? `${lvl.nextXp - xp} XP until Level ${lvl.level + 1} — ${lvl.next.title} ${lvl.next.icon}` : "Maximum level reached! 🎉")), /*#__PURE__*/React.createElement("div", {
    style: {
      background: "var(--card)",
      border: "1px solid var(--border)",
      borderRadius: 14,
      padding: 16,
      marginBottom: 16
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      fontSize: 11,
      fontWeight: 600,
      color: "var(--muted)",
      letterSpacing: ".1em",
      textTransform: "uppercase",
      marginBottom: 12
    }
  }, "How You Earn XP"), /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      flexDirection: "column",
      gap: 8
    }
  }, [["✅", `${Object.keys(completions).length} completions`, `${Object.keys(completions).length * XP_PER_COMPLETION} XP`], ["🔥", "Streak bonuses", `${xp - Object.keys(completions).length * XP_PER_COMPLETION} XP`]].map(([icon, label, val]) => /*#__PURE__*/React.createElement("div", {
    key: label,
    style: {
      display: "flex",
      justifyContent: "space-between",
      alignItems: "center"
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      fontSize: 13
    }
  }, icon, " ", label), /*#__PURE__*/React.createElement("span", {
    style: {
      fontSize: 13,
      fontWeight: 700,
      color: "var(--primary)"
    }
  }, val))))), unlocked.length > 0 && /*#__PURE__*/React.createElement("div", {
    style: {
      marginBottom: 16
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      fontSize: 11,
      fontWeight: 600,
      color: "var(--muted)",
      letterSpacing: ".1em",
      textTransform: "uppercase",
      marginBottom: 10
    }
  }, "Unlocked (", unlocked.length, ")"), /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      flexDirection: "column",
      gap: 8
    }
  }, unlocked.map(a => /*#__PURE__*/React.createElement("div", {
    key: a.id,
    style: {
      background: "var(--card)",
      border: "1px solid #2ecc9830",
      borderRadius: 12,
      padding: "12px 14px",
      display: "flex",
      alignItems: "center",
      gap: 12
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      fontSize: 28,
      flexShrink: 0
    }
  }, a.icon), /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("div", {
    style: {
      fontWeight: 600,
      fontSize: 14
    }
  }, a.label), /*#__PURE__*/React.createElement("div", {
    style: {
      fontSize: 11,
      color: "var(--muted)"
    }
  }, a.desc)), /*#__PURE__*/React.createElement("div", {
    style: {
      marginLeft: "auto",
      fontSize: 11,
      color: "#2ecc98",
      fontWeight: 600
    }
  }, "\u2713 Earned"))))), locked.length > 0 && /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("div", {
    style: {
      fontSize: 11,
      fontWeight: 600,
      color: "var(--muted)",
      letterSpacing: ".1em",
      textTransform: "uppercase",
      marginBottom: 10
    }
  }, "Locked (", locked.length, ")"), /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      flexDirection: "column",
      gap: 8
    }
  }, locked.map(a => /*#__PURE__*/React.createElement("div", {
    key: a.id,
    style: {
      background: "var(--card)",
      border: "1px solid var(--border)",
      borderRadius: 12,
      padding: "12px 14px",
      display: "flex",
      alignItems: "center",
      gap: 12,
      opacity: 0.5
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      fontSize: 28,
      flexShrink: 0,
      filter: "grayscale(1)"
    }
  }, a.icon), /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("div", {
    style: {
      fontWeight: 600,
      fontSize: 14
    }
  }, a.label), /*#__PURE__*/React.createElement("div", {
    style: {
      fontSize: 11,
      color: "var(--muted)"
    }
  }, a.desc)), /*#__PURE__*/React.createElement("div", {
    style: {
      marginLeft: "auto",
      fontSize: 11,
      color: "var(--muted)"
    }
  }, "\uD83D\uDD12"))))));
}

// ─── Onboarding ───────────────────────────────────────────────────────────────
function OnboardingScreen({
  onComplete
}) {
  const [step, setStep] = useState(0);
  const [name, setName] = useState("");
  const [picked, setPicked] = useState([]);
  const starterHabits = [{
    icon: "🧘",
    name: "Meditation",
    color: "#a855f7",
    freq: "daily",
    desc: "10 minutes of calm to start the day"
  }, {
    icon: "📚",
    name: "Read 20 Pages",
    color: "#3b82f6",
    freq: "daily",
    desc: "Make progress on the current book"
  }, {
    icon: "🏃",
    name: "Morning Run",
    color: "#f43f5e",
    freq: "daily",
    desc: "30-minute jog or walk"
  }, {
    icon: "✍️",
    name: "Journaling",
    color: "#10b981",
    freq: "daily",
    desc: "Reflect on wins and gratitude"
  }, {
    icon: "🚿",
    name: "Cold Shower",
    color: "#0ea5e9",
    freq: "daily",
    desc: "Build resilience and boost energy"
  }, {
    icon: "💧",
    name: "Drink Water",
    color: "#06b6d4",
    freq: "daily",
    desc: "8 glasses throughout the day"
  }, {
    icon: "💪",
    name: "Workout",
    color: "#f59e0b",
    freq: "daily",
    desc: "Gym, yoga, or any exercise"
  }, {
    icon: "😴",
    name: "Sleep by 10 PM",
    color: "#6366f1",
    freq: "daily",
    desc: "Protect your recovery"
  }, {
    icon: "📵",
    name: "No Social Media",
    color: "#d946ef",
    freq: "daily",
    desc: "Stay present and focused"
  }, {
    icon: "📋",
    name: "Weekly Review",
    color: "#f59e0b",
    freq: "weekly",
    desc: "Review goals and plan ahead"
  }];
  const toggle = h => setPicked(p => p.find(x => x.name === h.name) ? p.filter(x => x.name !== h.name) : [...p, h]);
  const steps = [
  /*#__PURE__*/
  // Step 0 — Welcome
  React.createElement("div", {
    key: "welcome",
    style: {
      textAlign: "center",
      maxWidth: 420,
      margin: "0 auto"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      fontSize: 64,
      marginBottom: 16
    }
  }, "\u26A1"), /*#__PURE__*/React.createElement("h1", {
    style: {
      fontSize: 32,
      fontWeight: 800,
      marginBottom: 8,
      letterSpacing: "-1px"
    }
  }, "Welcome to Zenflow"), /*#__PURE__*/React.createElement("p", {
    style: {
      color: "var(--muted)",
      fontSize: 15,
      lineHeight: 1.6,
      marginBottom: 32
    }
  }, "Build powerful habits, track your progress, and become the best version of yourself \u2014 one day at a time."), /*#__PURE__*/React.createElement("input", {
    value: name,
    onChange: e => setName(e.target.value),
    placeholder: "What's your name?",
    style: {
      width: "100%",
      padding: "13px 16px",
      borderRadius: 12,
      border: "1px solid var(--border)",
      background: "var(--card)",
      color: "var(--text)",
      fontSize: 15,
      outline: "none",
      marginBottom: 16,
      fontFamily: "inherit"
    },
    onFocus: e => e.target.style.borderColor = "var(--primary)",
    onBlur: e => e.target.style.borderColor = "var(--border)"
  }), /*#__PURE__*/React.createElement("button", {
    onClick: () => setStep(1),
    disabled: !name.trim(),
    style: {
      width: "100%",
      padding: "14px",
      borderRadius: 12,
      border: "none",
      background: name.trim() ? "var(--primary)" : "var(--border)",
      color: name.trim() ? "#071810" : "var(--muted)",
      fontWeight: 700,
      fontSize: 15,
      cursor: name.trim() ? "pointer" : "default",
      transition: ".2s"
    }
  }, "Let's go \u2192")),
  /*#__PURE__*/
  // Step 1 — Pick habits
  React.createElement("div", {
    key: "habits",
    style: {
      maxWidth: 480,
      margin: "0 auto"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      textAlign: "center",
      marginBottom: 24
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      fontSize: 40,
      marginBottom: 8
    }
  }, "\uD83C\uDFAF"), /*#__PURE__*/React.createElement("h2", {
    style: {
      fontSize: 24,
      fontWeight: 800,
      marginBottom: 6
    }
  }, "Hey ", name, "! Pick your habits"), /*#__PURE__*/React.createElement("p", {
    style: {
      color: "var(--muted)",
      fontSize: 13
    }
  }, "Choose what you want to build. You can add more later.")), /*#__PURE__*/React.createElement("div", {
    style: {
      display: "grid",
      gridTemplateColumns: "1fr 1fr",
      gap: 8,
      marginBottom: 20
    }
  }, starterHabits.map(h => {
    const sel = !!picked.find(x => x.name === h.name);
    return /*#__PURE__*/React.createElement("div", {
      key: h.name,
      onClick: () => toggle(h),
      style: {
        background: sel ? `${h.color}18` : "var(--card)",
        border: `1.5px solid ${sel ? h.color : "var(--border)"}`,
        borderRadius: 12,
        padding: "12px 14px",
        cursor: "pointer",
        transition: ".15s",
        display: "flex",
        alignItems: "center",
        gap: 10
      }
    }, /*#__PURE__*/React.createElement("span", {
      style: {
        fontSize: 20
      }
    }, h.icon), /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("div", {
      style: {
        fontSize: 12,
        fontWeight: 600
      }
    }, h.name), /*#__PURE__*/React.createElement("div", {
      style: {
        fontSize: 10,
        color: "var(--muted)"
      }
    }, h.freq)), sel && /*#__PURE__*/React.createElement("div", {
      style: {
        marginLeft: "auto",
        color: h.color,
        fontSize: 14,
        fontWeight: 700
      }
    }, "\u2713"));
  })), /*#__PURE__*/React.createElement("button", {
    onClick: () => onComplete(name, picked),
    disabled: picked.length === 0,
    style: {
      width: "100%",
      padding: "14px",
      borderRadius: 12,
      border: "none",
      background: picked.length ? "var(--primary)" : "var(--border)",
      color: picked.length ? "#071810" : "var(--muted)",
      fontWeight: 700,
      fontSize: 15,
      cursor: picked.length ? "pointer" : "default",
      transition: ".2s"
    }
  }, "Start with ", picked.length, " habit", picked.length !== 1 ? "s" : "", " \uD83D\uDE80"))];
  return /*#__PURE__*/React.createElement("div", {
    style: {
      position: "fixed",
      inset: 0,
      background: "var(--bg)",
      zIndex: 9999,
      display: "flex",
      flexDirection: "column",
      alignItems: "center",
      justifyContent: "center",
      padding: 32
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      gap: 6,
      marginBottom: 40
    }
  }, [0, 1].map(i => /*#__PURE__*/React.createElement("div", {
    key: i,
    style: {
      width: i === step ? 20 : 6,
      height: 6,
      borderRadius: 3,
      background: i <= step ? "var(--primary)" : "var(--border)",
      transition: ".3s"
    }
  }))), steps[step]);
}

// ─── Splash Screen ────────────────────────────────────────────────────────────
// ─── Zenflow SVG Icon ─────────────────────────────────────────────────────────
function ZenflowIcon({
  size = 80,
  style = {}
}) {
  const r = size * 0.18; // corner radius
  return /*#__PURE__*/React.createElement("svg", {
    width: size,
    height: size,
    viewBox: "0 0 100 100",
    xmlns: "http://www.w3.org/2000/svg",
    style: style
  }, /*#__PURE__*/React.createElement("defs", null, /*#__PURE__*/React.createElement("linearGradient", {
    id: "zf-wave",
    x1: "0%",
    y1: "0%",
    x2: "100%",
    y2: "0%"
  }, /*#__PURE__*/React.createElement("stop", {
    offset: "0%",
    stopColor: "#10b981"
  }), /*#__PURE__*/React.createElement("stop", {
    offset: "50%",
    stopColor: "#14b8a6"
  }), /*#__PURE__*/React.createElement("stop", {
    offset: "100%",
    stopColor: "#a855f7"
  })), /*#__PURE__*/React.createElement("linearGradient", {
    id: "zf-bg",
    x1: "0%",
    y1: "0%",
    x2: "100%",
    y2: "100%"
  }, /*#__PURE__*/React.createElement("stop", {
    offset: "0%",
    stopColor: "#0d1117"
  }), /*#__PURE__*/React.createElement("stop", {
    offset: "100%",
    stopColor: "#111827"
  })), /*#__PURE__*/React.createElement("filter", {
    id: "zf-glow"
  }, /*#__PURE__*/React.createElement("feGaussianBlur", {
    stdDeviation: "1.5",
    result: "blur"
  }), /*#__PURE__*/React.createElement("feMerge", null, /*#__PURE__*/React.createElement("feMergeNode", {
    in: "blur"
  }), /*#__PURE__*/React.createElement("feMergeNode", {
    in: "SourceGraphic"
  })))), /*#__PURE__*/React.createElement("rect", {
    x: "0",
    y: "0",
    width: "100",
    height: "100",
    rx: "22",
    ry: "22",
    fill: "url(#zf-bg)"
  }), /*#__PURE__*/React.createElement("rect", {
    x: "1.5",
    y: "1.5",
    width: "97",
    height: "97",
    rx: "21",
    ry: "21",
    fill: "none",
    stroke: "#ffffff08",
    strokeWidth: "1.5"
  }), /*#__PURE__*/React.createElement("path", {
    d: "M10 50 C18 34, 26 34, 34 50 C42 66, 50 66, 58 50 C66 34, 74 34, 82 50 C88 62, 92 62, 90 50",
    fill: "none",
    stroke: "url(#zf-wave)",
    strokeWidth: "4.5",
    strokeLinecap: "round",
    filter: "url(#zf-glow)"
  }), /*#__PURE__*/React.createElement("path", {
    d: "M10 50 C18 34, 26 34, 34 50 C42 66, 50 66, 58 50 C66 34, 74 34, 82 50 C88 62, 92 62, 90 50",
    fill: "none",
    stroke: "url(#zf-wave)",
    strokeWidth: "8",
    strokeLinecap: "round",
    opacity: "0.15"
  }), /*#__PURE__*/React.createElement("circle", {
    cx: "50",
    cy: "50",
    r: "6.5",
    fill: "white",
    opacity: "0.95"
  }), /*#__PURE__*/React.createElement("circle", {
    cx: "50",
    cy: "50",
    r: "3.5",
    fill: "#10b981"
  }), /*#__PURE__*/React.createElement("circle", {
    cx: "50",
    cy: "50",
    r: "10",
    fill: "#10b981",
    opacity: "0.12"
  }));
}

// ─── Legal Modal Shell ────────────────────────────────────────────────────────
function LegalModal({
  title,
  onClose,
  children
}) {
  return /*#__PURE__*/React.createElement("div", {
    style: {
      position: "fixed",
      inset: 0,
      background: "rgba(0,0,0,.82)",
      zIndex: 10000,
      display: "flex",
      alignItems: "center",
      justifyContent: "center",
      padding: 20
    },
    onClick: e => e.target === e.currentTarget && onClose()
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      background: "linear-gradient(145deg,#0e0e1a,#151525)",
      border: "1px solid #ffffff14",
      borderRadius: 20,
      width: "100%",
      maxWidth: 640,
      maxHeight: "82vh",
      display: "flex",
      flexDirection: "column",
      animation: "pop-in .3s cubic-bezier(.34,1.56,.64,1)"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      alignItems: "center",
      justifyContent: "space-between",
      padding: "20px 24px 16px",
      borderBottom: "1px solid #ffffff0e"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      fontFamily: "'Syne',sans-serif",
      fontWeight: 700,
      fontSize: 17,
      color: "#f0f0f8"
    }
  }, title), /*#__PURE__*/React.createElement("button", {
    onClick: onClose,
    style: {
      background: "none",
      border: "none",
      color: "#6060a0",
      cursor: "pointer",
      fontSize: 20,
      lineHeight: 1
    }
  }, "\u2715")), /*#__PURE__*/React.createElement("div", {
    style: {
      overflowY: "auto",
      padding: "20px 24px 24px",
      color: "#c0c0d8",
      fontSize: 13,
      lineHeight: 1.8
    }
  }, children)));
}
function LegalH({
  children
}) {
  return /*#__PURE__*/React.createElement("div", {
    style: {
      fontFamily: "'Syne',sans-serif",
      fontWeight: 700,
      fontSize: 13,
      color: "#f0f0f8",
      marginTop: 20,
      marginBottom: 6,
      letterSpacing: ".02em"
    }
  }, children);
}
function LegalP({
  children
}) {
  return /*#__PURE__*/React.createElement("p", {
    style: {
      marginBottom: 10,
      color: "#a0a0c0"
    }
  }, children);
}

// ─── Privacy Policy ───────────────────────────────────────────────────────────
function PrivacyModal({
  onClose
}) {
  return /*#__PURE__*/React.createElement(LegalModal, {
    title: "\uD83D\uDD12 Privacy Policy",
    onClose: onClose
  }, /*#__PURE__*/React.createElement(LegalP, null, "Last updated: June 2026 \xB7 Effective immediately"), /*#__PURE__*/React.createElement(LegalH, null, "1. Who We Are"), /*#__PURE__*/React.createElement(LegalP, null, "Zenflow is a personal productivity application built for local, offline-first use. It is developed and maintained as an independent project. For questions, contact: privacy@zenflow.app"), /*#__PURE__*/React.createElement(LegalH, null, "2. What Data We Collect"), /*#__PURE__*/React.createElement(LegalP, null, "Zenflow collects no data from you. The app operates entirely on your device. Your habits, completions, streaks, roadmap progress, custom quotes, and all settings are stored locally \u2014 on your machine only \u2014 using either the Tauri file-system store or your browser's localStorage."), /*#__PURE__*/React.createElement(LegalH, null, "3. Local Storage Only"), /*#__PURE__*/React.createElement(LegalP, null, "All app data lives in a single local file (", /*#__PURE__*/React.createElement("code", {
    style: {
      background: "#ffffff10",
      padding: "1px 5px",
      borderRadius: 4
    }
  }, "zenflow.json"), ") on your device. This file never leaves your machine. No cloud sync, no remote backup, no third-party storage provider is involved."), /*#__PURE__*/React.createElement(LegalH, null, "4. No Tracking or Analytics"), /*#__PURE__*/React.createElement(LegalP, null, "Zenflow contains zero analytics, zero telemetry, zero crash reporting, and zero advertising SDKs. We do not track how you use the app, which features you access, or how long you spend in any view. There are no pixels, beacons, or fingerprinting mechanisms of any kind."), /*#__PURE__*/React.createElement(LegalH, null, "5. No Account Required"), /*#__PURE__*/React.createElement(LegalP, null, "Zenflow requires no account, no sign-up, and no email address. Your name (if entered during onboarding) is stored locally only and is never transmitted anywhere."), /*#__PURE__*/React.createElement(LegalH, null, "6. No Third-Party Sharing"), /*#__PURE__*/React.createElement(LegalP, null, "Because we collect no data, we share no data. There are no third-party data processors, advertisers, or analytics partners with access to your information."), /*#__PURE__*/React.createElement(LegalH, null, "7. External Resources"), /*#__PURE__*/React.createElement(LegalP, null, "Zenflow makes zero outbound network requests. Fonts (Syne and DM Sans) are bundled directly inside the app and loaded from your device \u2014 no connection to Google Fonts or any other server is made at any point. Zenflow works fully offline."), /*#__PURE__*/React.createElement(LegalH, null, "8. Children's Privacy"), /*#__PURE__*/React.createElement(LegalP, null, "Zenflow does not knowingly collect information from children under 13. Since we collect no data at all, no special provisions are required \u2014 but we note this for completeness under COPPA and similar regulations."), /*#__PURE__*/React.createElement(LegalH, null, "9. Changes to This Policy"), /*#__PURE__*/React.createElement(LegalP, null, "If this policy changes materially, the updated version will be included in the next app release. The \"last updated\" date at the top will reflect any changes. Continued use of the app after an update constitutes acceptance of the revised policy."));
}

// ─── Terms of Service ─────────────────────────────────────────────────────────
function TermsModal({
  onClose
}) {
  return /*#__PURE__*/React.createElement(LegalModal, {
    title: "\uD83D\uDCCB Terms of Service",
    onClose: onClose
  }, /*#__PURE__*/React.createElement(LegalP, null, "Last updated: June 2026 \xB7 Please read these terms carefully before using Zenflow."), /*#__PURE__*/React.createElement(LegalH, null, "1. Acceptance of Terms"), /*#__PURE__*/React.createElement(LegalP, null, "By installing or using Zenflow, you agree to be bound by these Terms of Service. If you do not agree, please uninstall the application. Your continued use constitutes ongoing acceptance."), /*#__PURE__*/React.createElement(LegalH, null, "2. License Grant"), /*#__PURE__*/React.createElement(LegalP, null, "Zenflow grants you a personal, non-exclusive, non-transferable, revocable license to use this application for your own personal, non-commercial purposes. This license does not include the right to copy, modify, distribute, sell, or sublicense any part of the application."), /*#__PURE__*/React.createElement(LegalH, null, "3. Permitted Use"), /*#__PURE__*/React.createElement(LegalP, null, "You may use Zenflow to track personal habits, manage learning roadmaps, and view productivity analytics. The app is intended for lawful personal use only. You agree not to use the app in any way that violates applicable local, national, or international laws or regulations."), /*#__PURE__*/React.createElement(LegalH, null, "4. Content Ownership"), /*#__PURE__*/React.createElement(LegalP, null, "All content you create within Zenflow \u2014 your habits, notes, custom quotes, and settings \u2014 belongs entirely to you. We claim no ownership over your personal data. Because all data is stored locally, you are solely responsible for backing it up."), /*#__PURE__*/React.createElement(LegalH, null, "5. Intellectual Property"), /*#__PURE__*/React.createElement(LegalP, null, "The Zenflow name, logo, icon, design, and source code are the intellectual property of the Zenflow project. All rights not expressly granted in these Terms are reserved. The Zenflow icon design, wave motif, and colour scheme are original works protected under copyright law."), /*#__PURE__*/React.createElement(LegalH, null, "6. No Warranty"), /*#__PURE__*/React.createElement(LegalP, null, "Zenflow is provided \"as is\" and \"as available\" without warranty of any kind, express or implied. We do not warrant that the app will be error-free, uninterrupted, or meet your specific requirements. Your use of the app is at your sole risk."), /*#__PURE__*/React.createElement(LegalH, null, "7. Limitation of Liability"), /*#__PURE__*/React.createElement(LegalP, null, "To the maximum extent permitted by applicable law, Zenflow and its developers shall not be liable for any indirect, incidental, special, consequential, or punitive damages \u2014 including loss of data, loss of productivity, or loss of profits \u2014 arising from your use of or inability to use the app."), /*#__PURE__*/React.createElement(LegalH, null, "8. Data Responsibility"), /*#__PURE__*/React.createElement(LegalP, null, "Since all data is stored locally on your device, you are responsible for its safety and integrity. We recommend regularly exporting or backing up your data. We are not responsible for data loss resulting from device failure, operating system issues, or accidental deletion."), /*#__PURE__*/React.createElement(LegalH, null, "9. Modifications to the App or Terms"), /*#__PURE__*/React.createElement(LegalP, null, "We reserve the right to modify Zenflow or these Terms at any time. Updated Terms will be included with new app releases. Material changes will be highlighted in release notes. Continued use after an update means you accept the revised Terms."), /*#__PURE__*/React.createElement(LegalH, null, "10. Governing Law"), /*#__PURE__*/React.createElement(LegalP, null, "These Terms shall be governed by and construed in accordance with applicable law in the jurisdiction in which you reside. Any disputes shall be resolved through good-faith negotiation before any formal proceedings."));
}

// ─── About ────────────────────────────────────────────────────────────────────
function AboutModal({
  onClose
}) {
  return /*#__PURE__*/React.createElement(LegalModal, {
    title: "\u26A1 About Zenflow",
    onClose: onClose
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      alignItems: "center",
      gap: 16,
      marginBottom: 20,
      paddingBottom: 20,
      borderBottom: "1px solid #ffffff0e"
    }
  }, /*#__PURE__*/React.createElement(ZenflowIcon, {
    size: 56
  }), /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("div", {
    style: {
      fontFamily: "'Syne',sans-serif",
      fontWeight: 800,
      fontSize: 22,
      color: "#f0f0f8"
    }
  }, "Zenflow"), /*#__PURE__*/React.createElement("div", {
    style: {
      fontSize: 12,
      color: "#6060a0",
      marginTop: 2
    }
  }, "Version 1.0.0 \xB7 June 2026"), /*#__PURE__*/React.createElement("div", {
    style: {
      fontSize: 12,
      color: "#10b981",
      marginTop: 4
    }
  }, "Flow through your goals"))), /*#__PURE__*/React.createElement(LegalH, null, "Mission"), /*#__PURE__*/React.createElement(LegalP, null, "Zenflow exists to help you build meaningful habits, track long-term learning goals, and develop the discipline that compounds over time \u2014 without distractions, subscriptions, or data harvesting. Everything lives on your device. Everything is yours."), /*#__PURE__*/React.createElement(LegalH, null, "Features"), [["✅", "Daily habit tracking", "Check off habits each day with streaks and XP rewards"], ["📅", "Calendar view", "See your completion history across any month at a glance"], ["🎓", "Learning Roadmap", "400+ checkable topics across Cybersecurity, German, and Order Flow Trading"], ["📊", "Analytics", "Visual breakdowns of your completion rates, streaks, and trends"], ["🗓️", "Year Review", "Full 12-month heatmap to see your long-term consistency"], ["🏆", "Achievements", "Unlock badges and level up as you build consistency"], ["🗂️", "Groups", "Organise habits into custom categories"], ["💬", "Custom Quotes", "Add your own motivational quotes to the daily feed"], ["🔔", "Daily Reminder", "Set a notification time to stay on track"], ["🎨", "Themes", "Dark/light mode with 8 accent colours to match your style"], ["🛡️", "Streak Shield", "Protect a streak once per week when life gets in the way"]].map(([icon, title, desc]) => /*#__PURE__*/React.createElement("div", {
    key: title,
    style: {
      display: "flex",
      gap: 12,
      marginBottom: 10
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      fontSize: 16,
      flexShrink: 0,
      marginTop: 1
    }
  }, icon), /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("div", {
    style: {
      fontWeight: 600,
      color: "#d0d0e8",
      fontSize: 13
    }
  }, title), /*#__PURE__*/React.createElement("div", {
    style: {
      fontSize: 12,
      color: "#7070a0"
    }
  }, desc)))), /*#__PURE__*/React.createElement(LegalH, null, "Tech Stack"), [["⚛️", "React 18", "UI framework — hooks, state management, component architecture"], ["🦀", "Tauri 2", "Native desktop shell — Rust backend, cross-platform (Windows/macOS/Linux)"], ["⚡", "Vite 6", "Build tool and development server"], ["💾", "Tauri Store Plugin", "Persistent local storage (falls back to localStorage in browser)"], ["🔔", "Tauri Notifications", "Native OS notifications for daily reminders"], ["🎨", "Fontsource (bundled)", "Syne + DM Sans loaded locally — zero Google Fonts network calls, fully offline"]].map(([icon, name, desc]) => /*#__PURE__*/React.createElement("div", {
    key: name,
    style: {
      display: "flex",
      gap: 12,
      marginBottom: 8
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      fontSize: 14,
      flexShrink: 0
    }
  }, icon), /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("div", {
    style: {
      fontWeight: 600,
      color: "#d0d0e8",
      fontSize: 12
    }
  }, name), /*#__PURE__*/React.createElement("div", {
    style: {
      fontSize: 11,
      color: "#6060a0"
    }
  }, desc)))), /*#__PURE__*/React.createElement(LegalH, null, "Privacy Commitment"), /*#__PURE__*/React.createElement(LegalP, null, "Zenflow is 100% local. No accounts. No tracking. No analytics. No ads \u2014 ever. Your data belongs to you and stays on your device."), /*#__PURE__*/React.createElement("div", {
    style: {
      marginTop: 24,
      padding: "14px 16px",
      background: "#ffffff05",
      borderRadius: 12,
      border: "1px solid #ffffff0a",
      textAlign: "center"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      fontSize: 11,
      color: "#40406a"
    }
  }, "\xA9 2026 Zenflow. All rights reserved."), /*#__PURE__*/React.createElement("div", {
    style: {
      fontSize: 11,
      color: "#40406a",
      marginTop: 3
    }
  }, "Made with \u2665 for focused humans everywhere.")));
}

// ─── Copyright Agreement Modal (first launch only) ────────────────────────────
function CopyrightModal({
  onAgree
}) {
  const [checked, setChecked] = useState(false);
  return /*#__PURE__*/React.createElement("div", {
    style: {
      position: "fixed",
      inset: 0,
      background: "rgba(0,0,0,.92)",
      zIndex: 10001,
      display: "flex",
      alignItems: "center",
      justifyContent: "center",
      padding: 20
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      background: "linear-gradient(145deg,#0e0e1a,#151525)",
      border: "1px solid #10b98130",
      borderRadius: 24,
      width: "100%",
      maxWidth: 480,
      padding: 36,
      animation: "pop-in .4s cubic-bezier(.34,1.56,.64,1)",
      display: "flex",
      flexDirection: "column",
      alignItems: "center",
      textAlign: "center"
    }
  }, /*#__PURE__*/React.createElement(ZenflowIcon, {
    size: 64,
    style: {
      marginBottom: 20
    }
  }), /*#__PURE__*/React.createElement("div", {
    style: {
      fontFamily: "'Syne',sans-serif",
      fontWeight: 800,
      fontSize: 22,
      color: "#f0f0f8",
      marginBottom: 6
    }
  }, "Welcome to Zenflow"), /*#__PURE__*/React.createElement("div", {
    style: {
      fontSize: 13,
      color: "#6060a0",
      marginBottom: 24
    }
  }, "Before you begin, please review the following"), /*#__PURE__*/React.createElement("div", {
    style: {
      background: "#ffffff06",
      border: "1px solid #ffffff0e",
      borderRadius: 14,
      padding: 20,
      textAlign: "left",
      marginBottom: 20,
      width: "100%"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      fontFamily: "'Syne',sans-serif",
      fontWeight: 700,
      fontSize: 12,
      color: "#10b981",
      letterSpacing: ".08em",
      textTransform: "uppercase",
      marginBottom: 12
    }
  }, "\xA9 Copyright Notice"), /*#__PURE__*/React.createElement("p", {
    style: {
      fontSize: 12,
      color: "#a0a0c0",
      lineHeight: 1.8,
      marginBottom: 10
    }
  }, "Zenflow \u2014 including its name, icon, wave motif, design system, and source code \u2014 is original work protected under copyright law. All rights reserved \xA9 2026 Zenflow."), /*#__PURE__*/React.createElement("p", {
    style: {
      fontSize: 12,
      color: "#a0a0c0",
      lineHeight: 1.8,
      marginBottom: 10
    }
  }, "You are granted a personal, non-commercial license to use this application. You may not copy, redistribute, sell, reverse-engineer for commercial purposes, or rebrand any part of Zenflow without explicit written permission."), /*#__PURE__*/React.createElement("p", {
    style: {
      fontSize: 12,
      color: "#a0a0c0",
      lineHeight: 1.8
    }
  }, "All data you create within Zenflow belongs entirely to you and is stored locally on your device. We collect nothing.")), /*#__PURE__*/React.createElement("label", {
    style: {
      display: "flex",
      alignItems: "flex-start",
      gap: 12,
      marginBottom: 24,
      cursor: "pointer",
      textAlign: "left",
      width: "100%"
    }
  }, /*#__PURE__*/React.createElement("div", {
    onClick: () => setChecked(c => !c),
    style: {
      width: 20,
      height: 20,
      borderRadius: 6,
      border: `2px solid ${checked ? "#10b981" : "#40406a"}`,
      background: checked ? "#10b981" : "transparent",
      flexShrink: 0,
      marginTop: 1,
      display: "flex",
      alignItems: "center",
      justifyContent: "center",
      transition: ".2s",
      cursor: "pointer"
    }
  }, checked && /*#__PURE__*/React.createElement("span", {
    style: {
      color: "#0a0a14",
      fontSize: 12,
      fontWeight: 800
    }
  }, "\u2713")), /*#__PURE__*/React.createElement("span", {
    style: {
      fontSize: 12,
      color: "#8080b0",
      lineHeight: 1.7
    }
  }, "I have read and agree to the copyright terms above. I understand that Zenflow is protected intellectual property and agree to use it only as permitted.")), /*#__PURE__*/React.createElement("button", {
    disabled: !checked,
    onClick: onAgree,
    style: {
      width: "100%",
      padding: "14px 0",
      borderRadius: 12,
      border: "none",
      background: checked ? "linear-gradient(135deg,#10b981,#14b8a6)" : "#1a1a2e",
      color: checked ? "#fff" : "#40406a",
      fontSize: 14,
      fontWeight: 700,
      cursor: checked ? "pointer" : "not-allowed",
      transition: ".3s",
      fontFamily: "'Syne',sans-serif",
      letterSpacing: ".02em"
    }
  }, "I Understand & Agree \u2192")));
}

// ─── Splash Screen ────────────────────────────────────────────────────────────
function SplashScreen({
  onDone
}) {
  const [phase, setPhase] = useState(0); // 0=logo, 1=tagline, 2=fade
  useEffect(() => {
    const t1 = setTimeout(() => setPhase(1), 600);
    const t2 = setTimeout(() => setPhase(2), 1800);
    const t3 = setTimeout(() => onDone(), 2400);
    return () => [t1, t2, t3].forEach(clearTimeout);
  }, []);
  return /*#__PURE__*/React.createElement("div", {
    style: {
      position: "fixed",
      inset: 0,
      background: "#0a0a14",
      display: "flex",
      flexDirection: "column",
      alignItems: "center",
      justifyContent: "center",
      zIndex: 9999,
      transition: "opacity .5s ease",
      opacity: phase === 2 ? 0 : 1
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      transform: phase >= 1 ? "scale(1)" : "scale(0.5)",
      transition: "transform .5s cubic-bezier(.34,1.56,.64,1)",
      marginBottom: 24
    }
  }, /*#__PURE__*/React.createElement(ZenflowIcon, {
    size: 80
  })), /*#__PURE__*/React.createElement("div", {
    style: {
      fontFamily: "'Syne',sans-serif",
      fontWeight: 800,
      fontSize: 28,
      color: "#f0f0f8",
      letterSpacing: "-0.5px",
      opacity: phase >= 1 ? 1 : 0,
      transition: "opacity .4s ease .2s"
    }
  }, "Zenflow"), /*#__PURE__*/React.createElement("div", {
    style: {
      fontSize: 13,
      color: "#6060a0",
      marginTop: 6,
      opacity: phase >= 1 ? 1 : 0,
      transition: "opacity .4s ease .4s"
    }
  }, "Flow through your goals"), /*#__PURE__*/React.createElement("div", {
    style: {
      position: "absolute",
      bottom: 28,
      fontSize: 11,
      color: "#30305a",
      opacity: phase >= 1 ? 1 : 0,
      transition: "opacity .4s ease .6s",
      letterSpacing: ".03em"
    }
  }, "\xA9 2026 Zenflow \xB7 All rights reserved"), /*#__PURE__*/React.createElement("div", {
    style: {
      position: "absolute",
      width: 160,
      height: 160,
      borderRadius: "50%",
      border: "1px solid #10b98128",
      animation: "pulse-ring 1.5s ease-out infinite"
    }
  }));
}

// ─── Level Up Modal ────────────────────────────────────────────────────────────
function LevelUpModal({
  level,
  onClose
}) {
  if (!level) return null;
  return /*#__PURE__*/React.createElement("div", {
    style: {
      position: "fixed",
      inset: 0,
      background: "rgba(0,0,0,.85)",
      zIndex: 998,
      display: "flex",
      alignItems: "center",
      justifyContent: "center"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      background: "linear-gradient(145deg,#0e0e1a,#1a1a30)",
      border: "1px solid #a855f740",
      borderRadius: 24,
      padding: 40,
      textAlign: "center",
      maxWidth: 340,
      animation: "pop-in .4s cubic-bezier(.34,1.56,.64,1)"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      fontSize: 64,
      marginBottom: 12,
      animation: "spin-once 0.6s ease"
    }
  }, level.icon), /*#__PURE__*/React.createElement("div", {
    style: {
      fontSize: 11,
      letterSpacing: ".15em",
      textTransform: "uppercase",
      color: "#a855f7",
      marginBottom: 8
    }
  }, "Level Up!"), /*#__PURE__*/React.createElement("div", {
    style: {
      fontFamily: "'Syne',sans-serif",
      fontWeight: 800,
      fontSize: 26,
      color: "#f0f0f8",
      marginBottom: 6
    }
  }, level.title), /*#__PURE__*/React.createElement("div", {
    style: {
      fontSize: 13,
      color: "#6060a0",
      marginBottom: 24,
      lineHeight: 1.6
    }
  }, "You've reached level ", level.level, ". Your dedication is paying off \u2014 keep the momentum going!"), /*#__PURE__*/React.createElement("button", {
    onClick: onClose,
    style: {
      background: "linear-gradient(135deg,#2ecc98,#a855f7)",
      border: "none",
      borderRadius: 12,
      padding: "12px 32px",
      color: "#000",
      fontWeight: 700,
      fontSize: 14,
      cursor: "pointer"
    }
  }, "Keep Going \uD83D\uDE80")));
}

// ─── Streak Shield Modal ───────────────────────────────────────────────────────
function StreakShieldBadge({
  shields
}) {
  if (shields === 0) return null;
  return /*#__PURE__*/React.createElement("div", {
    title: `${shields} streak shield${shields > 1 ? "s" : ""} — protects your streak on a missed day`,
    style: {
      display: "inline-flex",
      alignItems: "center",
      gap: 4,
      background: "#f59e0b20",
      border: "1px solid #f59e0b40",
      borderRadius: 8,
      padding: "3px 8px",
      fontSize: 11,
      color: "#f59e0b",
      fontWeight: 600
    }
  }, "\uD83D\uDEE1\uFE0F ", shields);
}

// ─── Focus Mode Banner ─────────────────────────────────────────────────────────
function FocusBanner({
  habit,
  onDismiss
}) {
  if (!habit) return null;
  return /*#__PURE__*/React.createElement("div", {
    style: {
      background: `${habit.color}18`,
      border: `1px solid ${habit.color}40`,
      borderRadius: 14,
      padding: "14px 18px",
      marginBottom: 18,
      display: "flex",
      alignItems: "center",
      gap: 14
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      fontSize: 28
    }
  }, habit.icon), /*#__PURE__*/React.createElement("div", {
    style: {
      flex: 1
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      fontSize: 10,
      fontWeight: 600,
      textTransform: "uppercase",
      letterSpacing: ".1em",
      color: habit.color,
      marginBottom: 2
    }
  }, "\u2B50 Today's Focus Habit"), /*#__PURE__*/React.createElement("div", {
    style: {
      fontSize: 15,
      fontWeight: 700
    }
  }, habit.name), habit.desc && /*#__PURE__*/React.createElement("div", {
    style: {
      fontSize: 11,
      color: "var(--muted)",
      marginTop: 2
    }
  }, habit.desc)), /*#__PURE__*/React.createElement("button", {
    onClick: onDismiss,
    style: {
      background: "none",
      border: "none",
      color: "var(--muted)",
      cursor: "pointer",
      fontSize: 18,
      lineHeight: 1
    }
  }, "\xD7"));
}

// ─── Page Transition Wrapper ───────────────────────────────────────────────────
function PageTransition({
  children,
  pageKey
}) {
  const [visible, setVisible] = useState(false);
  useEffect(() => {
    setVisible(false);
    const t = setTimeout(() => setVisible(true), 30);
    return () => clearTimeout(t);
  }, [pageKey]);
  return /*#__PURE__*/React.createElement("div", {
    style: {
      opacity: visible ? 1 : 0,
      transform: visible ? "translateY(0)" : "translateY(8px)",
      transition: "opacity .25s ease, transform .25s ease"
    }
  }, children);
}

// ─── Custom Quotes Manager ─────────────────────────────────────────────────────
function QuotesPage({
  customQuotes,
  onSave
}) {
  const [input, setInput] = useState("");
  const [author, setAuthor] = useState("");
  return /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("h1", {
    style: {
      fontSize: 28,
      fontWeight: 800,
      marginBottom: 4,
      letterSpacing: "-0.5px"
    }
  }, "My Quotes"), /*#__PURE__*/React.createElement("div", {
    style: {
      color: "var(--muted)",
      fontSize: 13,
      marginBottom: 20
    }
  }, "Add your own motivational quotes to the daily rotation."), /*#__PURE__*/React.createElement("div", {
    style: {
      background: "var(--card)",
      border: "1px solid var(--border)",
      borderRadius: 14,
      padding: 16,
      marginBottom: 16
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      fontSize: 11,
      fontWeight: 600,
      color: "var(--muted)",
      textTransform: "uppercase",
      letterSpacing: ".1em",
      marginBottom: 12
    }
  }, "Add New Quote"), /*#__PURE__*/React.createElement("textarea", {
    value: input,
    onChange: e => setInput(e.target.value),
    placeholder: "Type your quote here...",
    rows: 3,
    style: {
      width: "100%",
      background: "var(--bg)",
      border: "1px solid var(--border)",
      borderRadius: 10,
      color: "var(--text)",
      fontSize: 13,
      padding: "10px 12px",
      resize: "none",
      outline: "none",
      fontFamily: "'DM Sans',sans-serif",
      marginBottom: 8
    }
  }), /*#__PURE__*/React.createElement("input", {
    value: author,
    onChange: e => setAuthor(e.target.value),
    placeholder: "Author (optional)",
    style: {
      width: "100%",
      background: "var(--bg)",
      border: "1px solid var(--border)",
      borderRadius: 10,
      color: "var(--text)",
      fontSize: 13,
      padding: "8px 12px",
      outline: "none",
      fontFamily: "'DM Sans',sans-serif",
      marginBottom: 12
    }
  }), /*#__PURE__*/React.createElement("button", {
    onClick: () => {
      if (!input.trim()) return;
      onSave([...customQuotes, {
        text: sanitiseText(input.trim()),
        author: sanitiseText(author.trim()) || "You"
      }]);
      setInput("");
      setAuthor("");
    },
    style: {
      background: "var(--primary)",
      border: "none",
      borderRadius: 10,
      padding: "9px 20px",
      color: "#000",
      fontWeight: 700,
      fontSize: 13,
      cursor: "pointer"
    }
  }, "Add Quote")), /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      flexDirection: "column",
      gap: 10
    }
  }, customQuotes.map((q, i) => /*#__PURE__*/React.createElement("div", {
    key: i,
    style: {
      background: "var(--card)",
      border: "1px solid var(--border)",
      borderRadius: 12,
      padding: "14px 16px",
      display: "flex",
      gap: 12,
      alignItems: "flex-start"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      flex: 1
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      fontSize: 13,
      fontStyle: "italic",
      color: "var(--text)",
      lineHeight: 1.5
    }
  }, "\"", q.text, "\""), /*#__PURE__*/React.createElement("div", {
    style: {
      fontSize: 11,
      color: "var(--muted)",
      marginTop: 4
    }
  }, "\u2014 ", q.author)), /*#__PURE__*/React.createElement("button", {
    onClick: () => onSave(customQuotes.filter((_, j) => j !== i)),
    style: {
      background: "none",
      border: "none",
      color: "var(--muted)",
      cursor: "pointer",
      fontSize: 16,
      flexShrink: 0
    }
  }, "\uD83D\uDDD1\uFE0F"))), customQuotes.length === 0 && /*#__PURE__*/React.createElement("div", {
    style: {
      color: "var(--muted)",
      fontSize: 13,
      textAlign: "center",
      padding: 24,
      border: "1px dashed var(--border)",
      borderRadius: 12
    }
  }, "No custom quotes yet \u2014 add one above!")));
}

// ─── Habit Groups Page ─────────────────────────────────────────────────────────
const GROUP_DEFS = [{
  id: "morning",
  label: "🌅 Morning",
  color: "#f59e0b"
}, {
  id: "evening",
  label: "🌙 Evening",
  color: "#6366f1"
}, {
  id: "weekly",
  label: "📋 Weekly",
  color: "#10b981"
}, {
  id: "health",
  label: "💪 Health",
  color: "#f43f5e"
}, {
  id: "mind",
  label: "🧠 Mind",
  color: "#a855f7"
}, {
  id: "ungrouped",
  label: "📌 Other",
  color: "#6060a0"
}];
function HabitGroupsPage({
  habits,
  habitGroups,
  onSetGroup,
  completions
}) {
  const td = fmt(new Date());
  return /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("h1", {
    style: {
      fontSize: 28,
      fontWeight: 800,
      marginBottom: 4,
      letterSpacing: "-0.5px"
    }
  }, "Habit Groups"), /*#__PURE__*/React.createElement("div", {
    style: {
      color: "var(--muted)",
      fontSize: 13,
      marginBottom: 20
    }
  }, "Organise your habits into routines."), GROUP_DEFS.map(g => {
    const grouped = habits.filter(h => (habitGroups[h.id] || "ungrouped") === g.id);
    if (grouped.length === 0) return null;
    return /*#__PURE__*/React.createElement("div", {
      key: g.id,
      style: {
        marginBottom: 20
      }
    }, /*#__PURE__*/React.createElement("div", {
      style: {
        fontSize: 11,
        fontWeight: 700,
        color: g.color,
        letterSpacing: ".1em",
        textTransform: "uppercase",
        marginBottom: 8
      }
    }, g.label), /*#__PURE__*/React.createElement("div", {
      style: {
        display: "flex",
        flexDirection: "column",
        gap: 6
      }
    }, grouped.map(h => /*#__PURE__*/React.createElement("div", {
      key: h.id,
      style: {
        background: "var(--card)",
        border: "1px solid var(--border)",
        borderRadius: 12,
        padding: "12px 14px",
        display: "flex",
        alignItems: "center",
        gap: 12
      }
    }, /*#__PURE__*/React.createElement("div", {
      style: {
        fontSize: 20
      }
    }, h.icon), /*#__PURE__*/React.createElement("div", {
      style: {
        flex: 1,
        fontSize: 13,
        fontWeight: 500
      }
    }, h.name), /*#__PURE__*/React.createElement("div", {
      style: {
        width: 8,
        height: 8,
        borderRadius: "50%",
        background: completions[`${h.id}:${td}`] ? "#2ecc98" : "var(--border)"
      }
    }), /*#__PURE__*/React.createElement("select", {
      value: habitGroups[h.id] || "ungrouped",
      onChange: e => onSetGroup(h.id, e.target.value),
      style: {
        background: "var(--bg)",
        border: "1px solid var(--border)",
        borderRadius: 8,
        color: "var(--text)",
        fontSize: 11,
        padding: "4px 8px",
        cursor: "pointer",
        outline: "none"
      }
    }, GROUP_DEFS.map(gd => /*#__PURE__*/React.createElement("option", {
      key: gd.id,
      value: gd.id
    }, gd.label)))))));
  }), habits.length === 0 && /*#__PURE__*/React.createElement("div", {
    style: {
      color: "var(--muted)",
      fontSize: 13
    }
  }, "Add some habits first!"));
}

// ─── Learning Roadmap Data ────────────────────────────────────────────────────
const ROADMAP_DATA = [{
  id: "cyber",
  title: "Cybersecurity",
  icon: "🔐",
  color: "#3b82f6",
  dim: "rgba(59,130,246,.13)",
  border: "rgba(59,130,246,.28)",
  stages: [{
    label: "Stage 1 — Foundations",
    sub: "months 1–3",
    topics: ["TCP/IP & OSI model", "DNS, DHCP, HTTP/S", "Subnetting basics", "Firewalls & VPNs", "Linux command line", "File permissions (chmod)", "Cron jobs & log reading", "Ubuntu VM in VirtualBox", "Windows Active Directory", "Python scripting basics", "Bash automation", "CIA triad", "Symmetric vs asymmetric encryption", "Hashing & PKI", "TLS handshake", "🎯 CompTIA Network+"]
  }, {
    label: "Stage 2 — Core Security Domains",
    sub: "months 4–6",
    topics: ["RSA, AES, ECC", "Diffie-Hellman", "Digital signatures", "Certificate chains", "Padding oracle attacks", "Timing attacks", "OAuth 2.0 & SAML", "LDAP & Kerberos", "MFA & SSO", "RBAC vs ABAC", "Privilege escalation paths", "STRIDE threat modelling", "MITRE ATT&CK matrix", "Reading CVEs & CVSS", "NIST CSF & ISO 27001", "CIS Controls", "PicoCTF — web & crypto", "🎯 CompTIA Security+"]
  }, {
    label: "Stage 3 — Ethical Hacking",
    sub: "months 7–9",
    topics: ["Passive OSINT (Shodan, WHOIS)", "Active recon (Nmap, Nessus)", "SQL injection", "XSS & CSRF", "SSRF & IDOR", "Broken authentication", "Command injection", "Burp Suite proxy", "OWASP WebGoat / Juice Shop", "Metasploit framework", "Buffer overflows", "Linux & Windows privesc", "Lateral movement", "Mimikatz credential dumping", "Pivoting & C2 frameworks", "Pentest report writing", "TryHackMe & HackTheBox", "Kali Linux VM", "WPA2 handshake capture (airodump-ng)", "WPA2 offline crack (hashcat)", "Deauthentication attacks (aireplay-ng)", "Evil twin / rogue AP (hostapd-wpe)", "PMKID attack (hcxtools)", "WPS PIN brute-force (reaver)", "Gophish phishing simulation", "Social Engineering Toolkit (SET)", "evilginx2 — AiTM phishing", "Spear phishing pretexts", "Vishing & smishing concepts", "Social engineering kill chain", "🎯 First live CTF (team-based)"]
  }, {
    label: "Stage 4 — Blue Team / Defensive",
    sub: "months 10–12",
    topics: ["Log aggregation & SIEM", "Splunk & Elastic SIEM", "Detection rule writing", "Alert tuning & dashboards", "NIST IR lifecycle", "IR playbooks & triage", "Disk imaging (FTK, Autopsy)", "Memory forensics (Volatility)", "Network forensics (Wireshark, Zeek)", "Chain of custody", "Timeline reconstruction", "Static malware analysis", "Dynamic analysis (Cuckoo sandbox)", "YARA rule writing", "IOC extraction & sharing", "PE file format (headers, sections)", "Process injection techniques", "Persistence mechanisms", "C2 communication patterns", "AV evasion concepts (sig vs heuristic)", "HackTheBox — 10 machines", "🎯 OSCP prep begins"]
  }, {
    label: "Stage 5 — Cloud & AppSec",
    sub: "months 13–15",
    topics: ["Shared responsibility model", "IAM misconfigurations", "S3 bucket exposure", "VPC security groups", "CloudTrail & GuardDuty", "CSPM tools", "Docker image hardening", "Kubernetes RBAC", "Container escape techniques", "Vault for secrets management", "SAST (Semgrep, SonarQube)", "DAST (OWASP ZAP)", "SCA & secrets scanning", "IaC security (tfsec, Checkov)", "Secure SDLC & code review", "Shellcode concepts", "Firmware extraction (binwalk)", "UART/JTAG debugging interfaces", "RFID/NFC cloning concepts", "Raspberry Pi pentest platform", "USB Rubber Ducky attacks", "CTFtime.org competitions", "🎯 AWS Security Specialty", "🎯 OSCP"]
  }, {
    label: "Stage 6 — Specialisation",
    sub: "months 16–18+",
    topics: ["APT simulation", "Cobalt Strike / Sliver C2", "AV/EDR evasion", "CTI lifecycle & OSINT at scale", "Dark web monitoring", "STIX / TAXII", "ISO 27001 auditing", "FAIR risk quantification", "Fuzzing techniques", "Reverse engineering (Ghidra)", "CVE disclosure process", "HackerOne / Bugcrowd", "GitHub portfolio & writeups", "Mobile money security (M-Pesa)", "OT/ICS security fundamentals", "Kenya Data Protection Act (2019)", "ISACA Kenya Chapter", "AfricaHackOn conference", "🎯 CRTO / CRTE", "🎯 CISM / CISSP"]
  }]
}, {
  id: "german",
  title: "German Language",
  icon: "🇩🇪",
  color: "#10b981",
  dim: "rgba(16,185,129,.13)",
  border: "rgba(16,185,129,.28)",
  stages: [{
    label: "A1 — Absolute Beginner",
    sub: "months 1–3",
    topics: ["Alphabet & pronunciation", "Umlauts (ä, ö, ü) & ß", "Pronunciation: ü sound", "Pronunciation: ö sound", "Pronunciation: Ich-Laut (ch after e/i)", "Pronunciation: Ach-Laut (ch after a/o/u)", "Pronunciation: uvular R", "Pronunciation: w = English v", "Pronunciation: v = English f", "Pronunciation: z = ts", "Greetings & introductions", "Numbers 1–100", "Days & months", "Colours & family vocab", "Grammatical gender (der/die/das)", "Learning nouns with articles", "Present tense conjugation", "sein, haben, werden", "500-word core vocabulary", "DW Nicos Weg (A1)", "Anki — 15 cards/day", "Duolingo daily habit", "Pimsleur audio", "Forvo.com for pronunciation", "Speechling recordings"]
  }, {
    label: "A2 — Elementary",
    sub: "months 3–5",
    topics: ["Nominative case", "Accusative case (der→den)", "Dative case", "Genitive case", "Full declension table", "Perfekt tense (spoken)", "Präteritum (written)", "haben vs. sein auxiliaries", "Past participle formation", "Modal verbs (können/müssen…)", "Verb-second word order", "Subordinate clause verb-final", "Schritte Plus A2 textbook", "Minimal pairs drilling (liegen/lügen)", "Record & compare to native speaker"]
  }, {
    label: "B1 — Intermediate Threshold",
    sub: "months 6–9",
    topics: ["Konjunktiv II (würde + inf.)", "Polite requests (Könnten Sie…?)", "Relative clauses", "Subordinate clause mastery", "Passive voice (werden + PP)", "Two-way prepositions (an/auf/in…)", "Fixed-case prepositions", "English→German translation (news para)", "German→English translation (Spiegel)", "Back-translation exercises", "Slow German podcast", "italki tutors (1×/week)", "Pronunciation correction first 5 min each session", "🎯 Goethe B1 (Nairobi)"]
  }, {
    label: "B2 — Upper Intermediate",
    sub: "months 10–12",
    topics: ["Idiomatic expressions", "Der Spiegel / SZ reading", "ARD/ZDF Mediathek", "Dark on Netflix (DE audio)", "Konjunktiv I (reported speech)", "Genitive in formal writing", "Extended participial phrases", "Double infinitive constructions", "Sie vs. du register", "Formal email writing (Betreff, MfG)", "Dialect awareness (Bavarian, Swiss…)", "Business vocab: Bilanz, Umsatz, Aktie", "Business vocab: Vertrag, Klausel, kündigen", "Meeting vocab: Tagesordnung, Protokoll", "Deutsch im Beruf series (DW)", "Weekly German news topic deep-dive", "150-word weekly summary in German", "Translation: technical document", "🎯 Goethe B2", "🎯 Goethe Zertifikat Deutsch für den Beruf"]
  }, {
    label: "C1 — Advanced",
    sub: "months 13–16",
    topics: ["Erörterungen (argumentative essays)", "Berichte & formal correspondence", "Nested subordinate clauses", "Nominalisations", "Dense compound nouns", "Simplified Kafka & Brecht", "German Weltanschauung & humour", "Spontaneous abstract speech", "Hammer's German Grammar", "Deutschlandfunk Nova podcast", "FAZ (high-register newspaper)", "Cornelsen Deutsch für den Beruf", "Technical translation (legal/scientific)", "German↔English↔Swahili translation niche", "C1 essay: 500 words with tutor feedback", "🎯 Goethe C1"]
  }, {
    label: "C2 — Mastery / Near-Native",
    sub: "months 17–18+",
    topics: ["Kafka, Goethe's Faust (original)", "Nietzsche & Thomas Mann", "Historical/archaic German forms", "Bavarian dialect", "Swabian & Saxon dialects", "Swiss & Austrian German", "Berlinerisch", "Near-synonym precision (nutzen vs. benutzen…)", "GIZ / KfW Kenya professional German", "Remote work for German companies (SAP, Siemens)", "Conference interpretation prep", "🎯 Goethe C2 (GDS)"]
  }]
}, {
  id: "trading",
  title: "Order Flow Trading",
  icon: "📈",
  color: "#f59e0b",
  dim: "rgba(245,158,11,.13)",
  border: "rgba(245,158,11,.28)",
  stages: [{
    label: "Stage 1 — Market Microstructure",
    sub: "",
    topics: ["Order book (Level 2)", "Bid / ask / spread", "Market orders vs limit orders", "Liquidity providers vs consumers", "Bid-ask spread dynamics", "Price discovery mechanics", "Why candles hide intent"]
  }, {
    label: "Stage 2 — Volume Analysis & Tape Reading",
    sub: "",
    topics: ["Time & Sales (the tape)", "Volume at price (VAP)", "High-volume nodes", "Low-volume rejection zones", "Delta per candle", "Cumulative delta", "Price vs delta divergence", "Buy vs sell-side aggression"]
  }, {
    label: "Stage 3 — Footprint Charts & Market Profile",
    sub: "",
    topics: ["Footprint (cluster) charts", "Absorption pattern", "Exhaustion pattern", "Buy imbalance (3× rule)", "Sell imbalance (3× rule)", "Stacked imbalances", "Unfinished auction", "Iceberg / hidden orders", "TPO (market profile) charts", "Point of Control (POC)", "Value Area (VAH / VAL)", "Initial Balance (IB)", "Single prints", "HVN & LVN", "4 opening types"]
  }, {
    label: "Stage 4 — Auction Market Theory & Context",
    sub: "",
    topics: ["Auction market theory (AMT)", "Balance vs imbalance", "Initiative vs responsive activity", "Multi-timeframe context", "Weekly/daily profile alignment", "10-year Treasury yield (ZN) watch", "DXY — dollar index correlation", "VIX regime filter (>20 / 12–15 / >30)", "Gold (GC) as fear gauge", "Oil (CL) macro signal", "Daily intermarket 5-min checklist", "Options put/call ratio", "Implied volatility spikes", "Large OTM call/put sweeps", "Unusual Whales flow scanner", "Market Chameleon scanner", "FOMC playbook (no trades 30 min before)", "CPI release playbook", "NFP — observe only (first 12 months)", "Earnings gap risk management"]
  }, {
    label: "Stage 5 — Execution & Trade Management",
    sub: "",
    topics: ["Failed auction setup", "Breakout with volume confirmation", "Iceberg detection entry", "Stop placement beyond structure", "Scaling in & out", "Trade journaling (signal-specific)", "Price confirmation rule", "Write setup rules BEFORE chart review", "Out-of-sample backtesting period", "Market replay (Sierra Chart / NinjaTrader)", "200-trade minimum sample", "Backtesting results spreadsheet", "Walk-forward validation", "Monte Carlo simulation (drawdown)", "Expectancy per setup calculation", "Drop negative-expectancy setups", "Topstep / Apex / FTMO evaluation research", "Prop firm funded account structure", "Safaricom fibre latency check", "Wise / Payoneer for USD receipt"]
  }, {
    label: "Stage 6 — Tools, Platforms & Markets",
    sub: "",
    topics: ["CME futures (ES, NQ, CL, GC)", "Forex order flow limitations", "Crypto (Binance/Bybit)", "Sierra Chart", "Bookmap (heatmap)", "Jigsaw Trading", "NinjaTrader", "DOM (Depth of Market) trading", "Spoofing detection", "Layering detection", "Liquidity vacuum", "Stop hunt patterns", "Genuine wall identification", "CME direct data feed", "EAT trading hours (2:30 PM–5 PM & 9 PM)"]
  }, {
    label: "Stage 7 — Delta Divergence",
    sub: "",
    topics: ["Bearish divergence at top", "Bullish divergence at bottom", "Trend confirmation (no divergence)", "Hidden divergence (continuation)", "Entry triggers & stop placement", "Delta confirmation before entry"]
  }, {
    label: "Risk Management & Psychology",
    sub: "",
    topics: ["Expectancy formula", "200-trade sample minimum", "0.5–1% risk per trade", "2–3% daily max loss rule", "Asymmetry of drawdown", "Revenge trading", "Loss aversion bias", "Overtrading / FOMO", "Confirmation bias", "Outcome vs process grading", "Gambler's fallacy", "5 trader development phases", "Market regime awareness", "Regime filter (VIX, time of day)", "Sleep 7–9 hrs for decision quality", "Exercise before trading session", "No trading in low-VIX (<15) chop"]
  }]
}, {
  id: "crosstrack",
  title: "Cross-Track Systems",
  icon: "🧠",
  color: "#d946ef",
  dim: "rgba(217,70,239,.13)",
  border: "rgba(217,70,239,.28)",
  stages: [{
    label: "Mental Performance & Focus",
    sub: "ongoing",
    topics: ["Consistent wake time (non-negotiable)", "Blue light off 45 min before bed", "7–9 hrs sleep for memory consolidation", "Exercise before main study block", "BDNF window: 2–4 hrs post-exercise", "Caffeine: 90 min after waking, off by 1 PM", "2% dehydration = measurable IQ drop", "Avocado, eggs, sukuma wiki (brain foods)", "45-min Pomodoro blocks", "Phone on flight mode during study", "Implementation intentions (when/where)", "Prepare materials before sitting down", "Practice at edge of competence", "Interleaved subjects (why this schedule works)", "One complete rest day per week", "Warning signs of overtraining (3 criteria)"]
  }, {
    label: "Obsidian Knowledge Vault",
    sub: "set up Week 1",
    topics: ["Install Obsidian (free, local)", "Create vault folder structure", "000 Inbox — daily capture note", "100 Cybersecurity folder tree", "200 German folder tree", "300 Order Flow folder tree", "400 Cross-Track (weekly reviews)", "500 Resources (books, courses, tools)", "Bi-directional linking between concepts", "Morning: open today's inbox note", "Evening: process inbox into folders", "Sunday 30-min weekly review", "🔥 To Revisit tag system", "Anki card → matching Obsidian note", "Monthly cross-track concept bridge (200 words)"]
  }, {
    label: "Nairobi Career Pathing",
    sub: "months 6–18",
    topics: ["Safaricom security team target", "Equity Bank / KCB / Britam targets", "Kenya Data Protection Act compliance niche", "Mobile money security (globally unique)", "GIZ / KfW German organisations in Nairobi", "German Embassy / Austrian Embassy / SECO", "iHub Ngong Road — community presence", "ISACA Kenya Chapter membership", "AfricaHackOn annual conference", "BrighterMonday & LinkedIn Kenya", "Entry SOC analyst: KES 80–120k/mo", "Senior security engineer: KES 300–500k/mo", "Remote for international: $3–8k USD/mo", "German B2 + OSCP = remote DE company hire", "Equity Bank / NCBA for USD receipt", "Wise / Payoneer account setup", "Kenyan tax advice for trading income", "Bug bounty income (HackerOne) from month 12"]
  }, {
    label: "Pattern Recognition (Cross-Track)",
    sub: "ongoing",
    topics: ["Delta divergence ↔ SIEM anomaly detection", "OSINT methodology ↔ German text inference", "Tape reading ↔ partial-input comprehension", "Deliberate practice: study at edge of ability", "Reading German news at 5–10% unknown words", "Replay hardest market days (not just clean trends)", "Monthly: apply one track's concept to another", "CTF OSINT skills transfer to trading research", "Footprint pattern recognition = security pattern recognition", "Behavioural baseline (security) = value area (trading)"]
  }]
}];

// ─── Learning Roadmap Page ────────────────────────────────────────────────────
function LearningRoadmapPage({
  progress,
  onToggle
}) {
  const [activeTrack, setActiveTrack] = useState("cyber");
  const [expandedStages, setExpandedStages] = useState({});
  const track = ROADMAP_DATA.find(t => t.id === activeTrack);

  // Count totals per track
  const trackStats = ROADMAP_DATA.map(t => {
    const total = t.stages.reduce((s, st) => s + st.topics.length, 0);
    const done = t.stages.reduce((s, st) => s + st.topics.filter(tp => progress[`${t.id}:${tp}`]).length, 0);
    return {
      id: t.id,
      total,
      done
    };
  });
  const toggleStage = stageLabel => {
    setExpandedStages(prev => ({
      ...prev,
      [stageLabel]: !prev[stageLabel]
    }));
  };

  // All stages open by default on first render
  useEffect(() => {
    const init = {};
    ROADMAP_DATA.forEach(t => t.stages.forEach(s => {
      init[s.label] = true;
    }));
    setExpandedStages(init);
  }, []);
  const stageStats = stage => {
    const total = stage.topics.length;
    const done = stage.topics.filter(tp => progress[`${activeTrack}:${tp}`]).length;
    return {
      total,
      done,
      pct: total ? done / total : 0
    };
  };
  return /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("div", {
    style: {
      marginBottom: 24
    }
  }, /*#__PURE__*/React.createElement("h2", {
    style: {
      fontFamily: "'Syne',sans-serif",
      fontWeight: 800,
      fontSize: 22,
      color: "var(--text)",
      marginBottom: 4
    }
  }, "Learning Roadmap"), /*#__PURE__*/React.createElement("p", {
    style: {
      fontSize: 13,
      color: "var(--muted)"
    }
  }, "18-month curriculum \xB7 tick topics as you master them")), /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      gap: 10,
      marginBottom: 22,
      flexWrap: "wrap"
    }
  }, ROADMAP_DATA.map(t => {
    const st = trackStats.find(x => x.id === t.id);
    const pct = st.total ? Math.round(st.done / st.total * 100) : 0;
    const active = activeTrack === t.id;
    return /*#__PURE__*/React.createElement("button", {
      key: t.id,
      onClick: () => setActiveTrack(t.id),
      style: {
        display: "flex",
        alignItems: "center",
        gap: 10,
        padding: "10px 16px",
        borderRadius: 12,
        border: active ? `1.5px solid ${t.color}` : "1px solid var(--border)",
        background: active ? t.dim : "var(--card)",
        cursor: "pointer",
        transition: ".18s",
        flex: "1 1 150px"
      }
    }, /*#__PURE__*/React.createElement("span", {
      style: {
        fontSize: 20
      }
    }, t.icon), /*#__PURE__*/React.createElement("div", {
      style: {
        textAlign: "left",
        flex: 1,
        minWidth: 0
      }
    }, /*#__PURE__*/React.createElement("div", {
      style: {
        fontSize: 13,
        fontWeight: 600,
        color: active ? t.color : "var(--text)",
        whiteSpace: "nowrap",
        overflow: "hidden",
        textOverflow: "ellipsis"
      }
    }, t.title), /*#__PURE__*/React.createElement("div", {
      style: {
        fontSize: 11,
        color: "var(--muted)",
        marginTop: 2
      }
    }, st.done, "/", st.total, " topics \xB7 ", pct, "%")), /*#__PURE__*/React.createElement("svg", {
      width: "32",
      height: "32",
      viewBox: "0 0 32 32",
      style: {
        flexShrink: 0
      }
    }, /*#__PURE__*/React.createElement("circle", {
      cx: "16",
      cy: "16",
      r: "13",
      fill: "none",
      stroke: "var(--border)",
      strokeWidth: "3"
    }), /*#__PURE__*/React.createElement("circle", {
      cx: "16",
      cy: "16",
      r: "13",
      fill: "none",
      stroke: t.color,
      strokeWidth: "3",
      strokeDasharray: `${2 * Math.PI * 13}`,
      strokeDashoffset: `${2 * Math.PI * 13 * (1 - pct / 100)}`,
      strokeLinecap: "round",
      style: {
        transform: "rotate(-90deg)",
        transformOrigin: "16px 16px",
        transition: "stroke-dashoffset .6s ease"
      }
    }), /*#__PURE__*/React.createElement("text", {
      x: "16",
      y: "20",
      textAnchor: "middle",
      fontSize: "9",
      fontWeight: "700",
      fill: t.color
    }, pct, "%")));
  })), track.stages.map(stage => {
    const {
      total,
      done,
      pct
    } = stageStats(stage);
    const open = expandedStages[stage.label] !== false;
    const allDone = done === total;
    return /*#__PURE__*/React.createElement("div", {
      key: stage.label,
      style: {
        background: "var(--card)",
        border: `1px solid ${allDone ? track.border : "var(--border)"}`,
        borderRadius: 14,
        marginBottom: 10,
        overflow: "hidden",
        transition: "border-color .25s"
      }
    }, /*#__PURE__*/React.createElement("button", {
      onClick: () => toggleStage(stage.label),
      style: {
        width: "100%",
        display: "flex",
        alignItems: "center",
        gap: 12,
        padding: "13px 16px",
        background: "none",
        border: "none",
        cursor: "pointer",
        textAlign: "left"
      }
    }, /*#__PURE__*/React.createElement("div", {
      style: {
        position: "relative",
        width: 36,
        height: 36,
        flexShrink: 0
      }
    }, /*#__PURE__*/React.createElement("svg", {
      width: "36",
      height: "36",
      viewBox: "0 0 36 36"
    }, /*#__PURE__*/React.createElement("circle", {
      cx: "18",
      cy: "18",
      r: "14",
      fill: "none",
      stroke: "var(--border)",
      strokeWidth: "3.5"
    }), /*#__PURE__*/React.createElement("circle", {
      cx: "18",
      cy: "18",
      r: "14",
      fill: "none",
      stroke: allDone ? track.color : track.color + "99",
      strokeWidth: "3.5",
      strokeDasharray: `${2 * Math.PI * 14}`,
      strokeDashoffset: `${2 * Math.PI * 14 * (1 - pct)}`,
      strokeLinecap: "round",
      style: {
        transform: "rotate(-90deg)",
        transformOrigin: "18px 18px",
        transition: "stroke-dashoffset .5s ease"
      }
    }), allDone ? /*#__PURE__*/React.createElement("text", {
      x: "18",
      y: "22.5",
      textAnchor: "middle",
      fontSize: "13"
    }, "\u2713") : /*#__PURE__*/React.createElement("text", {
      x: "18",
      y: "22",
      textAnchor: "middle",
      fontSize: "9",
      fontWeight: "700",
      fill: track.color
    }, done))), /*#__PURE__*/React.createElement("div", {
      style: {
        flex: 1,
        minWidth: 0
      }
    }, /*#__PURE__*/React.createElement("div", {
      style: {
        fontSize: 13,
        fontWeight: 600,
        color: allDone ? track.color : "var(--text)",
        lineHeight: 1.3
      }
    }, stage.label), stage.sub && /*#__PURE__*/React.createElement("div", {
      style: {
        fontSize: 11,
        color: "var(--muted)",
        marginTop: 1
      }
    }, stage.sub), /*#__PURE__*/React.createElement("div", {
      style: {
        fontSize: 11,
        color: "var(--muted)",
        marginTop: 2
      }
    }, done, "/", total, " topics")), /*#__PURE__*/React.createElement("span", {
      style: {
        fontSize: 16,
        color: "var(--muted)",
        transform: open ? "rotate(180deg)" : "rotate(0deg)",
        transition: ".2s",
        flexShrink: 0
      }
    }, "\u2304")), /*#__PURE__*/React.createElement("div", {
      style: {
        height: 2,
        background: "var(--border)",
        margin: "0 16px"
      }
    }, /*#__PURE__*/React.createElement("div", {
      style: {
        height: "100%",
        width: `${pct * 100}%`,
        background: track.color,
        borderRadius: 2,
        transition: "width .5s ease"
      }
    })), open && /*#__PURE__*/React.createElement("div", {
      style: {
        padding: "12px 14px 14px",
        display: "flex",
        flexWrap: "wrap",
        gap: 7
      }
    }, stage.topics.map(tp => {
      const key = `${activeTrack}:${tp}`;
      const checked = !!progress[key];
      const isMilestone = tp.startsWith("🎯");
      return /*#__PURE__*/React.createElement("button", {
        key: tp,
        onClick: () => onToggle(key),
        style: {
          display: "flex",
          alignItems: "center",
          gap: 6,
          padding: isMilestone ? "5px 12px 5px 8px" : "5px 10px",
          borderRadius: 100,
          border: checked ? `1.5px solid ${track.color}` : isMilestone ? `1.5px dashed ${track.color}88` : "1px solid var(--border)",
          background: checked ? track.dim : isMilestone ? `${track.color}0d` : "var(--bg)",
          cursor: "pointer",
          transition: ".15s",
          fontSize: 12,
          fontWeight: checked ? 600 : 400,
          color: checked ? track.color : isMilestone ? track.color + "cc" : "var(--muted)"
        }
      }, /*#__PURE__*/React.createElement("span", {
        style: {
          width: 14,
          height: 14,
          borderRadius: "50%",
          flexShrink: 0,
          border: checked ? "none" : `1.5px solid ${checked ? track.color : "var(--border)"}`,
          background: checked ? track.color : "transparent",
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          transition: ".15s"
        }
      }, checked && /*#__PURE__*/React.createElement("svg", {
        width: "9",
        height: "7",
        viewBox: "0 0 9 7",
        fill: "none"
      }, /*#__PURE__*/React.createElement("path", {
        d: "M1 3.5L3.5 6L8 1",
        stroke: "white",
        strokeWidth: "1.6",
        strokeLinecap: "round",
        strokeLinejoin: "round"
      }))), /*#__PURE__*/React.createElement("span", {
        style: {
          lineHeight: 1.3
        }
      }, tp));
    })));
  }), (() => {
    const st = trackStats.find(x => x.id === activeTrack);
    const pct = st.total ? Math.round(st.done / st.total * 100) : 0;
    return /*#__PURE__*/React.createElement("div", {
      style: {
        marginTop: 20,
        background: "var(--card)",
        border: `1px solid ${track.border}`,
        borderRadius: 14,
        padding: "16px 18px"
      }
    }, /*#__PURE__*/React.createElement("div", {
      style: {
        display: "flex",
        justifyContent: "space-between",
        alignItems: "center",
        marginBottom: 10
      }
    }, /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("div", {
      style: {
        fontSize: 13,
        fontWeight: 600,
        color: "var(--text)"
      }
    }, track.icon, " ", track.title, " \u2014 Overall Progress"), /*#__PURE__*/React.createElement("div", {
      style: {
        fontSize: 11,
        color: "var(--muted)",
        marginTop: 2
      }
    }, st.done, " of ", st.total, " topics mastered")), /*#__PURE__*/React.createElement("div", {
      style: {
        fontSize: 28,
        fontWeight: 800,
        color: track.color,
        fontFamily: "'Syne',sans-serif"
      }
    }, pct, "%")), /*#__PURE__*/React.createElement("div", {
      style: {
        height: 6,
        background: "var(--border)",
        borderRadius: 3,
        overflow: "hidden"
      }
    }, /*#__PURE__*/React.createElement("div", {
      style: {
        height: "100%",
        width: `${pct}%`,
        background: track.color,
        borderRadius: 3,
        transition: "width .7s ease"
      }
    })));
  })());
}

// ─── PIN Lock System (Fix #1 — app lock, Fix #14 — brute-force protection) ───
// Hashes the PIN with SHA-256 before storing — never stored in plaintext.
// After 5 wrong attempts the app locks out for 30 seconds (exponential back-off).
// Session timeout: app re-locks after SESSION_TIMEOUT_MS of inactivity (Fix #4).

const SESSION_TIMEOUT_MS = 10 * 60 * 1000; // 10 minutes
const MAX_PIN_ATTEMPTS = 5;
const LOCKOUT_BASE_MS = 30 * 1000; // 30 s base; doubles each lockout round

async function hashPin(pin) {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode("zenflow-pin:" + pin));
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, "0")).join("");
}
function PinScreen({
  mode,
  onSuccess,
  onSetPin
}) {
  // mode: "set" (first-time setup) | "unlock" (entering existing PIN)
  const [digits, setDigits] = useState([]);
  const [confirm, setConfirm] = useState([]); // only used in "set" mode
  const [phase, setPhase] = useState("enter"); // "enter" | "confirm"
  const [error, setError] = useState("");
  const [shake, setShake] = useState(false);
  const [attempts, setAttempts] = useState(0);
  const [lockedUntil, setLockedUntil] = useState(null);
  const [lockRound, setLockRound] = useState(0);
  const [now, setNow] = useState(Date.now());

  // Tick every second so countdown updates
  useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(t);
  }, []);
  const locked = lockedUntil && now < lockedUntil;
  const lockSecsLeft = locked ? Math.ceil((lockedUntil - now) / 1000) : 0;
  const triggerShake = () => {
    setShake(true);
    setTimeout(() => setShake(false), 600);
  };
  const handleDigit = d => {
    if (locked) return;
    const current = phase === "confirm" ? confirm : digits;
    const setter = phase === "confirm" ? setConfirm : setDigits;
    if (current.length >= 4) return;
    const next = [...current, d];
    setter(next);
    if (next.length === 4) {
      setTimeout(() => handleComplete(next), 80);
    }
  };
  const handleDelete = () => {
    if (locked) return;
    if (phase === "confirm") {
      setConfirm(c => c.slice(0, -1));
    } else {
      setDigits(d => d.slice(0, -1));
    }
  };
  const handleComplete = async entered => {
    if (mode === "set") {
      if (phase === "enter") {
        setPhase("confirm");
      } else {
        // Verify both entries match
        if (entered.join("") !== digits.join("")) {
          setError("PINs don't match. Try again.");
          triggerShake();
          setConfirm([]);
          setPhase("enter");
          setDigits([]);
          return;
        }
        const hash = await hashPin(digits.join(""));
        onSetPin(hash);
      }
    } else {
      // Unlock mode — verify against stored hash
      const stored = localStorage.getItem("zenflow:pin-hash");
      const hash = await hashPin(entered.join(""));
      if (hash === stored) {
        setAttempts(0);
        onSuccess();
      } else {
        const newAttempts = attempts + 1;
        setAttempts(newAttempts);
        triggerShake();
        setDigits([]);
        if (newAttempts >= MAX_PIN_ATTEMPTS) {
          // Exponential back-off: 30s, 60s, 120s…
          const newRound = lockRound + 1;
          setLockRound(newRound);
          const duration = LOCKOUT_BASE_MS * Math.pow(2, newRound - 1);
          setLockedUntil(Date.now() + duration);
          setAttempts(0);
          setError(`Too many attempts. Locked for ${Math.ceil(duration / 1000)}s.`);
        } else {
          setError(`Wrong PIN. ${MAX_PIN_ATTEMPTS - newAttempts} attempt${MAX_PIN_ATTEMPTS - newAttempts !== 1 ? "s" : ""} left.`);
        }
      }
    }
  };
  const displayDigits = phase === "confirm" ? confirm : digits;
  const title = mode === "set" ? phase === "enter" ? "Create a PIN" : "Confirm your PIN" : "Enter PIN";
  const subtitle = mode === "set" ? phase === "enter" ? "Choose a 4-digit PIN to protect your data" : "Re-enter your PIN to confirm" : locked ? `Too many failed attempts. Try again in ${lockSecsLeft}s.` : "Zenflow is locked";
  return /*#__PURE__*/React.createElement("div", {
    style: {
      position: "fixed",
      inset: 0,
      background: "#0a0a14",
      display: "flex",
      flexDirection: "column",
      alignItems: "center",
      justifyContent: "center",
      fontFamily: "'DM Sans', sans-serif",
      color: "#f0f0f8",
      zIndex: 99999
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      fontSize: 48,
      marginBottom: 16
    }
  }, "\uD83D\uDD12"), /*#__PURE__*/React.createElement("div", {
    style: {
      fontFamily: "'Syne', sans-serif",
      fontWeight: 800,
      fontSize: 22,
      marginBottom: 6
    }
  }, "Zenflow"), /*#__PURE__*/React.createElement("div", {
    style: {
      fontSize: 14,
      color: "#6060a0",
      marginBottom: 32,
      textAlign: "center",
      maxWidth: 260
    }
  }, subtitle), /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      gap: 16,
      marginBottom: 24,
      animation: shake ? "pin-shake 0.5s ease" : "none"
    }
  }, [0, 1, 2, 3].map(i => /*#__PURE__*/React.createElement("div", {
    key: i,
    style: {
      width: 16,
      height: 16,
      borderRadius: "50%",
      background: displayDigits.length > i ? "#2ecc98" : "transparent",
      border: "2px solid " + (displayDigits.length > i ? "#2ecc98" : "#ffffff30"),
      transition: "all .12s ease"
    }
  }))), error && /*#__PURE__*/React.createElement("div", {
    style: {
      fontSize: 12,
      color: "#f43f5e",
      marginBottom: 16,
      textAlign: "center",
      maxWidth: 220
    }
  }, error), /*#__PURE__*/React.createElement("div", {
    style: {
      display: "grid",
      gridTemplateColumns: "repeat(3, 72px)",
      gap: 12
    }
  }, [1, 2, 3, 4, 5, 6, 7, 8, 9, "", 0, "⌫"].map((k, i) => /*#__PURE__*/React.createElement("button", {
    key: i,
    onClick: () => {
      if (k === "⌫") handleDelete();else if (k !== "") handleDigit(String(k));
    },
    disabled: locked && k !== "⌫",
    style: {
      width: 72,
      height: 72,
      borderRadius: "50%",
      border: "1px solid #ffffff14",
      background: k === "" ? "transparent" : "#ffffff08",
      color: locked ? "#ffffff30" : "#f0f0f8",
      fontSize: k === "⌫" ? 20 : 22,
      fontWeight: 600,
      cursor: k === "" || locked ? "default" : "pointer",
      pointerEvents: k === "" ? "none" : "auto",
      transition: "background .1s",
      display: "flex",
      alignItems: "center",
      justifyContent: "center"
    },
    onMouseEnter: e => {
      if (k !== "" && !locked) e.currentTarget.style.background = "#ffffff14";
    },
    onMouseLeave: e => {
      e.currentTarget.style.background = k === "" ? "transparent" : "#ffffff08";
    }
  }, k))), /*#__PURE__*/React.createElement("style", null, `@keyframes pin-shake { 0%,100%{transform:translateX(0)} 20%,60%{transform:translateX(-10px)} 40%,80%{transform:translateX(10px)} }`));
}

// ─── PIN Setup Modal (in-app — for users who want to enable PIN after onboarding) ─
function PinSetupModal({
  onClose,
  onSaved
}) {
  const handleSetPin = hash => {
    localStorage.setItem("zenflow:pin-hash", hash);
    onSaved();
    onClose();
  };
  return /*#__PURE__*/React.createElement("div", {
    style: {
      position: "fixed",
      inset: 0,
      background: "#00000080",
      zIndex: 9999,
      display: "flex",
      alignItems: "center",
      justifyContent: "center"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      background: "#0a0a14",
      border: "1px solid #ffffff14",
      borderRadius: 20,
      overflow: "hidden",
      width: 380
    }
  }, /*#__PURE__*/React.createElement(PinScreen, {
    mode: "set",
    onSetPin: handleSetPin,
    onSuccess: () => {}
  }), /*#__PURE__*/React.createElement("button", {
    onClick: onClose,
    style: {
      position: "absolute",
      top: 20,
      right: 20,
      background: "none",
      border: "none",
      color: "#6060a0",
      cursor: "pointer",
      fontSize: 20
    }
  }, "\xD7")));
}

// ─── Accent Colour Picker (sidebar) ───────────────────────────────────────────
const ACCENT_COLORS = [{
  label: "Emerald",
  value: "#2ecc98"
}, {
  label: "Purple",
  value: "#a855f7"
}, {
  label: "Blue",
  value: "#3b82f6"
}, {
  label: "Pink",
  value: "#f472b6"
}, {
  label: "Orange",
  value: "#f59e0b"
}, {
  label: "Red",
  value: "#f43f5e"
}, {
  label: "Cyan",
  value: "#06b6d4"
}, {
  label: "Lime",
  value: "#84cc16"
}];
function App() {
  const [habits, setHabits] = useState(INITIAL_HABITS);
  const [completions, setCompletions] = useState(SEED_COMPLETIONS);
  const [roadmapProgress, setRoadmapProgress] = useState({});
  const [page, setPage] = useState("home");
  const [editingHabit, setEditingHabit] = useState(null);
  const [dark, setDark] = useState(true);
  const [confetti, setConfetti] = useState(false);
  const [toast, setToast] = useState(null);
  const [loaded, setLoaded] = useState(false);
  const [integrityWarning, setIntegrityWarning] = useState(null); // Fix #9
  const [weeklyReport, setWeeklyReport] = useState(null);
  const [onboarded, setOnboarded] = useState(true);
  const [userName, setUserName] = useState("");
  const [reminderHour, setReminderHour] = useState(8);
  const [accentColor, setAccentColor] = useState("#2ecc98");
  const [shields, setShields] = useState(0);
  const [levelUpModal, setLevelUpModal] = useState(null);
  const [focusHabitId, setFocusHabitId] = useState(null);
  const [focusDismissed, setFocusDismissed] = useState("");
  const [habitGroups, setHabitGroups] = useState({});
  const [customQuotes, setCustomQuotes] = useState([]);
  const [showSplash, setShowSplash] = useState(true);
  const [copyrightAgreed, setCopyrightAgreed] = useState(true); // loaded from persist below
  const [showPrivacy, setShowPrivacy] = useState(false);
  const [showTerms, setShowTerms] = useState(false);
  const [showAbout, setShowAbout] = useState(false);
  // Fix #1, #4, #14 — PIN lock + session timeout
  const [appLocked, setAppLocked] = useState(!!localStorage.getItem("zenflow:pin-hash"));
  const [pinMode, setPinMode] = useState(!!localStorage.getItem("zenflow:pin-hash")); // true = PIN is configured
  const [showPinSetup, setShowPinSetup] = useState(false);
  const sessionTimer = useRef(null);
  const dragItem = useRef(null);
  const dragOver = useRef(null);
  const prevLevel = useRef(null);

  // ── Integrity failure listener (Fix #9) ───────────────────────────
  useEffect(() => {
    const handler = e => setIntegrityWarning(e.detail.key);
    window.addEventListener("zenflow:integrity-fail", handler);
    return () => window.removeEventListener("zenflow:integrity-fail", handler);
  }, []);

  // ── Session timeout (Fix #4) — re-lock after inactivity ───────────
  // Only active when a PIN is configured. Resets on any user interaction.
  const resetSessionTimer = useCallback(() => {
    if (!localStorage.getItem("zenflow:pin-hash")) return;
    clearTimeout(sessionTimer.current);
    sessionTimer.current = setTimeout(() => {
      setAppLocked(true);
    }, SESSION_TIMEOUT_MS);
  }, []);
  useEffect(() => {
    if (!pinMode) return; // no PIN set — no timeout needed
    const events = ["mousedown", "mousemove", "keydown", "touchstart", "scroll"];
    events.forEach(e => window.addEventListener(e, resetSessionTimer, {
      passive: true
    }));
    resetSessionTimer(); // start timer immediately
    return () => {
      events.forEach(e => window.removeEventListener(e, resetSessionTimer));
      clearTimeout(sessionTimer.current);
    };
  }, [pinMode, resetSessionTimer]);

  // ── Load persisted data on mount ──────────────────────────────────
  useEffect(() => {
    (async () => {
      const [h, c, d, ob, un, rh, ac, sh, hg, cq, rp, ca] = await Promise.all([persistGet("habits", INITIAL_HABITS), persistGet("completions", SEED_COMPLETIONS), persistGet("dark", true), persistGet("onboarded", false), persistGet("userName", ""), persistGet("reminderHour", 8), persistGet("accentColor", "#2ecc98"), persistGet("shields", 0), persistGet("habitGroups", {}), persistGet("customQuotes", []), persistGet("roadmapProgress", {}), persistGet("copyrightAgreed", false)]);
      const isDemoData = h.length > 0 && h.every(x => x.id <= 6 && x.createdAt?.startsWith("2025-0"));
      const cleanHabits = isDemoData ? [] : h;
      const cleanCompletions = isDemoData ? {} : c;
      setHabits(cleanHabits);
      setCompletions(cleanCompletions);
      setDark(d);
      setOnboarded(isDemoData ? false : ob);
      setUserName(un);
      setReminderHour(rh);
      setAccentColor(ac);
      setShields(sh);
      setHabitGroups(hg);
      setCustomQuotes(cq);
      setRoadmapProgress(rp);
      setCopyrightAgreed(ca);
      if (cleanHabits.length > 0) {/* IDs are now UUIDs — no counter needed */}
      setLoaded(true);
    })();
  }, []);

  // ── Persist on every change ────────────────────────────────────────
  useEffect(() => {
    if (loaded) persistSet("habits", habits);
  }, [habits, loaded]);
  useEffect(() => {
    if (loaded) persistSet("completions", completions);
  }, [completions, loaded]);
  useEffect(() => {
    if (loaded) persistSet("dark", dark);
  }, [dark, loaded]);
  useEffect(() => {
    if (loaded) persistSet("onboarded", onboarded);
  }, [onboarded, loaded]);
  useEffect(() => {
    if (loaded) persistSet("userName", userName);
  }, [userName, loaded]);
  useEffect(() => {
    if (loaded) persistSet("reminderHour", reminderHour);
  }, [reminderHour, loaded]);
  useEffect(() => {
    if (loaded) persistSet("accentColor", accentColor);
  }, [accentColor, loaded]);
  useEffect(() => {
    if (loaded) persistSet("shields", shields);
  }, [shields, loaded]);
  useEffect(() => {
    if (loaded) persistSet("habitGroups", habitGroups);
  }, [habitGroups, loaded]);
  useEffect(() => {
    if (loaded) persistSet("customQuotes", customQuotes);
  }, [customQuotes, loaded]);
  useEffect(() => {
    if (loaded) persistSet("roadmapProgress", roadmapProgress);
  }, [roadmapProgress, loaded]);
  useEffect(() => {
    if (loaded) persistSet("copyrightAgreed", copyrightAgreed);
  }, [copyrightAgreed, loaded]);

  // ── Daily focus habit (picks one randomly each day, persists) ─────
  useEffect(() => {
    if (!loaded || habits.length === 0) return;
    const td = fmt(new Date());
    if (focusDismissed === td) return;
    // Seed random with today's date so same habit shows all day
    const seed = parseInt(td.replace(/-/g, "")) % habits.length;
    setFocusHabitId(habits[seed]?.id ?? null);
  }, [loaded, habits, focusDismissed]);

  // ── Level-up detector ──────────────────────────────────────────────
  useEffect(() => {
    if (!loaded) return;
    const {
      level
    } = getLevel(computeXP(habits, completions));
    if (prevLevel.current !== null && level > prevLevel.current) {
      const lvl = getLevel(computeXP(habits, completions));
      setLevelUpModal(lvl);
      setConfetti(true);
      setShields(s => s + 1); // earn a shield on level up
    }
    prevLevel.current = level;
  }, [completions, habits, loaded]);

  // ── Build weekly report for the just-ended week ────────────────────
  const buildWeeklyReport = useCallback((completionsSnap, habitsSnap) => {
    const now = new Date();
    // Last 7 days (the week that just ended)
    const days = Array.from({
      length: 7
    }, (_, i) => {
      const d = new Date(now);
      d.setDate(d.getDate() - (7 - i));
      const ds = fmt(d);
      const done = habitsSnap.filter(h => completionsSnap[`${h.id}:${ds}`]).length;
      const labels = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
      return {
        label: labels[d.getDay()],
        done,
        total: habitsSnap.length,
        ds
      };
    });
    const totalDone = days.reduce((s, d) => s + d.done, 0);
    const maxPossible = days.reduce((s, d) => s + d.total, 0);
    const rate = maxPossible > 0 ? totalDone / maxPossible : 0;
    const best = days.reduce((b, d) => d.done > b.done ? d : b, days[0]);
    const perfectDays = days.filter(d => d.done === d.total && d.total > 0).length;
    const weekNum = Math.ceil((now - new Date(now.getFullYear(), 0, 1)) / 604800000);
    return {
      days,
      rate,
      best,
      total: totalDone,
      maxPossible,
      perfectDays,
      weekNum
    };
  }, []);

  // ── Midnight auto-reset + end-of-week summary ──────────────────────
  useEffect(() => {
    function scheduleMidnight() {
      const now = new Date();
      const midnight = new Date(now);
      midnight.setHours(24, 0, 0, 500);
      const msUntilMidnight = midnight - now;
      return setTimeout(() => {
        const tomorrow = new Date();
        // If tomorrow is Monday (day 1), the week just ended — show summary
        if (tomorrow.getDay() === 1) {
          setCompletions(prev => {
            setWeeklyReport(buildWeeklyReport(prev, habits));
            return {
              ...prev
            };
          });
        } else {
          setCompletions(prev => ({
            ...prev
          }));
        }
        scheduleMidnight();
      }, msUntilMidnight);
    }
    const t = scheduleMidnight();
    return () => clearTimeout(t);
  }, [habits, buildWeeklyReport]);
  const theme = dark ? {
    bg: "#0a0a14",
    surface: "#0f0f22",
    card: "#15152c",
    border: "#ffffff14",
    text: "#f0f0f8",
    muted: "#6060a0",
    primary: accentColor,
    accent: "#d946ef"
  } : {
    bg: "#f0f0f4",
    surface: "#ffffff",
    card: "#ffffff",
    border: "#0000001a",
    text: "#1a1a2e",
    muted: "#7070a0",
    primary: accentColor,
    accent: "#c026d3"
  };
  const vars = Object.entries({
    bg: theme.bg,
    surface: theme.surface,
    card: theme.card,
    border: theme.border,
    text: theme.text,
    muted: theme.muted,
    primary: theme.primary,
    accent: theme.accent
  }).map(([k, v]) => `--${k}: ${v}`).join(";");
  const showToast = (title, body) => setToast({
    title,
    body
  });
  const handleToggle = useCallback((habitId, date, note) => {
    setCompletions(prev => {
      const key = `${habitId}:${date}`;
      if (prev[key]) {
        const next = {
          ...prev
        };
        delete next[key];
        return next;
      }
      const h = habits.find(x => x.id === habitId);
      const newComp = {
        ...prev,
        [key]: {
          note: note || ""
        }
      };
      const newStreak = getStreak(habitId, newComp, h?.freq);
      if (MILESTONE_DAYS.includes(newStreak)) {
        const m = MILESTONE_META[newStreak];
        setConfetti(true);
        setTimeout(() => showToast(`${m.icon} Milestone Unlocked!`, `${h?.name} — ${m.label} (${newStreak} day streak!)`), 200);
      }
      // Award a streak shield every 7 days
      if (newStreak > 0 && newStreak % 7 === 0) {
        setShields(s => s + 1);
        setTimeout(() => showToast("🛡️ Streak Shield Earned!", "Miss a day? Your shield will protect your streak."), 600);
      }
      return newComp;
    });
  }, [habits]);
  const handleSaveHabit = form => {
    const clean = sanitiseHabitForm(form);
    if (editingHabit) {
      setHabits(hs => hs.map(h => h.id === editingHabit.id ? {
        ...h,
        ...clean
      } : h));
      showToast("Habit updated", `${clean.name} has been saved.`);
    } else {
      const id = generateId();
      setHabits(hs => [...hs, {
        id,
        ...clean,
        createdAt: today()
      }]);
      showToast("Habit created!", `Start your streak for ${clean.name} today.`);
    }
    setEditingHabit(null);
    setPage("habits");
  };
  const handleOnboardingComplete = (name, pickedHabits) => {
    const newHabits = pickedHabits.map(h => ({
      ...sanitiseHabitForm(h),
      id: generateId(),
      createdAt: today()
    }));
    setHabits(newHabits);
    setCompletions({});
    setUserName(sanitiseText(name));
    setOnboarded(true);
  };
  const handleDragReorder = (fromIdx, toIdx) => {
    if (fromIdx === toIdx) return;
    setHabits(hs => {
      const arr = [...hs];
      const [moved] = arr.splice(fromIdx, 1);
      arr.splice(toIdx, 0, moved);
      return arr;
    });
  };
  const handleDelete = id => {
    setHabits(hs => hs.filter(h => h.id !== id));
    setCompletions(prev => {
      const next = {
        ...prev
      };
      Object.keys(next).filter(k => k.startsWith(`${id}:`)).forEach(k => delete next[k]);
      return next;
    });
  };
  const NAV = [{
    id: "home",
    label: "Today",
    icon: "✅"
  }, {
    id: "calendar",
    label: "Calendar",
    icon: "📅"
  }, {
    id: "habits",
    label: "All Habits",
    icon: "⊞"
  }, {
    id: "groups",
    label: "Groups",
    icon: "🗂️"
  }, {
    id: "roadmap",
    label: "Roadmap",
    icon: "🎓"
  }, {
    id: "analytics",
    label: "Analytics",
    icon: "📊"
  }, {
    id: "monthly",
    label: "Year Review",
    icon: "🗓️"
  }, {
    id: "achievements",
    label: "Achievements",
    icon: "🏆"
  }, {
    id: "quotes",
    label: "My Quotes",
    icon: "💬"
  }];
  const goPage = p => {
    setEditingHabit(null);
    setPage(p);
  };

  // ── Tauri notifications (daily reminder at user-set time) ──────────
  useEffect(() => {
    async function scheduleReminder() {
      try {
        const {
          isPermissionGranted,
          requestPermission,
          sendNotification
        } = await import("@tauri-apps/plugin-notification");
        let granted = await isPermissionGranted();
        if (!granted) {
          const perm = await requestPermission();
          granted = perm === "granted";
        }
        if (!granted) return;

        // Fire a daily reminder at user-set hour
        function fireAtHour() {
          const now = new Date();
          const next = new Date(now);
          next.setHours(reminderHour, 0, 0, 0);
          if (next <= now) next.setDate(next.getDate() + 1);
          const ms = next - now;
          return setTimeout(async () => {
            const td = fmt(new Date());
            const done = habits.filter(h => completions[`${h.id}:${td}`]).length;
            const remaining = habits.length - done;
            if (remaining > 0) {
              // Fix #21: Notification content is deliberately vague — no habit counts
              // or specific data that could appear on a lock screen or in notification
              // history visible to other users on a shared machine.
              await sendNotification({
                title: "⚡ Zenflow",
                body: "You have habits to complete today. Keep your streak alive!"
              });
            }
            fireAtHour();
          }, ms);
        }
        const t = fireAtHour();
        return () => clearTimeout(t);
      } catch {/* notifications not available */}
    }
    if (loaded) scheduleReminder();
  }, [loaded, habits, completions, reminderHour]);
  return /*#__PURE__*/React.createElement(React.Fragment, null, /*#__PURE__*/React.createElement("style", null, `
        *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: 'DM Sans', sans-serif; }
        @keyframes cf-fall { 0% { transform: translateY(0) rotate(0); opacity: 1; } 100% { transform: translateY(102vh) rotate(720deg); opacity: 0; } }
        @keyframes cf-sway { 0%,100% { margin-left: 0 } 50% { margin-left: 26px } }
        @keyframes pulse-ring { 0% { transform: scale(1); opacity: .4; } 100% { transform: scale(2); opacity: 0; } }
        @keyframes pop-in { 0% { transform: scale(0.7); opacity: 0; } 100% { transform: scale(1); opacity: 1; } }
        @keyframes spin-once { 0% { transform: rotate(0deg) scale(0.5); } 60% { transform: rotate(20deg) scale(1.15); } 100% { transform: rotate(0deg) scale(1); } }
        ::-webkit-scrollbar { width: 4px; } ::-webkit-scrollbar-thumb { background: #ffffff18; border-radius: 4px; }
        [draggable] { user-select: none; }
      `), appLocked && /*#__PURE__*/React.createElement(PinScreen, {
    mode: "unlock",
    onSuccess: () => {
      setAppLocked(false);
      resetSessionTimer();
    },
    onSetPin: () => {}
  }), showPinSetup && /*#__PURE__*/React.createElement(PinScreen, {
    mode: "set",
    onSetPin: hash => {
      localStorage.setItem("zenflow:pin-hash", hash);
      setPinMode(true);
      setAppLocked(false);
      setShowPinSetup(false);
      resetSessionTimer();
    },
    onSuccess: () => {}
  }), showSplash && /*#__PURE__*/React.createElement(SplashScreen, {
    onDone: () => setShowSplash(false)
  }), integrityWarning && /*#__PURE__*/React.createElement("div", {
    style: {
      position: "fixed",
      top: 0,
      left: 0,
      right: 0,
      zIndex: 10002,
      background: "linear-gradient(90deg,#7f1d1d,#991b1b)",
      borderBottom: "1px solid #dc262650",
      padding: "10px 20px",
      display: "flex",
      alignItems: "center",
      gap: 12,
      fontFamily: "'DM Sans',sans-serif",
      fontSize: 13,
      color: "#fecaca"
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      fontSize: 18,
      flexShrink: 0
    }
  }, "\u26A0\uFE0F"), /*#__PURE__*/React.createElement("div", {
    style: {
      flex: 1
    }
  }, /*#__PURE__*/React.createElement("strong", {
    style: {
      color: "#fee2e2"
    }
  }, "Data integrity warning"), " — ", "The stored data for ", /*#__PURE__*/React.createElement("code", {
    style: {
      background: "#ffffff18",
      padding: "1px 5px",
      borderRadius: 3,
      fontSize: 11
    }
  }, integrityWarning), " failed its SHA-256 checksum. The file may be corrupted or tampered with. Your data has been reset to a safe default for this key."), /*#__PURE__*/React.createElement("button", {
    onClick: () => setIntegrityWarning(null),
    style: {
      background: "#ffffff18",
      border: "none",
      borderRadius: 6,
      color: "#fecaca",
      padding: "4px 10px",
      cursor: "pointer",
      fontSize: 12,
      flexShrink: 0
    }
  }, "Dismiss")), loaded && !onboarded && /*#__PURE__*/React.createElement("div", {
    style: {
      position: "fixed",
      inset: 0,
      ["--bg"]: theme.bg,
      ["--card"]: theme.card,
      ["--border"]: theme.border,
      ["--text"]: theme.text,
      ["--muted"]: theme.muted,
      ["--primary"]: theme.primary,
      background: theme.bg,
      color: theme.text
    }
  }, /*#__PURE__*/React.createElement(OnboardingScreen, {
    onComplete: handleOnboardingComplete
  })), /*#__PURE__*/React.createElement("div", {
    style: {
      display: loaded && onboarded ? "flex" : "none",
      height: "100vh",
      background: "var(--bg)",
      color: "var(--text)",
      fontFamily: "'DM Sans',sans-serif",
      ...Object.fromEntries(vars.split(";").filter(Boolean).map(v => {
        const [k, ...rest] = v.split(":");
        return [`--${k.replace("--", "")}`, rest.join(":")];
      }))
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      height: "100vh",
      width: "100%",
      [`--bg`]: theme.bg,
      [`--surface`]: theme.surface,
      [`--card`]: theme.card,
      [`--border`]: theme.border,
      [`--text`]: theme.text,
      [`--muted`]: theme.muted,
      [`--primary`]: theme.primary,
      [`--accent`]: theme.accent
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      width: 210,
      background: theme.surface,
      borderRight: `1px solid ${theme.border}`,
      display: "flex",
      flexDirection: "column",
      flexShrink: 0
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      padding: "18px 16px 10px",
      display: "flex",
      alignItems: "center",
      gap: 10
    }
  }, /*#__PURE__*/React.createElement(ZenflowIcon, {
    size: 34
  }), /*#__PURE__*/React.createElement("div", {
    style: {
      flex: 1,
      minWidth: 0
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      fontFamily: "'Syne',sans-serif",
      fontWeight: 800,
      fontSize: 14,
      color: theme.text,
      lineHeight: 1,
      whiteSpace: "nowrap",
      overflow: "hidden",
      textOverflow: "ellipsis"
    }
  }, "Zenflow"), userName && /*#__PURE__*/React.createElement("div", {
    style: {
      fontSize: 10,
      color: theme.muted,
      marginTop: 2
    }
  }, "Hey, ", userName, " \uD83D\uDC4B")), /*#__PURE__*/React.createElement(StreakShieldBadge, {
    shields: shields
  })), /*#__PURE__*/React.createElement(XPBar, {
    habits: habits,
    completions: completions
  }), /*#__PURE__*/React.createElement("nav", {
    style: {
      flex: 1,
      padding: "4px 8px 0",
      display: "flex",
      flexDirection: "column",
      gap: 2
    }
  }, NAV.map(n => /*#__PURE__*/React.createElement("button", {
    key: n.id,
    onClick: () => goPage(n.id),
    style: {
      display: "flex",
      alignItems: "center",
      gap: 10,
      padding: "9px 12px",
      borderRadius: 10,
      border: "none",
      cursor: "pointer",
      fontSize: 13,
      fontWeight: 500,
      background: page === n.id ? `${theme.primary}18` : "transparent",
      color: page === n.id ? theme.primary : theme.muted,
      transition: ".15s",
      width: "100%",
      textAlign: "left"
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      fontSize: 14
    }
  }, n.icon), n.label)), /*#__PURE__*/React.createElement("button", {
    onClick: () => {
      setEditingHabit(null);
      setPage("form");
    },
    style: {
      display: "flex",
      alignItems: "center",
      gap: 10,
      padding: "9px 12px",
      borderRadius: 10,
      border: "none",
      cursor: "pointer",
      fontSize: 13,
      fontWeight: 500,
      background: page === "form" ? `${theme.primary}18` : "transparent",
      color: page === "form" ? theme.primary : theme.muted,
      transition: ".15s",
      width: "100%",
      textAlign: "left"
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      fontSize: 14
    }
  }, "\uFF0B"), "New Habit")), /*#__PURE__*/React.createElement("div", {
    style: {
      padding: "10px 8px 16px",
      borderTop: `1px solid ${theme.border}`
    }
  }, /*#__PURE__*/React.createElement("button", {
    onClick: () => setDark(d => !d),
    style: {
      display: "flex",
      alignItems: "center",
      gap: 10,
      padding: "9px 12px",
      width: "100%",
      borderRadius: 10,
      border: "none",
      cursor: "pointer",
      fontSize: 13,
      background: "transparent",
      color: theme.muted,
      transition: ".15s"
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      fontSize: 15
    }
  }, dark ? "🌙" : "☀️"), dark ? "Dark" : "Light"), /*#__PURE__*/React.createElement("div", {
    style: {
      padding: "8px 10px",
      marginTop: 4
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      fontSize: 9,
      color: theme.muted,
      letterSpacing: ".08em",
      textTransform: "uppercase",
      marginBottom: 5
    }
  }, "\u23F0 Daily Reminder"), /*#__PURE__*/React.createElement("select", {
    value: reminderHour,
    onChange: e => setReminderHour(Number(e.target.value)),
    style: {
      width: "100%",
      background: "var(--bg)",
      border: "1px solid var(--border)",
      borderRadius: 8,
      color: "var(--text)",
      fontSize: 11,
      padding: "5px 8px",
      cursor: "pointer",
      outline: "none"
    }
  }, Array.from({
    length: 24
  }, (_, h) => /*#__PURE__*/React.createElement("option", {
    key: h,
    value: h
  }, String(h).padStart(2, "0"), ":00 ", h < 12 ? "AM" : "PM")))), /*#__PURE__*/React.createElement("div", {
    style: {
      padding: "8px 10px",
      marginTop: 2
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      fontSize: 9,
      color: theme.muted,
      letterSpacing: ".08em",
      textTransform: "uppercase",
      marginBottom: 8
    }
  }, "\uD83C\uDFA8 Accent Colour"), /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      flexWrap: "wrap",
      gap: 6
    }
  }, ACCENT_COLORS.map(a => /*#__PURE__*/React.createElement("div", {
    key: a.value,
    onClick: () => setAccentColor(a.value),
    title: a.label,
    style: {
      width: 20,
      height: 20,
      borderRadius: "50%",
      background: a.value,
      cursor: "pointer",
      border: accentColor === a.value ? `2px solid ${theme.text}` : "2px solid transparent",
      transition: ".15s",
      transform: accentColor === a.value ? "scale(1.2)" : "scale(1)"
    }
  })))), /*#__PURE__*/React.createElement("div", {
    style: {
      padding: "8px 10px",
      marginTop: 2
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      fontSize: 9,
      color: theme.muted,
      letterSpacing: ".08em",
      textTransform: "uppercase",
      marginBottom: 6
    }
  }, "\uD83D\uDD12 App Lock (PIN)"), pinMode ? /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      gap: 6
    }
  }, /*#__PURE__*/React.createElement("button", {
    onClick: () => setAppLocked(true),
    style: {
      flex: 1,
      padding: "5px 8px",
      borderRadius: 8,
      border: "1px solid var(--border)",
      background: "none",
      color: theme.muted,
      cursor: "pointer",
      fontSize: 10
    }
  }, "Lock Now"), /*#__PURE__*/React.createElement("button", {
    onClick: () => {
      if (window.confirm("Remove PIN protection? Your data will be accessible without a PIN.")) {
        localStorage.removeItem("zenflow:pin-hash");
        setPinMode(false);
      }
    },
    style: {
      flex: 1,
      padding: "5px 8px",
      borderRadius: 8,
      border: "1px solid #f43f5e44",
      background: "none",
      color: "#f43f5e",
      cursor: "pointer",
      fontSize: 10
    }
  }, "Remove PIN")) : /*#__PURE__*/React.createElement("button", {
    onClick: () => setShowPinSetup(true),
    style: {
      width: "100%",
      padding: "6px 10px",
      borderRadius: 8,
      border: "1px solid var(--primary)",
      background: "none",
      color: "var(--primary)",
      cursor: "pointer",
      fontSize: 11,
      fontWeight: 600
    }
  }, "Set PIN")), /*#__PURE__*/React.createElement("div", {
    style: {
      padding: "10px 12px 14px",
      borderTop: `1px solid ${theme.border}`,
      marginTop: 4
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      flexWrap: "wrap",
      gap: 4,
      marginBottom: 6
    }
  }, [["About", () => setShowAbout(true)], ["Privacy", () => setShowPrivacy(true)], ["Terms", () => setShowTerms(true)]].map(([label, fn]) => /*#__PURE__*/React.createElement("button", {
    key: label,
    onClick: fn,
    style: {
      background: "none",
      border: "none",
      cursor: "pointer",
      fontSize: 10,
      color: theme.muted,
      padding: "2px 4px",
      borderRadius: 4,
      transition: ".15s",
      textDecoration: "underline",
      textDecorationColor: "transparent"
    },
    onMouseEnter: e => e.target.style.color = "#10b981",
    onMouseLeave: e => e.target.style.color = theme.muted
  }, label))), /*#__PURE__*/React.createElement("div", {
    style: {
      fontSize: 9,
      color: "#30305a",
      letterSpacing: ".04em"
    }
  }, "\xA9 2026 Zenflow")))), /*#__PURE__*/React.createElement("div", {
    style: {
      flex: 1,
      overflowY: "auto",
      padding: "28px 28px 60px",
      background: theme.bg,
      color: theme.text,
      position: "relative"
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      position: "fixed",
      top: 0,
      left: 210,
      right: 0,
      height: 280,
      background: `radial-gradient(ellipse at 60% 0%, ${accentColor}12 0%, transparent 65%)`,
      pointerEvents: "none"
    }
  }), /*#__PURE__*/React.createElement("div", {
    style: {
      maxWidth: 720,
      margin: "0 auto",
      position: "relative"
    }
  }, page === "home" && focusHabitId && focusDismissed !== fmt(new Date()) && (() => {
    const fh = habits.find(h => h.id === focusHabitId);
    return fh ? /*#__PURE__*/React.createElement(FocusBanner, {
      habit: fh,
      onDismiss: () => setFocusDismissed(fmt(new Date()))
    }) : null;
  })(), /*#__PURE__*/React.createElement(PageTransition, {
    pageKey: page
  }, page === "home" && /*#__PURE__*/React.createElement(HomePage, {
    habits: habits,
    completions: completions,
    onToggle: handleToggle,
    toast: showToast,
    allQuotes: [...QUOTES, ...customQuotes]
  }), page === "calendar" && /*#__PURE__*/React.createElement(CalendarPage, {
    habits: habits,
    completions: completions
  }), page === "habits" && /*#__PURE__*/React.createElement(HabitsListPage, {
    habits: habits,
    completions: completions,
    onDelete: handleDelete,
    onEdit: h => {
      setEditingHabit(h);
      setPage("form");
    },
    onCreate: () => {
      setEditingHabit(null);
      setPage("form");
    },
    onReorder: handleDragReorder
  }), page === "groups" && /*#__PURE__*/React.createElement(HabitGroupsPage, {
    habits: habits,
    habitGroups: habitGroups,
    onSetGroup: (id, g) => setHabitGroups(prev => ({
      ...prev,
      [id]: g
    })),
    completions: completions
  }), page === "form" && /*#__PURE__*/React.createElement(HabitFormPage, {
    habit: editingHabit,
    onSave: handleSaveHabit,
    onCancel: () => goPage("habits")
  }), page === "roadmap" && /*#__PURE__*/React.createElement(LearningRoadmapPage, {
    progress: roadmapProgress,
    onToggle: key => setRoadmapProgress(prev => {
      const n = {
        ...prev
      };
      if (n[key]) delete n[key];else n[key] = true;
      return n;
    })
  }), page === "analytics" && /*#__PURE__*/React.createElement(AnalyticsPage, {
    habits: habits,
    completions: completions,
    onShowWeekly: () => setWeeklyReport(buildWeeklyReport(completions, habits))
  }), page === "monthly" && /*#__PURE__*/React.createElement(MonthlyPage, {
    habits: habits,
    completions: completions
  }), page === "achievements" && /*#__PURE__*/React.createElement(AchievementsPage, {
    habits: habits,
    completions: completions
  }), page === "quotes" && /*#__PURE__*/React.createElement(QuotesPage, {
    customQuotes: customQuotes,
    onSave: setCustomQuotes
  })))))), /*#__PURE__*/React.createElement(Confetti, {
    active: confetti,
    onDone: () => setConfetti(false)
  }), /*#__PURE__*/React.createElement(Toast, {
    msg: toast,
    onHide: () => setToast(null)
  }), /*#__PURE__*/React.createElement(WeeklyReportModal, {
    report: weeklyReport,
    onClose: () => setWeeklyReport(null)
  }), /*#__PURE__*/React.createElement(LevelUpModal, {
    level: levelUpModal,
    onClose: () => setLevelUpModal(null)
  }), loaded && !copyrightAgreed && /*#__PURE__*/React.createElement(CopyrightModal, {
    onAgree: () => {
      setCopyrightAgreed(true);
      persistSet("copyrightAgreed", true);
    }
  }), showPrivacy && /*#__PURE__*/React.createElement(PrivacyModal, {
    onClose: () => setShowPrivacy(false)
  }), showTerms && /*#__PURE__*/React.createElement(TermsModal, {
    onClose: () => setShowTerms(false)
  }), showAbout && /*#__PURE__*/React.createElement(AboutModal, {
    onClose: () => setShowAbout(false)
  }));
}
window.ZenflowApp = App;