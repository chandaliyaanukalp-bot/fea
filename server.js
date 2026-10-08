const express = require("express");
const cookieParser = require("cookie-parser");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const multer = require("multer");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const app = express();
const PORT = process.env.PORT || 3000;
const SECRET = process.env.JWT_SECRET || "CHANGE_THIS_SECRET_IN_PRODUCTION";
const DB_FILE = process.env.DATA_FILE || path.join(__dirname, "data.json");

function loadDB() {
  try { return JSON.parse(fs.readFileSync(DB_FILE, "utf8")); }
  catch { return { users: [], decks: [], progress: {} }; }
}
let db = loadDB();
function saveDB() {
  fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2), "utf8");
}
function id() { return crypto.randomUUID(); }

app.use(express.json({ limit: "1mb" }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, "public")));

function auth(req, res, next) {
  const token = req.cookies.sd_token;
  if (!token) return res.status(401).json({ error: "Not logged in" });
  try {
    const payload = jwt.verify(token, SECRET);
    req.user = db.users.find(u => u.id === payload.uid);
    if (!req.user) throw new Error("user missing");
    next();
  } catch {
    res.clearCookie("sd_token");
    return res.status(401).json({ error: "Session expired" });
  }
}

app.post("/api/register", async (req, res) => {
  const username = String(req.body.username || "").trim();
  const password = String(req.body.password || "");
  if (!/^[a-zA-Z0-9_]{3,24}$/.test(username))
    return res.status(400).json({ error: "Username must be 3–24 letters, numbers or _." });
  if (password.length < 6)
    return res.status(400).json({ error: "Password must be at least 6 characters." });
  if (db.users.some(u => u.username.toLowerCase() === username.toLowerCase()))
    return res.status(409).json({ error: "Username already exists." });

  const user = { id: id(), username, password: await bcrypt.hash(password, 12), createdAt: Date.now() };
  db.users.push(user);
  saveDB();
  const token = jwt.sign({ uid: user.id }, SECRET, { expiresIn: "30d" });
  res.cookie("sd_token", token, { httpOnly: true, sameSite: "lax", secure: process.env.NODE_ENV === "production", maxAge: 30*24*60*60*1000 });
  res.json({ user: { id: user.id, username: user.username } });
});

app.post("/api/login", async (req, res) => {
  const username = String(req.body.username || "").trim();
  const password = String(req.body.password || "");
  const user = db.users.find(u => u.username.toLowerCase() === username.toLowerCase());
  if (!user || !(await bcrypt.compare(password, user.password)))
    return res.status(401).json({ error: "Invalid username or password." });
  const token = jwt.sign({ uid: user.id }, SECRET, { expiresIn: "30d" });
  res.cookie("sd_token", token, { httpOnly: true, sameSite: "lax", secure: process.env.NODE_ENV === "production", maxAge: 30*24*60*60*1000 });
  res.json({ user: { id: user.id, username: user.username } });
});

app.post("/api/logout", (req, res) => { res.clearCookie("sd_token"); res.json({ ok: true }); });

app.get("/api/me", auth, (req, res) =>
  res.json({ user: { id: req.user.id, username: req.user.username } })
);

app.get("/api/decks", auth, (req, res) => {
  res.json(db.decks.filter(d => d.owner === req.user.id).map(d => ({
    id: d.id, name: d.name, cards: d.cards.length, createdAt: d.createdAt
  })));
});

app.get("/api/decks/:id", auth, (req, res) => {
  const d = db.decks.find(x => x.id === req.params.id && x.owner === req.user.id);
  if (!d) return res.status(404).json({ error: "Deck not found" });
  const p = db.progress[req.user.id + ":" + d.id] || Array(d.cards.length).fill(0);
  res.json({ ...d, progress: p });
});

app.delete("/api/decks/:id", auth, (req, res) => {
  const before = db.decks.length;
  db.decks = db.decks.filter(d => !(d.id === req.params.id && d.owner === req.user.id));
  if (db.decks.length === before) return res.status(404).json({ error: "Deck not found" });
  delete db.progress[req.user.id + ":" + req.params.id];
  saveDB();
  res.json({ ok: true });
});

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 2 * 1024 * 1024 }
});

function parseCSV(text) {
  const rows = [];
  let row = [], cell = "", quote = false;
  for (let i=0; i<text.length; i++) {
    const c = text[i], n = text[i+1];
    if (c === '"' && quote && n === '"') { cell += '"'; i++; continue; }
    if (c === '"') { quote = !quote; continue; }
    if (c === ',' && !quote) { row.push(cell.trim()); cell = ""; continue; }
    if ((c === '\n' || c === '\r') && !quote) {
      if (c === '\r' && n === '\n') i++;
      row.push(cell.trim()); cell = "";
      if (row.some(x => x.length)) rows.push(row);
      row = []; continue;
    }
    cell += c;
  }
  row.push(cell.trim());
  if (row.some(x => x.length)) rows.push(row);
  return rows;
}

app.post("/api/decks/import", auth, upload.single("file"), (req, res) => {
  if (!req.file) return res.status(400).json({ error: "CSV file required." });
  const rows = parseCSV(req.file.buffer.toString("utf8").replace(/^\uFEFF/, ""));
  const cards = rows
    .map(r => ({ question: r[0] || "", answer: r.slice(1).join(",") || "" }))
    .filter(x => x.question && x.answer);
  if (!cards.length) return res.status(400).json({ error: "No valid question,answer rows found." });

  const deck = {
    id: id(),
    owner: req.user.id,
    name: String(req.body.name || req.file.originalname.replace(/\.csv$/i, "") || "Imported Deck").trim().slice(0, 80),
    cards, createdAt: Date.now()
  };
  db.decks.push(deck);
  db.progress[req.user.id + ":" + deck.id] = Array(cards.length).fill(0);
  saveDB();
  res.json({ id: deck.id, name: deck.name, cards: cards.length });
});

app.put("/api/decks/:id/progress", auth, (req, res) => {
  const d = db.decks.find(x => x.id === req.params.id && x.owner === req.user.id);
  if (!d) return res.status(404).json({ error: "Deck not found" });
  const p = Array.isArray(req.body.progress) ? req.body.progress : [];
  db.progress[req.user.id + ":" + d.id] = d.cards.map((_, i) => p[i] === 1 ? 1 : p[i] === -1 ? -1 : 0);
  saveDB();
  res.json({ ok: true });
});

app.get("*", (req, res) => res.sendFile(path.join(__dirname, "public", "index.html")));

app.listen(PORT, () => console.log(`StudyDeck running on port ${PORT}`));
