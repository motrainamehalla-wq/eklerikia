// طبقة تخزين بسيطة تعتمد على ملف JSON — مناسبة لعدد الأعضاء المتوقع فى كلية إكليريكية.
// لو زاد عدد المستخدمين كثيراً مستقبلاً يمكن استبدالها بقاعدة بيانات حقيقية (Postgres/MySQL)
// بنفس الواجهة (load/save) دون تغيير باقى السيرفر.
const fs = require('fs');
const path = require('path');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');

const DIR = path.join(__dirname, 'data');
const FILE = path.join(DIR, 'db.json');

function ensureFile() {
  if (!fs.existsSync(DIR)) fs.mkdirSync(DIR, { recursive: true });
  if (!fs.existsSync(FILE)) {
    const initial = {
      users: [],
      lectures: [],
      attendance: [],
      admin: { passwordHash: bcrypt.hashSync('2712', 10) },
      sessions: {}
    };
    fs.writeFileSync(FILE, JSON.stringify(initial, null, 2));
  }
}

function load() {
  ensureFile();
  return JSON.parse(fs.readFileSync(FILE, 'utf8'));
}

function save(data) {
  fs.writeFileSync(FILE, JSON.stringify(data, null, 2));
}

function createSession(role, userId) {
  const data = load();
  const token = crypto.randomBytes(24).toString('hex');
  data.sessions[token] = { role, userId, created: Date.now() };
  save(data);
  return token;
}

function getSession(token) {
  const data = load();
  return data.sessions[token] || null;
}

function deleteSession(token) {
  const data = load();
  delete data.sessions[token];
  save(data);
}

module.exports = { load, save, createSession, getSession, deleteSession };
