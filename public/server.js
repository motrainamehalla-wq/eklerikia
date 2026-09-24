const express = require('express');
const path = require('path');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const db = require('./db');

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ---------- auth middleware ----------
function auth(requiredRole) {
  return (req, res, next) => {
    const header = req.headers.authorization || '';
    const token = header.startsWith('Bearer ') ? header.slice(7) : null;
    const session = token && db.getSession(token);
    if (!session) return res.status(401).json({ error: 'غير مصرح، من فضلك سجل الدخول مرة أخرى' });
    if (requiredRole && session.role !== requiredRole) {
      return res.status(403).json({ error: 'لا تملك صلاحية الوصول لهذا الإجراء' });
    }
    req.session = session;
    req.token = token;
    next();
  };
}

// ================= AUTH =================
const GRADES = ['الأولى', 'الثانية', 'الثالثة', 'الرابعة'];
const LECTURE_GRADES = [...GRADES, 'عام'];

app.post('/api/register', (req, res) => {
  const { name, nationalId, church, password, grade } = req.body || {};
  if (!name || !nationalId || !church || !password || !grade) {
    return res.status(400).json({ error: 'من فضلك أكمل جميع البيانات' });
  }
  if (!GRADES.includes(grade)) {
    return res.status(400).json({ error: 'من فضلك اختر الفرقة بشكل صحيح' });
  }
  const data = db.load();
  if (nationalId === 'admin' || data.users.some(u => u.nationalId === nationalId)) {
    return res.status(400).json({ error: 'هذا الرقم القومى مسجل بالفعل' });
  }
  data.users.push({
    id: crypto.randomUUID(),
    name, nationalId, church, grade,
    passwordHash: bcrypt.hashSync(password, 10),
    status: 'pending',
    createdAt: Date.now()
  });
  db.save(data);
  res.json({ ok: true });
});

app.post('/api/login', (req, res) => {
  const { nationalId, password } = req.body || {};
  const data = db.load();
  if (nationalId === 'admin') {
    if (!bcrypt.compareSync(password || '', data.admin.passwordHash)) {
      return res.status(401).json({ error: 'كلمة المرور غير صحيحة' });
    }
    return res.json({ token: db.createSession('admin', null), role: 'admin' });
  }
  const user = data.users.find(u => u.nationalId === nationalId);
  if (!user) return res.status(401).json({ error: 'لا يوجد حساب بهذا الرقم القومى' });
  if (!bcrypt.compareSync(password || '', user.passwordHash)) {
    return res.status(401).json({ error: 'كلمة المرور غير صحيحة' });
  }
  if (user.status !== 'approved') {
    return res.status(403).json({ error: 'حسابك لا يزال قيد المراجعة من الإدارة' });
  }
  res.json({
    token: db.createSession('member', user.id),
    role: 'member',
    user: { id: user.id, name: user.name, church: user.church, nationalId: user.nationalId }
  });
});

app.post('/api/logout', auth(), (req, res) => {
  db.deleteSession(req.token);
  res.json({ ok: true });
});

// ================= MEMBER PROFILE =================
app.get('/api/me', auth('member'), (req, res) => {
  const data = db.load();
  const u = data.users.find(x => x.id === req.session.userId);
  if (!u) return res.status(404).json({ error: 'الحساب غير موجود' });
  res.json({ id: u.id, name: u.name, church: u.church, nationalId: u.nationalId, grade: u.grade || null });
});

app.put('/api/me', auth('member'), (req, res) => {
  const data = db.load();
  const u = data.users.find(x => x.id === req.session.userId);
  if (!u) return res.status(404).json({ error: 'الحساب غير موجود' });
  const { name, church, password } = req.body || {};
  if (name) u.name = name;
  if (church) u.church = church;
  if (password) u.passwordHash = bcrypt.hashSync(password, 10);
  db.save(data);
  res.json({ ok: true });
});

// ================= LECTURES / SCHEDULE =================
app.get('/api/lectures', auth(), (req, res) => {
  res.json(db.load().lectures);
});

app.post('/api/lectures', auth('admin'), (req, res) => {
  const { title, date, time, grade } = req.body || {};
  if (!title || !date || !grade) return res.status(400).json({ error: 'أكمل بيانات المحاضرة' });
  if (!LECTURE_GRADES.includes(grade)) return res.status(400).json({ error: 'اختر الفرقة المستهدفة بشكل صحيح' });
  const data = db.load();
  const lecture = {
    id: crypto.randomUUID(), title, date, time: time || '', grade,
    code: 'LEC-' + crypto.randomBytes(4).toString('hex').toUpperCase()
  };
  data.lectures.push(lecture);
  db.save(data);
  res.json(lecture);
});

app.delete('/api/lectures/:id', auth('admin'), (req, res) => {
  const data = db.load();
  data.lectures = data.lectures.filter(l => l.id !== req.params.id);
  data.attendance = data.attendance.filter(a => a.lectureId !== req.params.id);
  db.save(data);
  res.json({ ok: true });
});

// ================= MEMBERS MANAGEMENT (admin) =================
app.get('/api/users', auth('admin'), (req, res) => {
  const data = db.load();
  res.json(data.users.map(u => ({ id: u.id, name: u.name, nationalId: u.nationalId, church: u.church, status: u.status, grade: u.grade || null })));
});

app.post('/api/users/:id/approve', auth('admin'), (req, res) => {
  const data = db.load();
  const u = data.users.find(x => x.id === req.params.id);
  if (!u) return res.status(404).json({ error: 'العضو غير موجود' });
  u.status = 'approved';
  db.save(data);
  res.json({ ok: true });
});

app.put('/api/users/:id', auth('admin'), (req, res) => {
  const data = db.load();
  const u = data.users.find(x => x.id === req.params.id);
  if (!u) return res.status(404).json({ error: 'العضو غير موجود' });
  const { name, church, grade, password } = req.body || {};
  if (grade && !GRADES.includes(grade)) return res.status(400).json({ error: 'فرقة غير صحيحة' });
  if (name) u.name = name;
  if (church) u.church = church;
  if (grade) u.grade = grade;
  if (password) u.passwordHash = bcrypt.hashSync(password, 10);
  db.save(data);
  res.json({ ok: true });
});

app.delete('/api/users/:id', auth('admin'), (req, res) => {
  const data = db.load();
  data.users = data.users.filter(u => u.id !== req.params.id);
  data.attendance = data.attendance.filter(a => a.userId !== req.params.id);
  db.save(data);
  res.json({ ok: true });
});

app.post('/api/users/bulk-import', auth('admin'), (req, res) => {
  const { rows } = req.body || {};
  if (!Array.isArray(rows) || !rows.length) return res.status(400).json({ error: 'لا توجد بيانات للاستيراد' });
  const data = db.load();
  let created = 0;
  const skipped = [];
  rows.forEach(r => {
    const name = (r.name || '').trim();
    const nationalId = (r.nationalId || '').trim();
    const church = (r.church || '').trim();
    const grade = (r.grade || '').trim();
    const password = (r.password || '').trim() || nationalId;
    if (!name || !nationalId || !church || !GRADES.includes(grade)) {
      skipped.push({ row: r, reason: 'بيانات ناقصة أو فرقة غير صحيحة' });
      return;
    }
    if (nationalId === 'admin' || data.users.some(u => u.nationalId === nationalId)) {
      skipped.push({ row: r, reason: 'الرقم القومى مسجل بالفعل' });
      return;
    }
    data.users.push({
      id: crypto.randomUUID(),
      name, nationalId, church, grade,
      passwordHash: bcrypt.hashSync(password, 10),
      status: 'approved',
      createdAt: Date.now()
    });
    created++;
  });
  db.save(data);
  res.json({ created, skipped });
});

// ================= ATTENDANCE =================
app.get('/api/attendance/mine', auth('member'), (req, res) => {
  const data = db.load();
  res.json(data.attendance.filter(a => a.userId === req.session.userId));
});

app.get('/api/attendance', auth('admin'), (req, res) => {
  const data = db.load();
  const { lectureId } = req.query;
  res.json(lectureId ? data.attendance.filter(a => a.lectureId === lectureId) : data.attendance);
});

app.post('/api/attendance/scan', auth('member'), (req, res) => {
  const { code } = req.body || {};
  const data = db.load();
  const lecture = data.lectures.find(l => l.code === (code || '').trim());
  if (!lecture) return res.status(400).json({ error: 'كود غير صالح' });
  const already = data.attendance.some(a => a.lectureId === lecture.id && a.userId === req.session.userId);
  if (!already) {
    data.attendance.push({ id: crypto.randomUUID(), lectureId: lecture.id, userId: req.session.userId, time: Date.now() });
    db.save(data);
  }
  res.json({ ok: true, already, title: lecture.title });
});

app.post('/api/attendance/toggle', auth('admin'), (req, res) => {
  const { lectureId, userId } = req.body || {};
  const data = db.load();
  const idx = data.attendance.findIndex(a => a.lectureId === lectureId && a.userId === userId);
  if (idx >= 0) data.attendance.splice(idx, 1);
  else data.attendance.push({ id: crypto.randomUUID(), lectureId, userId, time: Date.now() });
  db.save(data);
  res.json({ ok: true });
});

// ================= ADMIN SETTINGS =================
app.post('/api/admin/change-password', auth('admin'), (req, res) => {
  const { newPassword } = req.body || {};
  if (!newPassword || newPassword.length < 4) {
    return res.status(400).json({ error: 'كلمة المرور يجب ألا تقل عن 4 خانات' });
  }
  const data = db.load();
  data.admin.passwordHash = bcrypt.hashSync(newPassword, 10);
  db.save(data);
  res.json({ ok: true });
});

// ---------- fallback to frontend ----------
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`✝ Seminary server running on port ${PORT}`));
