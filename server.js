const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const path = require('path');

const app = express();
const server = http.createServer(app);
const io = new Server(server);

// --- База данных ---
const db = new Database('messenger.db');
db.pragma('journal_mode = WAL');
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    username TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    from_id INTEGER NOT NULL,
    to_id INTEGER NOT NULL,
    text TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
`);

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// --- Регистрация ---
app.post('/api/register', (req, res) => {
  const { email, password, username } = req.body;
  if (!email || !password || !username)
    return res.status(400).json({ error: 'Заполни все поля' });
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))
    return res.status(400).json({ error: 'Некорректный email' });
  if (password.length < 6)
    return res.status(400).json({ error: 'Пароль минимум 6 символов' });

  const existing = db.prepare('SELECT id FROM users WHERE email = ?').get(email);
  if (existing) return res.status(400).json({ error: 'Email уже занят' });

  const hash = bcrypt.hashSync(password, 10);
  const info = db.prepare('INSERT INTO users (email, password, username) VALUES (?, ?, ?)').run(email, hash, username);
  res.json({ id: info.lastInsertRowid, email, username });
});

// --- Вход ---
app.post('/api/login', (req, res) => {
  const { email, password } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
  if (!user || !bcrypt.compareSync(password, user.password))
    return res.status(401).json({ error: 'Неверный email или пароль' });
  res.json({ id: user.id, email: user.email, username: user.username });
});

// --- WebSocket ---
const onlineUsers = new Map(); // socketId -> { id, username }

io.on('connection', (socket) => {
  socket.on('auth', (user) => {
    socket.user = user;
    onlineUsers.set(socket.id, user);
    io.emit('online', Array.from(onlineUsers.values()).filter(u => u.id !== user.id));
  });

  socket.on('send message', ({ toId, text }) => {
    if (!socket.user || !text) return;
    const msg = db.prepare('INSERT INTO messages (from_id, to_id, text) VALUES (?, ?, ?)')
      .run(socket.user.id, toId, text);
    const full = {
      id: msg.lastInsertRowid,
      from: socket.user,
      toId,
      text,
      time: new Date().toISOString()
    };
    // Отправляем получателю, если онлайн
    for (const [sid, u] of onlineUsers.entries()) {
      if (u.id === toId) io.to(sid).emit('message', full);
    }
    // И отправителю (подтверждение)
    socket.emit('message', full);
  });

  socket.on('load history', ({ withId }, cb) => {
    if (!socket.user) return cb([]);
    const rows = db.prepare(`
      SELECT * FROM messages
      WHERE (from_id = ? AND to_id = ?) OR (from_id = ? AND to_id = ?)
      ORDER BY created_at DESC LIMIT 100
    `).all(socket.user.id, withId, withId, socket.user.id).reverse();

    const usersCache = {};
    const getUser = (id) => {
      if (id === socket.user.id) return socket.user;
      if (usersCache[id]) return usersCache[id];
      const u = db.prepare('SELECT id, username FROM users WHERE id = ?').get(id);
      usersCache[id] = u;
      return u;
    };

    cb(rows.map(r => ({
      id: r.id,
      from: getUser(r.from_id),
      toId: r.to_id,
      text: r.text,
      time: r.created_at
    })));
  });

  socket.on('disconnect', () => {
    onlineUsers.delete(socket.id);
    io.emit('online', Array.from(onlineUsers.values()));
  });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log(`Мессенджер работает: http://localhost:${PORT}`));