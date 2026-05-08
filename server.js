const express = require('express');
const initSqlJs = require('sql.js');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const fs = require('fs');
const path = require('path');

const app = express();

// ============================================================
// КОНФИГУРАЦИЯ
// ============================================================
const PORT = 5000;
const JWT_SECRET = 'supersecretkey_lab2_23';
const TOKEN_EXPIRY = '5m';
const DB_FILE = path.join(__dirname, 'users.db');

let db; // Будет хранить подключение к БД

// ============================================================
// ИНИЦИАЛИЗАЦИЯ БАЗЫ ДАННЫХ
// ============================================================
async function initDatabase() {
  const SQL = await initSqlJs();
  
  // Загружаем существующую БД или создаём новую
  if (fs.existsSync(DB_FILE)) {
    const fileBuffer = fs.readFileSync(DB_FILE);
    db = new SQL.Database(fileBuffer);
  } else {
    db = new SQL.Database();
  }
  
  // Создаём таблицу, если её нет
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      full_name TEXT,
      created_at TEXT DEFAULT (datetime('now'))
    )
  `);
  
  // Сохраняем изменения
  saveDatabase();
  
  // Добавляем тестового пользователя
  const testUser = db.exec('SELECT id FROM users WHERE username = ?', ['testuser']);
  if (testUser.length === 0 || testUser[0].values.length === 0) {
    const hash = await bcrypt.hash('testpass123', 10);
    db.run(
      'INSERT INTO users (username, email, password, full_name) VALUES (?, ?, ?, ?)',
      ['testuser', 'test@example.com', hash, 'Тестовый Пользователь']
    );
    saveDatabase();
    console.log('✅ Тестовый пользователь создан: testuser / testpass123');
  }
}

function saveDatabase() {
  const data = db.export();
  const buffer = Buffer.from(data);
  fs.writeFileSync(DB_FILE, buffer);
}

// ============================================================
// MIDDLEWARE
// ============================================================
app.use(cors());
app.use(express.json());

// ============================================================
// ЗАДАНИЕ 1: РЕГИСТРАЦИЯ
// ============================================================
app.post('/register', async (req, res) => {
  try {
    const { username, email, password, full_name } = req.body;

    // Проверка заполнения
    if (!username || !email || !password) {
      return res.status(400).json({ 
        error: 'Заполните все обязательные поля: username, email, password' 
      });
    }

    // Проверка пароля
    if (password.length < 6) {
      return res.status(400).json({ 
        error: 'Пароль должен содержать минимум 6 символов' 
      });
    }

    // Проверка уникальности username
    const existingUser = db.exec('SELECT id FROM users WHERE username = ?', [username]);
    if (existingUser.length > 0 && existingUser[0].values.length > 0) {
      return res.status(400).json({ 
        error: `Пользователь с логином '${username}' уже существует` 
      });
    }

    // Проверка уникальности email
    const existingEmail = db.exec('SELECT id FROM users WHERE email = ?', [email]);
    if (existingEmail.length > 0 && existingEmail[0].values.length > 0) {
      return res.status(400).json({ 
        error: `Email '${email}' уже используется` 
      });
    }

    // Хеширование пароля
    const hashedPassword = await bcrypt.hash(password, 10);

    // Сохранение в БД
    db.run(
      'INSERT INTO users (username, email, password, full_name) VALUES (?, ?, ?, ?)',
      [username, email, hashedPassword, full_name || null]
    );
    saveDatabase();

    // Получаем id нового пользователя
    const result = db.exec('SELECT last_insert_rowid() as id');
    const newId = result[0].values[0][0];

    res.status(201).json({
      message: 'Пользователь успешно зарегистрирован',
      user: {
        id: newId,
        username,
        email,
        full_name: full_name || null
      }
    });

  } catch (error) {
    console.error('Ошибка регистрации:', error);
    res.status(500).json({ error: 'Внутренняя ошибка сервера' });
  }
});

// ============================================================
// ЗАДАНИЕ 2: АУТЕНТИФИКАЦИЯ (ВХОД)
// ============================================================
app.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ error: 'Укажите логин и пароль' });
    }

    // Поиск пользователя
    const result = db.exec(
      'SELECT id, username, email, password, full_name FROM users WHERE username = ?',
      [username]
    );

    if (result.length === 0 || result[0].values.length === 0) {
      return res.status(401).json({ error: 'Неверный логин или пароль' });
    }

    const user = {
      id: result[0].values[0][0],
      username: result[0].values[0][1],
      email: result[0].values[0][2],
      password: result[0].values[0][3],
      full_name: result[0].values[0][4]
    };

    // Проверка пароля
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({ error: 'Неверный логин или пароль' });
    }

    // Создание JWT токена
    const token = jwt.sign(
      { userId: user.id, username: user.username },
      JWT_SECRET,
      { expiresIn: TOKEN_EXPIRY }
    );

    res.json({
      message: 'Успешный вход',
      token,
      token_type: 'bearer',
      expires_in: TOKEN_EXPIRY,
      user: {
        id: user.id,
        username: user.username,
        email: user.email
      }
    });

  } catch (error) {
    console.error('Ошибка входа:', error);
    res.status(500).json({ error: 'Внутренняя ошибка сервера' });
  }
});

// ============================================================
// ЗАДАНИЕ 3: MIDDLEWARE ПРОВЕРКИ JWT
// ============================================================
function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization;

  // Нет заголовка
  if (!authHeader) {
    return res.status(401).json({ 
      error: 'Токен отсутствует',
      detail: 'Добавьте заголовок Authorization: Bearer <token>'
    });
  }

  // Неверный формат
  const parts = authHeader.split(' ');
  if (parts.length !== 2 || parts[0] !== 'Bearer') {
    return res.status(401).json({ 
      error: 'Неверный формат токена',
      detail: 'Используйте: Bearer <token>'
    });
  }

  const token = parts[1];

  // Проверка токена
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({ 
        error: 'Срок действия токена истёк',
        detail: 'Выполните вход заново'
      });
    }
    if (error.name === 'JsonWebTokenError') {
      return res.status(401).json({ 
        error: 'Неверный токен',
        detail: 'Токен повреждён или имеет неверную подпись'
      });
    }
    return res.status(401).json({ error: 'Ошибка проверки токена' });
  }
}

// ============================================================
// ЗАДАНИЕ 4: ЗАЩИЩЁННЫЙ МАРШРУТ (ПРОФИЛЬ)
// ============================================================
app.get('/profile', authMiddleware, (req, res) => {
  try {
    const result = db.exec(
      'SELECT id, username, email, full_name, created_at FROM users WHERE id = ?',
      [req.user.userId]
    );

    if (result.length === 0 || result[0].values.length === 0) {
      return res.status(404).json({ error: 'Пользователь не найден' });
    }

    const user = {
      id: result[0].values[0][0],
      username: result[0].values[0][1],
      email: result[0].values[0][2],
      full_name: result[0].values[0][3],
      created_at: result[0].values[0][4]
    };

    res.json({
      message: 'Доступ к защищённому маршруту разрешён',
      user,
      token_info: {
        username: req.user.username,
        issued_at: new Date(req.user.iat * 1000).toISOString(),
        expires_at: new Date(req.user.exp * 1000).toISOString()
      }
    });

  } catch (error) {
    res.status(500).json({ error: 'Ошибка получения профиля' });
  }
});

// Дополнительный защищённый маршрут
app.get('/admin', authMiddleware, (req, res) => {
  res.json({
    message: `Пользователь ${req.user.username} имеет доступ`,
    user_id: req.user.userId
  });
});

// ============================================================
// ПУБЛИЧНЫЙ МАРШРУТ
// ============================================================
app.get('/', (req, res) => {
  res.json({
    service: 'JWT Auth API (Lab2)',
    version: '2.0.0',
    database: 'SQLite (sql.js)',
    endpoints: {
      'Публичный': 'GET /',
      'Регистрация': 'POST /register',
      'Вход': 'POST /login',
      'Профиль (защищённый)': 'GET /profile',
      'Админ (защищённый)': 'GET /admin'
    },
    test_user: {
      username: 'testuser',
      password: 'testpass123'
    }
  });
});

// ============================================================
// ЗАПУСК СЕРВЕРА
// ============================================================
async function start() {
  await initDatabase();
  
  app.listen(PORT, () => {
    console.log(`\n🚀 Сервер запущен: http://localhost:${PORT}`);
    console.log(`📁 База данных: ${DB_FILE}`);
    console.log(`⏳ Токен живёт: ${TOKEN_EXPIRY}`);
    console.log(`\n📋 Тестовый пользователь:`);
    console.log(`   Логин: testuser`);
    console.log(`   Пароль: testpass123\n`);
  });
}

start();