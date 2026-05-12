/**
 * VULNERABLE SAMPLE: Insecure Authentication & Authorization (Node.js)
 * Kategori: OWASP A07:2021 - Identification and Authentication Failures
 *           OWASP A01:2021 - Broken Access Control
 */

const express = require('express');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const app = express();

app.use(express.json());


// ============================================================
// HARDCODED SECRETS & WEAK JWT
// ============================================================

// VULNERABILITY: Hardcoded JWT secret
const JWT_SECRET = 'secret123';
const ADMIN_PASSWORD = 'admin123';

// VULNERABLE: Weak JWT configuration
app.post('/login', (req, res) => {
  const { username, password } = req.body;

  // VULNERABILITY: Hardcoded credentials comparison
  if (username === 'admin' && password === ADMIN_PASSWORD) {
    // VULNERABILITY: Weak secret, no expiry, algorithm not specified securely
    const token = jwt.sign({ username, role: 'admin' }, JWT_SECRET);
    res.json({ token });
  } else {
    res.status(401).json({ error: 'Invalid credentials' });
  }
});

// VULNERABLE: JWT verification tanpa algorithm specification
app.get('/admin', (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];

  try {
    // VULNERABILITY: Tidak menentukan algoritma yang diizinkan
    // Rentan terhadap "alg:none" attack
    const decoded = jwt.verify(token, JWT_SECRET);
    res.json({ message: 'Welcome admin', user: decoded });
  } catch (err) {
    res.status(401).json({ error: 'Unauthorized' });
  }
});

// SECURE: JWT dengan algoritma eksplisit dan expiry
app.post('/login/secure', (req, res) => {
  const { username, password } = req.body;
  const secretKey = process.env.JWT_SECRET; // SECURE: dari environment variable
  
  if (!secretKey) {
    return res.status(500).json({ error: 'Server configuration error' });
  }

  // Verifikasi credentials dengan database (pseudocode)
  // const user = await db.findUser(username, hashPassword(password));
  
  const token = jwt.sign(
    { username, role: 'user' },
    secretKey,
    {
      algorithm: 'HS256',
      expiresIn: '1h'
    }
  );
  res.json({ token });
});


// ============================================================
// BROKEN ACCESS CONTROL
// ============================================================

const usersData = {
  1: { id: 1, name: 'Alice', email: 'alice@example.com', salary: 50000 },
  2: { id: 2, name: 'Bob', email: 'bob@example.com', salary: 60000 },
  3: { id: 3, name: 'Charlie', email: 'charlie@example.com', salary: 75000 },
};

// VULNERABLE: Insecure Direct Object Reference (IDOR)
app.get('/user/:id', (req, res) => {
  const userId = req.params.id;
  
  // VULNERABILITY: Tidak ada pemeriksaan apakah user yang login boleh akses data ini
  // Attacker bisa akses /user/1, /user/2, dll untuk melihat data user lain
  const user = usersData[userId];
  if (!user) return res.status(404).json({ error: 'User not found' });
  
  res.json(user); // Mengembalikan semua data termasuk salary!
});

// VULNERABLE: Mass Assignment
app.put('/user/update', (req, res) => {
  const { userId } = req.body;
  
  // VULNERABILITY: Semua field dari request body langsung diupdate
  // Attacker bisa set: { userId: 1, role: "admin", isVerified: true }
  Object.assign(usersData[userId], req.body);
  res.json({ message: 'User updated', user: usersData[userId] });
});

// SECURE: Proper Authorization Check
function authenticateToken(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token provided' });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET, {
      algorithms: ['HS256'] // SECURE: Whitelist algoritma
    });
    req.user = decoded;
    next();
  } catch (err) {
    res.status(403).json({ error: 'Invalid token' });
  }
}

app.get('/user/:id/secure', authenticateToken, (req, res) => {
  const requestedId = parseInt(req.params.id);
  
  // SECURE: Hanya izinkan akses ke data sendiri (kecuali admin)
  if (req.user.id !== requestedId && req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Access denied' });
  }
  
  const user = usersData[requestedId];
  if (!user) return res.status(404).json({ error: 'User not found' });
  
  // SECURE: Hanya kembalikan field yang diperlukan
  const { id, name, email } = user;
  res.json({ id, name, email });
});


// ============================================================
// INSECURE RANDOM / CRYPTO
// ============================================================

// VULNERABLE: Math.random() untuk token keamanan
function generateTokenVulnerable() {
  // VULNERABILITY: Math.random() tidak kriptografis aman
  return Math.random().toString(36).substring(2);
}

// VULNERABLE: Weak password reset token
app.post('/forgot-password', (req, res) => {
  const { email } = req.body;
  
  // VULNERABILITY: Token menggunakan timestamp yang mudah ditebak
  const resetToken = Date.now().toString();
  
  res.json({ message: 'Reset link sent', token: resetToken }); // Juga VULNERABILITY: Token dikirim ke response
});

// SECURE: Cryptographically secure random token
function generateTokenSecure() {
  // SECURE: crypto.randomBytes() menggunakan CSPRNG
  return crypto.randomBytes(32).toString('hex');
}

app.post('/forgot-password/secure', (req, res) => {
  const { email } = req.body;
  
  // SECURE: Token kriptografis aman
  const resetToken = crypto.randomBytes(32).toString('hex');
  
  // Simpan token di database dengan expiry
  // await db.saveResetToken(email, hashToken(resetToken), Date.now() + 3600000);
  
  // Kirim via email, JANGAN via response
  // await sendEmail(email, resetToken);
  
  res.json({ message: 'Reset link sent to your email' });
});


app.listen(3001, () => console.log('Auth server running on port 3001'));
module.exports = app;
