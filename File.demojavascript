/*
  vulnerable_examples.js
  ----------------------
  A single JavaScript file that contains multiple intentionally vulnerable code
  snippets for educational and defensive learning purposes only.

  DO NOT deploy this code to production. Run only in a controlled, isolated
  environment. Each example includes a short explanation and recommended fix.
*/

///////////////////////////
// 1) DOM XSS (Client)  //
///////////////////////////

// Vulnerable pattern: inserting untrusted input into innerHTML.
// When input contains HTML/script, it becomes executable.
function displayUsernameUnsafe(username) {
  // ATTACKER-CONTROLLED: username
  const target = document.getElementById('greeting');
  // Vulnerable: innerHTML allows script tags to execute
  target.innerHTML = `Hello, ${username}!`;
}

// Fix: escape or use textContent to avoid interpreting HTML
function displayUsernameSafe(username) {
  const target = document.getElementById('greeting');
  target.textContent = `Hello, ${username}!`;
}

/////////////////////////////
// 2) insecure eval (Client)
/////////////////////////////

// Vulnerable pattern: eval on attacker-controlled string
function computeExpressionUnsafe(exprString) {
  // exprString might be provided by a user
  return eval(exprString); // dangerous: arbitrary code execution
}

// Fix: use a proper math parser or whitelist allowed tokens
function computeExpressionSafe(exprString) {
  // very small safe evaluator: only numbers and + - * / and parentheses
  if (!/^[0-9+\-*/() \t.]+$/.test(exprString)) throw new Error('invalid expression');
  // eslint-disable-next-line no-new-func
  return Function(`"use strict"; return (${exprString});`)();
}

////////////////////////////////////////////////////
// 3) Server-side SQL injection (Node + mysql example)
////////////////////////////////////////////////////

// Vulnerable pattern: building SQL by concatenation
const mysql = require('mysql');
const pool = mysql.createPool({
  host: '127.0.0.1', user: 'app', password: '', database: 'appdb'
});

function getUserByEmailUnsafe(email, callback) {
  // UNSAFE: directly concatenating user input into SQL
  const q = "SELECT * FROM users WHERE email = '" + email + "'";
  pool.query(q, callback);
}

// Fix: use parameterized queries / prepared statements
function getUserByEmailSafe(email, callback) {
  const q = 'SELECT * FROM users WHERE email = ?';
  pool.query(q, [email], callback);
}

/////////////////////////////////////////////////////////
// 4) Insecure deserialization (Node - object prototype pollution)
/////////////////////////////////////////////////////////

// Vulnerable pattern: merging attacker-controlled objects into application state
const _ = require('lodash');

function mergeConfigUnsafe(baseConfig, userConfig) {
  // If userConfig is attacker-controlled, lodash merge can allow prototype pollution
  return _.merge({}, baseConfig, userConfig);
}

// Fix: validate input schema and avoid merging untrusted objects into prototypes
function mergeConfigSafe(baseConfig, userConfig) {
  // Example: deep-clone only allowed keys, refuse __proto__ / constructor / prototype
  const cleaned = {};
  ['theme', 'lang', 'notifications'].forEach((k) => {
    if (Object.prototype.hasOwnProperty.call(userConfig, k)) cleaned[k] = userConfig[k];
  });
  return Object.assign({}, baseConfig, cleaned);
}

/////////////////////////////////////////////////////////////
// 5) Unsafe file upload handling (Node + Express)
/////////////////////////////////////////////////////////////

// Vulnerable pattern: accepting uploaded filenames and saving directly
const express = require('express');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const app = express();

const upload = multer({ dest: '/tmp/uploads' });

app.post('/upload-unsafe', upload.single('file'), (req, res) => {
  // ATTACKER can set originalname to "../../etc/passwd" and cause issues when used unsafely
  const original = req.file.originalname;
  const targetPath = path.join('/var/www/uploads', original); // UNSAFE
  fs.rename(req.file.path, targetPath, (err) => {
    if (err) return res.status(500).send('fail');
    res.send('ok');
  });
});

// Fixes: sanitize filename, generate server-side random filename, validate content-type / magic bytes
const crypto = require('crypto');

app.post('/upload-safe', upload.single('file'), (req, res) => {
  const safeName = crypto.randomBytes(16).toString('hex') + path.extname(req.file.originalname);
  const targetPath = path.join('/var/www/uploads', safeName);
  // TODO: validate MIME, check magic bytes, enforce size limits
  fs.rename(req.file.path, targetPath, (err) => {
    if (err) return res.status(500).send('fail');
    res.send('ok');
  });
});

////////////////////////////////////////////////////
// 6) Weak cryptography / predictable tokens
////////////////////////////////////////////////////

// Vulnerable pattern: using predictable random or weak hash for passwords/tokens
function generateTokenUnsafe(userId) {
  // predictable: using md5 and a predictable seed
  const md5 = require('crypto').createHash('md5');
  md5.update(userId + '|' + Date.now());
  return md5.digest('hex'); // weak and predictable
}

// Fix: use crypto.randomBytes or a strong KDF for passwords (bcrypt/argon2)
function generateTokenSafe() {
  return crypto.randomBytes(32).toString('hex');
}

////////////////////////////////////////////////////
// 7) Insecure CORS configuration (Node + Express)
////////////////////////////////////////////////////

// Vulnerable pattern: reflecting Origin blindly
app.use((req, res, next) => {
  const origin = req.get('Origin');
  // UNSAFE: reflect any origin back, effectively allowing any website to make authenticated requests
  res.setHeader('Access-Control-Allow-Origin', origin || '*');
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  next();
});

// Fix: whitelist known origins and check them
const ALLOWED_ORIGINS = new Set(['https://example.com', 'https://admin.example.com']);
app.use((req, res, next) => {
  const origin = req.get('Origin');
  if (origin && ALLOWED_ORIGINS.has(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
  }
  next();
});

////////////////////////////////////////////////////
// 8) Leaky error messages / information disclosure
////////////////////////////////////////////////////

function dangerousDBOperation(req, res) {
  pool.query('SELECT * FROM secret WHERE id = 1', (err, rows) => {
    if (err) {
      // UNSAFE: returning raw error object leaks stack traces and internals
      return res.status(500).json({ error: err });
    }
    res.json(rows);
  });
}

function saferDBOperation(req, res) {
  pool.query('SELECT * FROM secret WHERE id = 1', (err, rows) => {
    if (err) {
      // safe: log server-side, return generic message to client
      console.error('DB error fetching secret:', err);
      return res.status(500).json({ error: 'internal server error' });
    }
    res.json(rows);
  });
}

////////////////////////////////////////////////////
// 9) Insecure use of JSON.parse on untrusted input (client/server)
////////////////////////////////////////////////////

function parseUserDataUnsafe(jsonString) {
  // If attacker provides specially crafted values for __proto__ etc, it could cause prototype pollution
  return JSON.parse(jsonString);
}

// Fix: validate keys and types using a schema validator like ajv
const Ajv = require('ajv');
const ajv = new Ajv();
const schema = { type: 'object', properties: { name: { type: 'string' }, age: { type: 'number' } }, additionalProperties: false };
const validate = ajv.compile(schema);

function parseUserDataSafe(jsonString) {
  const parsed = JSON.parse(jsonString);
  if (!validate(parsed)) throw new Error('invalid payload');
  return parsed;
}

////////////////////////////////////////////////////
// 10) Race condition / TOCTOU example (Node fs)
////////////////////////////////////////////////////

function unsafeCheckThenRead(filename, cb) {
  // Time-of-check to time-of-use vulnerability
  fs.access(filename, fs.constants.R_OK, (err) => {
    if (err) return cb(new Error('no access'));
    // between access and read attacker could replace the file
    fs.readFile(filename, 'utf8', cb);
  });
}

// Fix: open file with flags and operate on the returned fd where possible
function saferRead(filename, cb) {
  fs.open(filename, 'r', (err, fd) => {
    if (err) return cb(err);
    fs.fstat(fd, (err2) => {
      if (err2) { fs.close(fd, () => {}); return cb(err2); }
      const buf = Buffer.alloc(Number(err2.size));
      fs.read(fd, buf, 0, buf.length, 0, (err3) => {
        fs.close(fd, () => {});
        if (err3) return cb(err3);
        cb(null, buf.toString('utf8'));
      });
    });
  });
}

/*
  End of examples.
  -----------------
  Each snippet above is intentionally simplified to highlight a single common
  vulnerability class. For learning, pair these with tests that show exploitation
  in a safe lab, and then implement the "Safe" variants as remediation.

  If you'd like, I can:
   - produce separate "vulnerable" and "fixed" files for a hands-on lab
   - provide unit tests that demonstrate the vulnerability and the fix
   - convert selected snippets into a small runnable Node/Express app that's
     sandboxed and annotated
*/
