const express = require('express');
const crypto = require('crypto');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const AES_KEY = crypto.createHash('sha256').update('Assignment2-WebEncryption-Key').digest();

// Educational RSA key pair generated when the server starts.
const { publicKey: RSA_PUBLIC_KEY, privateKey: RSA_PRIVATE_KEY } = crypto.generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
});

app.use(express.json({ limit: '1mb' }));
app.use(express.static(path.join(__dirname, 'public')));

function caesar(text, shift) {
  shift = ((Number(shift) || 0) % 26 + 26) % 26;
  return [...text].map(ch => {
    if (ch >= 'A' && ch <= 'Z') return String.fromCharCode((ch.charCodeAt(0) - 65 + shift) % 26 + 65);
    if (ch >= 'a' && ch <= 'z') return String.fromCharCode((ch.charCodeAt(0) - 97 + shift) % 26 + 97);
    return ch;
  }).join('');
}

function vigenere(text, key, decrypt = false) {
  const cleanKey = String(key || '').replace(/[^a-z]/gi, '').toUpperCase();
  if (!cleanKey) throw new Error('Vigenere requires a letter key.');
  let i = 0;
  return [...text].map(ch => {
    if (!/[a-z]/i.test(ch)) return ch;
    const base = ch === ch.toUpperCase() ? 65 : 97;
    const k = cleanKey.charCodeAt(i++ % cleanKey.length) - 65;
    const shift = decrypt ? -k : k;
    return String.fromCharCode((ch.charCodeAt(0) - base + shift + 26) % 26 + base);
  }).join('');
}

function xorCipher(text, key) {
  const cleanKey = String(key || '');
  if (!cleanKey) throw new Error('XOR requires a key.');
  const input = Buffer.from(text, 'utf8');
  const keyBytes = Buffer.from(cleanKey, 'utf8');
  const result = Buffer.alloc(input.length);
  for (let i = 0; i < input.length; i++) result[i] = input[i] ^ keyBytes[i % keyBytes.length];
  return result.toString('base64');
}

function xorDecrypt(payload, key) {
  const cleanKey = String(key || '');
  if (!cleanKey) throw new Error('XOR requires a key.');
  const input = Buffer.from(payload, 'base64');
  const keyBytes = Buffer.from(cleanKey, 'utf8');
  const result = Buffer.alloc(input.length);
  for (let i = 0; i < input.length; i++) result[i] = input[i] ^ keyBytes[i % keyBytes.length];
  return result.toString('utf8');
}

function railFenceEncrypt(text, rails) {
  rails = Number(rails);
  if (!Number.isInteger(rails) || rails < 2) throw new Error('Rail Fence requires at least 2 rails.');
  if (rails >= text.length) return text;
  const rows = Array.from({ length: rails }, () => []);
  let row = 0, direction = 1;
  for (const ch of text) {
    rows[row].push(ch);
    if (row === 0) direction = 1;
    else if (row === rails - 1) direction = -1;
    row += direction;
  }
  return rows.flat().join('');
}

function railFenceDecrypt(cipher, rails) {
  rails = Number(rails);
  if (!Number.isInteger(rails) || rails < 2) throw new Error('Rail Fence requires at least 2 rails.');
  if (rails >= cipher.length) return cipher;
  const pattern = [];
  let row = 0, direction = 1;
  for (let i = 0; i < cipher.length; i++) {
    pattern.push(row);
    if (row === 0) direction = 1;
    else if (row === rails - 1) direction = -1;
    row += direction;
  }
  const counts = Array(rails).fill(0);
  pattern.forEach(r => counts[r]++);
  const rows = [];
  let index = 0;
  for (const count of counts) rows.push(cipher.slice(index, index += count).split(''));
  return pattern.map(r => rows[r].shift()).join('');
}

function aesEncrypt(text) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', AES_KEY, iv);
  const encrypted = Buffer.concat([cipher.update(text, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, tag, encrypted]).toString('base64');
}

function aesDecrypt(payload) {
  const data = Buffer.from(payload, 'base64');
  if (data.length < 28) throw new Error('Invalid AES ciphertext.');
  const iv = data.subarray(0, 12);
  const tag = data.subarray(12, 28);
  const encrypted = data.subarray(28);
  const decipher = crypto.createDecipheriv('aes-256-gcm', AES_KEY, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(encrypted), decipher.final()]).toString('utf8');
}

function rsaEncrypt(text) {
  const maxBytes = 190; // RSA-2048 OAEP with SHA-256
  if (Buffer.byteLength(text, 'utf8') > maxBytes) throw new Error('RSA demo accepts up to 190 UTF-8 bytes per message.');
  return crypto.publicEncrypt({ key: RSA_PUBLIC_KEY, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' }, Buffer.from(text, 'utf8')).toString('base64');
}

function rsaDecrypt(payload) {
  return crypto.privateDecrypt({ key: RSA_PRIVATE_KEY, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' }, Buffer.from(payload, 'base64')).toString('utf8');
}

function base64Encode(text) { return Buffer.from(text, 'utf8').toString('base64'); }
function base64Decode(text) { return Buffer.from(text, 'base64').toString('utf8'); }

app.post('/api/encrypt', (req, res) => {
  try {
    const { text, algorithm, shift, key, rails } = req.body;
    if (!text || !text.trim()) return res.status(400).json({ error: 'Please enter text.' });
    if (!algorithm) return res.status(400).json({ error: 'Please select an encryption method.' });
    let ciphertext;
    if (algorithm === 'caesar') ciphertext = caesar(text, shift);
    else if (algorithm === 'vigenere') ciphertext = vigenere(text, key);
    else if (algorithm === 'aes') ciphertext = aesEncrypt(text);
    else if (algorithm === 'rsa') ciphertext = rsaEncrypt(text);
    else if (algorithm === 'xor') ciphertext = xorCipher(text, key);
    else if (algorithm === 'railfence') ciphertext = railFenceEncrypt(text, rails);
    else if (algorithm === 'base64') ciphertext = base64Encode(text);
    else return res.status(400).json({ error: 'Unsupported algorithm.' });
    res.json({ ciphertext });
  } catch (err) { res.status(400).json({ error: err.message }); }
});

app.post('/api/decrypt', (req, res) => {
  try {
    const { text, algorithm, shift, key, rails } = req.body;
    if (!text || !text.trim()) return res.status(400).json({ error: 'Please enter ciphertext.' });
    if (!algorithm) return res.status(400).json({ error: 'Please select a method.' });
    let plaintext;
    if (algorithm === 'caesar') plaintext = caesar(text, -(Number(shift) || 0));
    else if (algorithm === 'vigenere') plaintext = vigenere(text, key, true);
    else if (algorithm === 'aes') plaintext = aesDecrypt(text);
    else if (algorithm === 'rsa') plaintext = rsaDecrypt(text);
    else if (algorithm === 'xor') plaintext = xorDecrypt(text, key);
    else if (algorithm === 'railfence') plaintext = railFenceDecrypt(text, rails);
    else if (algorithm === 'base64') plaintext = base64Decode(text);
    else return res.status(400).json({ error: 'Unsupported algorithm.' });
    res.json({ plaintext });
  } catch (err) { res.status(400).json({ error: 'Decryption failed. Check the ciphertext and settings.' }); }
});

app.post('/api/hash', (req, res) => {
  const { text, hashAlgorithm = 'sha256' } = req.body;
  if (!text || !text.trim()) return res.status(400).json({ error: 'Please enter text.' });
  const supported = ['sha256', 'sha512', 'md5'];
  if (!supported.includes(hashAlgorithm)) return res.status(400).json({ error: 'Unsupported hash algorithm.' });
  res.json({ hash: crypto.createHash(hashAlgorithm).update(text, 'utf8').digest('hex') });
});

app.listen(PORT, () => console.log(`Web Encryption Tool running at http://localhost:${PORT}`));
