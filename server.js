const express = require('express');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const bodyParser = require('body-parser');
const path = require('path');
const fs = require('fs');

const publicKey = fs.readFileSync('public.pem', 'utf8');
const privateKey = fs.readFileSync('private.pem', 'utf8');


const app = express();
const PORT = 3000;
const SECRET_KEY = 'your_secret_key_here'; // Keep this safe
const AES_KEY = Buffer.from('1234567890123456'); // 16-byte key
const AES_IV = Buffer.from('6543210987654321'); // 16-byte IV


app.use(bodyParser.urlencoded({ extended: false }));
app.use(express.static('views'));

function hybridEncryptJWT(jwtPayload) {
  // 1. Generate random AES key and IV
  const aesKey = crypto.randomBytes(16); // 128-bit key
  const iv = crypto.randomBytes(16);     // 128-bit IV

  // 2. AES Encrypt the JWT
  const cipher = crypto.createCipheriv('aes-128-cbc', aesKey, iv);
  let encryptedJWT = cipher.update(jwtPayload, 'utf8', 'hex');
  encryptedJWT += cipher.final('hex');

  // 3. RSA Encrypt the AES key
  const encryptedKey = crypto.publicEncrypt(publicKey, aesKey).toString('hex');

  // 4. Return all in a JSON object (as string)
  return JSON.stringify({
    encryptedKey,
    iv: iv.toString('hex'),
    encryptedJWT
  });
}


function hybridDecryptJWT(encryptedDataStr) {
  const { encryptedKey, iv, encryptedJWT } = JSON.parse(encryptedDataStr);

  // 1. Decrypt AES key using RSA private key
  const aesKey = crypto.privateDecrypt(
    privateKey,
    Buffer.from(encryptedKey, 'hex')
  );

  // 2. Decrypt the JWT using AES key and IV
  const decipher = crypto.createDecipheriv(
    'aes-128-cbc',
    aesKey,
    Buffer.from(iv, 'hex')
  );

  let decryptedJWT = decipher.update(encryptedJWT, 'hex', 'utf8');
  decryptedJWT += decipher.final('utf8');
  return decryptedJWT;
}




// Route: Login form
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'login.html'));
});

// Route: Process login
app.post('/login', (req, res) => {
  const { username } = req.body;
  if (!username) return res.send('Username is required');

  const token = jwt.sign({ username }, SECRET_KEY, { expiresIn: '1h' });
  const hybridEncrypted = hybridEncryptJWT(token);

  res.send(`
    <h2>Login Successful!</h2>
    <p>Your Hybrid Encrypted Token:</p>
    <textarea rows="10" cols="80">${hybridEncrypted}</textarea>
    <br/><br/>
    <a href="/token.html">Go to token authorization page</a>
  `);
});



// Route: Validate token
app.post('/verify-token', (req, res) => {
  const { token } = req.body;

  try {
    const decryptedJWT = hybridDecryptJWT(token);
    const decoded = jwt.verify(decryptedJWT, SECRET_KEY);
    res.sendFile(path.join(__dirname, 'views', 'authorized.html'));
  } catch (err) {
    res.send('<h3>Invalid or expired token</h3><a href="/token.html">Try again</a>');
  }
});



app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});
