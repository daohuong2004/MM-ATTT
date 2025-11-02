/*
File: rsa_elgamal_and_report.js
Mô tả: Triển khai mẫu hệ mật RSA-2048 (sử dụng Node.js 'crypto') và ElGamal-1024 (thuần BigInt),
đi kèm chức năng mã hóa/giải mã, ký/số xác thực và sinh 1 file báo cáo Word (template) bằng thư viện 'docx'.

Yêu cầu:
- Node.js >= 16 (tốt nhất >=18) vì dùng crypto.generatePrimeSync
- npm install docx

Cách chạy:
1) npm install docx
2) node rsa_elgamal_and_report.js
Kết quả: trên thư mục sẽ có các file khóa, bản tin ví dụ, và report_template.docx

Lưu ý: mã này là mẫu nghiên cứu/kiểm thử.

const crypto = require('crypto');
const fs = require('fs');

// ---- Phần RSA (sử dụng module crypto) ----
function generateRSA2048() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicExponent: 0x10001,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
  });
  return { publicKey, privateKey };
}

function rsaEncrypt(publicKeyPem, message) {
  const buffer = Buffer.from(message, 'utf8');
  const encrypted = crypto.publicEncrypt({ key: publicKeyPem, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' }, buffer);
  return encrypted.toString('base64');
}

function rsaDecrypt(privateKeyPem, ciphertextBase64) {
  const buffer = Buffer.from(ciphertextBase64, 'base64');
  const decrypted = crypto.privateDecrypt({ key: privateKeyPem, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' }, buffer);
  return decrypted.toString('utf8');
}

function rsaSign(privateKeyPem, message) {
  const sign = crypto.createSign('sha256');
  sign.update(message);
  sign.end();
  const signature = sign.sign(privateKeyPem);
  return signature.toString('base64');
}

function rsaVerify(publicKeyPem, message, signatureBase64) {
  const verify = crypto.createVerify('sha256');
  verify.update(message);
  verify.end();
  return verify.verify(publicKeyPem, Buffer.from(signatureBase64, 'base64'));
}

// ---- Phần ElGamal (thuần BigInt) ----
// Hàm helper: modular exponentiation (a^e mod m) với BigInt
function modPow(base, exponent, mod) {
  base = base % mod;
  let result = 1n;
  while (exponent > 0n) {
    if (exponent & 1n) result = (result * base) % mod;
    base = (base * base) % mod;
    exponent >>= 1n;
  }
  return result;
}

// Sinh số nguyên ngẫu nhiên 0..(max-1)
function randBetween(max) {
  // max is BigInt
  const bytes = Math.ceil(Number((max.toString(2).length) / 8));
  let r;
  do {
    const buf = crypto.randomBytes(bytes);
    r = BigInt('0x' + buf.toString('hex'));
  } while (r >= max);
  return r;
}

// Kiểm tra primality bằng Miller-Rabin (độ chính xác tùy số lần)
function isProbablePrime(n, k = 10) {
  if (n === 2n || n === 3n) return true;
  if (n < 2n || n % 2n === 0n) return false;
  // write n-1 as d * 2^s
  let s = 0n;
  let d = n - 1n;
  while (d % 2n === 0n) {
    d /= 2n;
    s += 1n;
  }
  witnessLoop: for (let i = 0; i < k; i++) {
    const a = randBetween(n - 3n) + 2n; // random in [2, n-2]
    let x = modPow(a, d, n);
    if (x === 1n || x === n - 1n) continue;
    for (let r = 1n; r < s; r++) {
      x = (x * x) % n;
      if (x === n - 1n) continue witnessLoop;
    }
    return false;
  }
  return true;
}

// Sinh prime p với số bits chỉ định (dùng crypto.generatePrimeSync khi có sẵn, fallback: generate bằng thử Miller-Rabin)
function generatePrimeBits(bits) {
  try {
    // Node 15+ hỗ trợ crypto.generatePrimeSync
    const p = crypto.generatePrimeSync(bits, { bigint: true });
    return p;
  } catch (e) {
    // Fallback (chậm)
    while (true) {
      const bytes = Math.ceil(bits / 8);
      const buf = crypto.randomBytes(bytes);
      // ensure top bit 1 to get required bit length
      buf[0] |= 0x80;
      // ensure odd
      buf[buf.length - 1] |= 1;
      const candidate = BigInt('0x' + buf.toString('hex'));
      if (isProbablePrime(candidate, 12)) return candidate;
    }
  }
}

function generateElGamal1024() {
  const bits = 1024;
  console.log('Generating 1024-bit prime p (this may take a while)...');
  const p = generatePrimeBits(bits);
  // choose generator g; for safe usage, one typically chooses primitive root. For simplicity, choose small g=2 and verify
  let g = 2n;
  // private key x random in [2, p-2]
  const x = randBetween(p - 3n) + 2n;
  const h = modPow(g, x, p);
  return { p, g, x, h };
}

function elgamalEncrypt(p, g, h, message) {
  // map message to bigint: we'll use UTF-8 bytes
  const mBuf = Buffer.from(message, 'utf8');
  const m = BigInt('0x' + mBuf.toString('hex'));
  if (m >= p) throw new Error('Message too long for modulus p; use shorter message or hybrid scheme.');
  const y = randBetween(p - 2n) + 1n; // ephemeral
  const c1 = modPow(g, y, p);
  const s = modPow(h, y, p); // shared secret
  const c2 = (s * m) % p;
  return { c1, c2 };
}

function elgamalDecrypt(p, x, c1, c2) {
  const s = modPow(c1, x, p);
  // compute m = c2 * s^{-1} mod p
  const sInv = modInverse(s, p);
  const m = (c2 * sInv) % p;
  // convert bigint m back to utf8
  let hex = m.toString(16);
  if (hex.length % 2) hex = '0' + hex;
  const buf = Buffer.from(hex, 'hex');
  return buf.toString('utf8');
}

// Extended Euclidean to find modular inverse
function egcd(a, b) {
  if (b === 0n) return { g: a, x: 1n, y: 0n };
  const { g, x: x1, y: y1 } = egcd(b, a % b);
  return { g, x: y1, y: x1 - (a / b) * y1 };
}

function modInverse(a, m) {
  const { g, x } = egcd(a < 0n ? a + m : a, m);
  if (g !== 1n) throw new Error('No modular inverse');
  return (x % m + m) % m;
}

// ElGamal signing (classic ElGamal signature)
function elgamalSign(p, g, x, message) {
  // message -> hash integer (use sha256)
  const h = BigInt('0x' + crypto.createHash('sha256').update(message).digest('hex'));
  const p1 = p - 1n;
  while (true) {
    const k = randBetween(p1 - 1n) + 1n; // in [1, p-2]
    if (gcd(k, p1) !== 1n) continue;
    const r = modPow(g, k, p);
    const kInv = modInverse(k, p1);
    const s = (kInv * (h - x * r)) % p1;
    if (s < 0n) s += p1;
    if (s !== 0n) return { r, s };
  }
}

function elgamalVerify(p, g, h, message, r, s) {
  if (r <= 0n || r >= p) return false;
  const hmsg = BigInt('0x' + crypto.createHash('sha256').update(message).digest('hex'));
  const v1 = (modPow(h, r, p) * modPow(r, s, p)) % p;
  const v2 = modPow(g, hmsg, p);
  return v1 === v2;
}

function gcd(a, b) {
  while (b) {
    const t = a % b;
    a = b;
    b = t;
  }
  return a;
}

// ---- Sinh báo cáo Word (template) ----
async function generateWordReport(data, outPath = 'report_template.docx') {
  try {
    const { Document, Packer, Paragraph, TextRun, HeadingLevel } = require('docx');
    const doc = new Document();

    doc.addSection({
      properties: {},
      children: [
        new Paragraph({ text: 'Báo cáo: Kiểm thử phần mềm mã hóa, giải mã và ký', heading: HeadingLevel.TITLE }),
        new Paragraph({ text: `Ngày tạo: ${new Date().toISOString()}` }),
        new Paragraph({ text: '' }),
        new Paragraph({ text: '1. Các sơ đồ hệ mật và sơ đồ chữ ký đã triển khai' , heading: HeadingLevel.HEADING_1}),
        new Paragraph({ text: data.schemes }),
        new Paragraph({ text: '2. Tham số thực tế sử dụng và bản tin (ví dụ)' , heading: HeadingLevel.HEADING_1}),
        new Paragraph({ text: data.parameters }),
        new Paragraph({ text: '3. Hướng dẫn chuyển cho đối tác để kiểm tra' , heading: HeadingLevel.HEADING_1}),
        new Paragraph({ text: data.transfer }),
        new Paragraph({ text: '4. Yêu cầu báo cáo từ mỗi đối tác (kiểm tra, giải mã, xác thực)' , heading: HeadingLevel.HEADING_1}),
        new Paragraph({ text: data.partnerReport }),
        new Paragraph({ text: '5. Đăng ký độ dài khóa nộp vào tuần 14' , heading: HeadingLevel.HEADING_1}),
        new Paragraph({ text: data.registration }),
      ]
    });

    const buffer = await Packer.toBuffer(doc);
    fs.writeFileSync(outPath, buffer);
    console.log('Report template generated:', outPath);
  } catch (e) {
    console.warn('Không thể tạo file Word: chưa cài package "docx". Hãy chạy: npm install docx');
  }
}

// ---- Main: chạy thử các chức năng và lưu file khóa/bản tin ----
async function main() {
  console.log('=== RSA-2048: sinh khóa, mã hóa/giải mã, ký/xác thực ===');
  const rsa = generateRSA2048();
  fs.writeFileSync('rsa_private.pem', rsa.privateKey);
  fs.writeFileSync('rsa_public.pem', rsa.publicKey);
  const msg = 'Hello từ RSA test message';
  const encrypted = rsaEncrypt(rsa.publicKey, msg);
  fs.writeFileSync('rsa_cipher_b64.txt', encrypted);
  const decrypted = rsaDecrypt(rsa.privateKey, encrypted);
  const signature = rsaSign(rsa.privateKey, msg);
  const okVerify = rsaVerify(rsa.publicKey, msg, signature);
  console.log('RSA decrypted === original?', decrypted === msg);
  console.log('RSA signature valid?', okVerify);

  console.log('\n=== ElGamal-1024: sinh tham số, mã hóa/giải mã, ký/xác thực ===');
  const el = generateElGamal1024();
  fs.writeFileSync('elgamal_params.json', JSON.stringify({
    p: el.p.toString(16), g: el.g.toString(16), h: el.h.toString(16), x: el.x.toString(16)
  }, null, 2));

  const emsg = 'Hello từ ElGamal test';
  const { c1, c2 } = elgamalEncrypt(el.p, el.g, el.h, emsg);
  fs.writeFileSync('elgamal_cipher.json', JSON.stringify({ c1: c1.toString(16), c2: c2.toString(16) }, null, 2));
  const decryptedEl = elgamalDecrypt(el.p, el.x, c1, c2);
  console.log('ElGamal decrypted === original?', decryptedEl === emsg);

  const esign = elgamalSign(el.p, el.g, el.x, emsg);
  const everify = elgamalVerify(el.p, el.g, el.h, emsg, esign.r, esign.s);
  console.log('ElGamal signature valid?', everify);

  // Tạo template báo cáo
  const reportData = {
    schemes: '- RSA 2048 (mã hóa: OAEP SHA-256; ký: PKCS#1 v1.5 SHA-256)\n- ElGamal 1024 (mã hóa nguyên thủy, chữ ký ElGamal)\n',
    parameters: `RSA public: rsa_public.pem (2048-bit)\nRSA private: rsa_private.pem\nElGamal params (hex): saved in elgamal_params.json\nVí dụ bản tin RSA: ${msg}\nVí dụ bản tin ElGamal: ${emsg}`,
    transfer: 'Chuyển các file rsa_public.pem, elgamal_params.json, các file cipher và chữ ký cho đối tác để họ thực hiện giải mã/xác thực.' ,
    partnerReport: 'Mỗi đối tác cần trả lời: 1) Có giải mã đúng không? 2) Signature xác thực được không? 3) Ghi rõ các bước/command đã dùng.' ,
    registration: 'Đăng ký: RSA 2048; ElGamal 1024; (ECC256 - đã nêu nhưng chưa triển khai trong mã nguồn này).' 
  };

  await generateWordReport(reportData, 'report_template.docx');

  console.log('\nFiles generated in current folder: rsa_private.pem, rsa_public.pem, rsa_cipher_b64.txt, elgamal_params.json, elgamal_cipher.json, report_template.docx (if docx package installed).');
}

// Exports để test nếu cần
module.exports = { generateRSA2048, rsaEncrypt, rsaDecrypt, rsaSign, rsaVerify, generateElGamal1024, elgamalEncrypt, elgamalDecrypt, elgamalSign, elgamalVerify, main };

if (require.main === module) main().catch(err => console.error(err));
*/