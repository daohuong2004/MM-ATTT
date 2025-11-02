// ecc_256_ecies_ecdsa.js
// Node.js code: ECC P-256 (prime256v1) - Keygen, ECDSA sign/verify, ECIES encrypt/decrypt (ECDH + HKDF + AES-256-GCM)
// Usage: node ecc_256_ecies_ecdsa.js

const crypto = require('crypto');

// PARAMETERS (document these in report)
const CURVE_NAME = 'prime256v1'; // P-256, 256-bit curve
const AES_ALGO = 'aes-256-gcm';
const HKDF_HASH = 'sha256';
const HKDF_INFO = Buffer.from('ECIES with P-256 + HKDF-SHA256');
const AES_KEY_LEN = 32; // 256 bits
const GCM_IV_LEN = 12; // recommended 96-bit IV for GCM
const GCM_TAG_LEN = 16; // 128-bit tag

// Utility hex helpers
const toHex = (buf) => Buffer.isBuffer(buf) ? buf.toString('hex') : Buffer.from(buf).toString('hex');
const fromHex = (hex) => Buffer.from(hex, 'hex');

// Simple HKDF implementation: extract & expand (RFC 5869)
function hkdfExtract(salt, ikm, hash = HKDF_HASH) {
  if (!salt || salt.length === 0) salt = Buffer.alloc(crypto.createHash(hash).digest().length, 0);
  return crypto.createHmac(hash, salt).update(ikm).digest();
}

function hkdfExpand(prk, info, length, hash = HKDF_HASH) {
  const hashLen = crypto.createHash(hash).digest().length;
  const n = Math.ceil(length / hashLen);
  let t = Buffer.alloc(0);
  let okm = Buffer.alloc(0);
  for (let i = 0; i < n; i++) {
    const hmac = crypto.createHmac(hash, prk);
    hmac.update(Buffer.concat([t, info, Buffer.from([i + 1])]));
    t = hmac.digest();
    okm = Buffer.concat([okm, t]);
  }
  return okm.slice(0, length);
}

function hkdf(ikm, salt, info, length, hash = HKDF_HASH) {
  const prk = hkdfExtract(salt, ikm, hash);
  return hkdfExpand(prk, info, length, hash);
}

// Generate EC key pair (PEM)
function generateKeyPair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', {
    namedCurve: CURVE_NAME,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
  });
  return { publicKey, privateKey };
}

// Convert PEM public key to raw uncompressed point (hex) for ECDH use
// We'll create ECDH objects directly for ephemeral exchanges; for persistent keys we can import the key and get raw pubkey.
// Helper: export public key (PEM) to uncompressed public key bytes (04||X||Y)
function pemToUncompressedPubkeyHex(pemPublicKey) {
  // Create a KeyObject and export as 'raw' 'spki' does not give raw; Instead use createPublicKey(...).export({type:'spki',format:'der'}) and parse ASN.1 to extract EC point.
  // Node supports exporting 'spki'->'der' and then we can locate the publicKey bitstring at the end. For P-256 common layout, the last bytes are the uncompressed point.
  const keyObj = crypto.createPublicKey(pemPublicKey);
  const der = keyObj.export({ type: 'spki', format: 'der' }); // Buffer
  // The SPKI DER layout for EC usually ends with the public key BIT STRING which contains 0x04||X||Y
  // We'll try to find 0x04 followed by 64 bytes near the end:
  for (let i = der.length - 1 - 65; i >= 0; i--) {
    if (der[i] === 0x03 && der[i+1] === 0x42 && der[i+2] === 0x00 && der[i+3] === 0x04) {
      // bitstring length 0x42(66), then 0x00, then 0x04 start of uncompressed
      const start = i + 3;
      return der.slice(start, start + 65).toString('hex');
    }
  }
  // Fallback: try find 0x04 and 65 bytes after
  for (let i = der.length - 65; i >= 0; i--) {
    if (der[i] === 0x04) {
      return der.slice(i, i + 65).toString('hex');
    }
  }
  throw new Error('Unable to extract uncompressed public key from PEM (unexpected DER layout).');
}

// ECDSA sign (privateKey PEM), message Buffer -> signature (DER) hex
function signMessage(privateKeyPem, msgBuf) {
  const sign = crypto.createSign('SHA256');
  sign.update(msgBuf);
  sign.end();
  const sig = sign.sign(privateKeyPem); // DER encoded signature
  return sig.toString('hex');
}

// ECDSA verify (publicKey PEM), message Buffer, signature hex -> boolean
function verifySignature(publicKeyPem, msgBuf, sigHex) {
  const verify = crypto.createVerify('SHA256');
  verify.update(msgBuf);
  verify.end();
  return verify.verify(publicKeyPem, fromHex(sigHex));
}

// ECIES encrypt (recipientPublicKeyPem, plaintext Buffer) -> object containing ephemeralPubHex, ivHex, ciphertextHex, tagHex, hkdfSaltHex
function eciesEncrypt(recipientPublicKeyPem, plaintextBuf) {
  // 1) generate ephemeral EC keypair (ECDH)
  const ecdh = crypto.createECDH(CURVE_NAME);
  ecdh.generateKeys();
  const ephemeralPub = ecdh.getPublicKey(); // Buffer (uncompressed)
  // 2) recipient public key raw (uncompressed) -> import into ECDH computeSecret expects Buffer of public key in same format
  const recipientUncompressedHex = pemToUncompressedPubkeyHex(recipientPublicKeyPem);
  const recipientPubBuf = fromHex(recipientUncompressedHex);

  // 3) derive shared secret
  const sharedSecret = ecdh.computeSecret(recipientPubBuf);

  // 4) derive symmetric key via HKDF (use random salt)
  const salt = crypto.randomBytes(32);
  const key = hkdf(sharedSecret, salt, HKDF_INFO, AES_KEY_LEN);

  // 5) encrypt with AES-256-GCM
  const iv = crypto.randomBytes(GCM_IV_LEN);
  const cipher = crypto.createCipheriv(AES_ALGO, key, iv, { authTagLength: GCM_TAG_LEN });
  const ciphertext = Buffer.concat([cipher.update(plaintextBuf), cipher.final()]);
  const tag = cipher.getAuthTag();

  return {
    ephemeralPubHex: toHex(ephemeralPub), // sender ephemeral public key (uncompressed)
    ivHex: toHex(iv),
    ciphertextHex: toHex(ciphertext),
    tagHex: toHex(tag),
    hkdfSaltHex: toHex(salt)
  };
}

// ECIES decrypt (recipientPrivateKeyPem, envelope) -> plaintext Buffer
function eciesDecrypt(recipientPrivateKeyPem, envelope) {
  // recipientPrivateKeyPem -> create ECDH object and set private key
  const recipientKeyObj = crypto.createPrivateKey(recipientPrivateKeyPem);
  // Extract raw private key? Simpler: import into ECDH via setPrivateKey requires raw private scalar.
  // But Node supports createECDH and setPrivateKey with private key in 'der'/'pem'? Not directly.
  // Alternative: use ephemeral ECDH computeSecret by creating ECDH and setting private key from DER.
  // We'll export recipient private as 'pkcs8' DER and then locate private key scalar - but that parsing is complex.
  // Simpler approach: create ephemeral ECDH using createECDH and call setPrivateKey with private key scalar extracted by using createPrivateKey().export({format:'der',type:'pkcs8'})
  const privDer = recipientKeyObj.export({ format: 'der', type: 'pkcs8' }); // Buffer
  // For P-256, private scalar is at the end with OCTET STRING. We'll try to find a sequence of 32 bytes near end.
  // Heuristic: find last occurrence of 0x04 followed by 32 bytes (private key octet string)
  let privScalar = null;
  for (let i = privDer.length - 34; i >= 0; i--) {
    if (privDer[i] === 0x04 && privDer[i+1] === 0x20) { // 0x04 OCTET STRING, 0x20 length 32
      privScalar = privDer.slice(i+2, i+2+32);
      break;
    }
  }
  if (!privScalar) throw new Error('Unable to extract private scalar from PKCS8 DER (unexpected layout).');

  const ecdh = crypto.createECDH(CURVE_NAME);
  ecdh.setPrivateKey(privScalar);

  const ephemeralPub = fromHex(envelope.ephemeralPubHex);
  const sharedSecret = ecdh.computeSecret(ephemeralPub);

  // derive key
  const salt = fromHex(envelope.hkdfSaltHex);
  const key = hkdf(sharedSecret, salt, HKDF_INFO, AES_KEY_LEN);

  // decrypt
  const iv = fromHex(envelope.ivHex);
  const tag = fromHex(envelope.tagHex);
  const ciphertext = fromHex(envelope.ciphertextHex);
  const decipher = crypto.createDecipheriv(AES_ALGO, key, iv, { authTagLength: GCM_TAG_LEN });
  decipher.setAuthTag(tag);
  const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  return plaintext;
}

// DEMO main
function main() {
  console.log('--- ECC P-256 Demo (Keygen, ECDSA, ECIES) ---\n');

  // Generate key pairs for "Alice" (sender) and "Bob" (recipient)
  const alice = generateKeyPair();
  const bob = generateKeyPair();

  console.log('Curve:', CURVE_NAME);
  console.log('--- Public keys (PEM) ---');
  console.log('Alice Public (PEM):\n', alice.publicKey);
  console.log('Bob Public (PEM):\n', bob.publicKey);

  // Message to sign & encrypt
  const message = Buffer.from('Đây là bản tin thử nghiệm: ECIES + ECDSA với P-256', 'utf8');

  // 1) ECDSA sign (Alice signs)
  const signatureHex = signMessage(alice.privateKey, message);
  console.log('\nSignature (DER hex) by Alice:', signatureHex);

  // 2) Verify signature (using Alice public)
  const ok = verifySignature(alice.publicKey, message, signatureHex);
  console.log('Signature valid?', ok);

  // 3) ECIES encrypt message to Bob (sender uses Bob's public key)
  const envelope = eciesEncrypt(bob.publicKey, message);
  console.log('\n--- ECIES Envelope (to send to Bob) ---');
  console.log('ephemeralPubHex:', envelope.ephemeralPubHex);
  console.log('hkdfSaltHex   :', envelope.hkdfSaltHex);
  console.log('ivHex         :', envelope.ivHex);
  console.log('ciphertextHex :', envelope.ciphertextHex);
  console.log('tagHex        :', envelope.tagHex);

  // 4) Bob decrypts
  const decrypted = eciesDecrypt(bob.privateKey, envelope);
  console.log('\nBob decrypted message:', decrypted.toString('utf8'));

  // 5) Example: what to include in report
  console.log('\n--- What to put in report (example fields) ---');
  console.log('Curve used: prime256v1 (P-256) - 256-bit keys');
  console.log('Symmetric cipher: AES-256-GCM, IV length =', GCM_IV_LEN, 'bytes, TAG =', GCM_TAG_LEN, 'bytes');
  console.log('KDF: HKDF-SHA256 (info = "' + HKDF_INFO.toString() + '"), salt (hex) above');
  console.log('Signed message (utf8):', message.toString('utf8'));
  console.log('Signature (DER hex):', signatureHex);
  console.log('Encrypted envelope fields (hex): ephemeralPub || hkdfSalt || iv || ciphertext || tag (see above)');
}

if (require.main === module) {
  try {
    main();
  } catch (err) {
    console.error('Error in demo:', err);
  }
}

// Export functions for unit tests if needed
module.exports = {
  generateKeyPair,
  signMessage,
  verifySignature,
  eciesEncrypt,
  eciesDecrypt,
  pemToUncompressedPubkeyHex
};
