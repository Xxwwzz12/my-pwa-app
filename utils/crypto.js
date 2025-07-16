import crypto from 'crypto';

/**
 * Validate encryption/decryption key
 * @param {string|Buffer} key - Encryption key (32-byte Buffer or 64-char hex string)
 * @throws {Error} If key is invalid
 */
const validateKey = (key) => {
  if (Buffer.isBuffer(key)) {
    if (key.length !== 32) {
      throw new Error('Key must be 32 bytes for AES-256');
    }
    return;
  }
  
  if (typeof key === 'string') {
    if (!/^[0-9a-f]{64}$/i.test(key)) {
      throw new Error('Key must be a 64-character hex string (32 bytes)');
    }
    return;
  }
  
  throw new Error('Key must be a Buffer or hex string');
};

/**
 * Encrypt text using AES-256-GCM
 * @param {string} text - Text to encrypt
 * @param {string|Buffer} key - Encryption key (hex string or Buffer)
 * @returns {string} Encrypted data in format: iv:encryptedData:tag
 */
export function encrypt(text, key) {
  // Validate key format
  validateKey(key);
  
  // Convert key to Buffer if needed
  const keyBuf = Buffer.isBuffer(key) ? key : Buffer.from(key, 'hex');
  
  // Generate initialization vector
  const iv = crypto.randomBytes(16);
  
  // Create cipher
  const cipher = crypto.createCipheriv('aes-256-gcm', keyBuf, iv);
  
  // Encrypt text
  const encrypted = Buffer.concat([
    cipher.update(text, 'utf8'),
    cipher.final()
  ]);
  
  // Get authentication tag
  const tag = cipher.getAuthTag();
  
  // Return as colon-separated hex strings
  return `${iv.toString('hex')}:${encrypted.toString('hex')}:${tag.toString('hex')}`;
}

/**
 * Decrypt text using AES-256-GCM
 * @param {string} encryptedText - Encrypted text in format: iv:encryptedData:tag
 * @param {string|Buffer} key - Decryption key (hex string or Buffer)
 * @returns {string} Decrypted plain text
 */
export function decrypt(encryptedText, key) {
  // Validate key format
  validateKey(key);
  
  // Convert key to Buffer if needed
  const keyBuf = Buffer.isBuffer(key) ? key : Buffer.from(key, 'hex');
  
  // Split encrypted text into components
  const parts = encryptedText.split(':');
  
  // Validate format
  if (parts.length !== 3) {
    throw new Error(
      'Invalid encrypted text format. Expected "iv:data:tag" but got ' +
      `${parts.length} parts. Input: ${encryptedText.slice(0, 50)}...`
    );
  }
  
  // Parse components
  const iv = Buffer.from(parts[0], 'hex');
  const encryptedData = Buffer.from(parts[1], 'hex');
  const tag = Buffer.from(parts[2], 'hex');
  
  // Create decipher
  const decipher = crypto.createDecipheriv('aes-256-gcm', keyBuf, iv);
  
  // Set authentication tag
  decipher.setAuthTag(tag);
  
  // Decrypt and return as UTF-8 string
  return Buffer.concat([
    decipher.update(encryptedData),
    decipher.final()
  ]).toString('utf8');
}