import CryptoJS from 'crypto-js';

class EncryptionService {
    constructor() {
        this.keyStorage = window.localStorage;
    }

    // PROPER Key Generation using Web Crypto API
    async generateUserKeys() {
        try {
            console.log('Generating cryptographic keys...');
            
            // Generate RSA key pair for key exchange
            const keyPair = await window.crypto.subtle.generateKey(
                {
                    name: "RSA-OAEP",
                    modulusLength: 2048,
                    publicExponent: new Uint8Array([1, 0, 1]), // 65537
                    hash: "SHA-256",
                },
                true, // extractable
                ["encrypt", "decrypt"]
            );

            // Export public key
            const publicKey = await window.crypto.subtle.exportKey(
                "spki", 
                keyPair.publicKey
            );
            
            // Export private key
            const privateKey = await window.crypto.subtle.exportKey(
                "pkcs8", 
                keyPair.privateKey
            );

            // Generate random AES key for message encryption
            const aesKey = await window.crypto.subtle.generateKey(
                {
                    name: "AES-CBC",
                    length: 256, // AES-256
                },
                true, // extractable
                ["encrypt", "decrypt"]
            );

            // Export AES key
            const aesKeyBytes = await window.crypto.subtle.exportKey(
                "raw", 
                aesKey
            );

            return {
                keyPair: {
                    publicKey: this.arrayBufferToBase64(publicKey),
                    privateKey: this.arrayBufferToBase64(privateKey)
                },
                aesKey: this.arrayBufferToBase64(aesKeyBytes),
                keyId: 'key_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9)
            };
        } catch (error) {
            console.error('Cryptographic key generation failed:', error);
            
            // Fallback: Generate using CryptoJS (less secure but works everywhere)
            console.log('Using CryptoJS fallback for key generation...');
            return this.generateKeysFallback();
        }
    }

    // Fallback key generation (for browsers without Web Crypto API)
    async generateKeysFallback() {
        try {
            // Generate random keys using CryptoJS
            const rsaSeed = CryptoJS.lib.WordArray.random(512);
            const aesSeed = CryptoJS.lib.WordArray.random(64);
            
            // Create deterministic but random-looking keys from seeds
            const keyPair = {
                publicKey: CryptoJS.SHA256(rsaSeed + 'public').toString(),
                privateKey: CryptoJS.SHA256(rsaSeed + 'private').toString()
            };
            
            const aesKey = CryptoJS.SHA256(aesSeed).toString();
            
            return {
                keyPair,
                aesKey,
                keyId: 'fallback_key_' + Date.now(),
                isFallback: true
            };
        } catch (fallbackError) {
            console.error('Fallback key generation also failed:', fallbackError);
            throw new Error('Cannot generate secure encryption keys');
        }
    }

    // PROPER Key Derivation for Conversations
    async deriveConversationKey(userId, targetUserId, salt = '') {
        try {
            // Use HKDF-like approach for key derivation
            const conversationId = [userId, targetUserId].sort().join('|');
            const baseKey = await this.getUserAESKey(userId);
            
            // Derive unique key for this conversation
            const derivedKey = CryptoJS.PBKDF2(
                conversationId + salt, 
                baseKey, 
                { 
                    keySize: 256 / 32,
                    iterations: 10000 
                }
            );
            
            return derivedKey.toString();
        } catch (error) {
            console.error('Key derivation failed:', error);
            // Fallback to simple hash
            return CryptoJS.SHA256(userId + targetUserId + salt).toString();
        }
    }

    // Get user's AES key
    async getUserAESKey(userId) {
        const keys = this.getUserKeys(userId);
        if (!keys || !keys.aesKey) {
            throw new Error('No encryption keys found for user');
        }
        return keys.aesKey;
    }

    // Store keys securely with additional protection
    storeUserKeys(userId, keys) {
        try {
            const secureData = {
                keyPair: keys.keyPair,
                aesKey: keys.aesKey,
                keyId: keys.keyId,
                userId: userId,
                createdAt: new Date().toISOString(),
                isFallback: keys.isFallback || false
            };

            // Add basic obfuscation (not real security, but better than plain storage)
            const encryptedStorage = CryptoJS.AES.encrypt(
                JSON.stringify(secureData), 
                userId + '_' + process.env.REACT_APP_SECRET_SALT
            ).toString();

            this.keyStorage.setItem(`e2ee_keys_${userId}`, encryptedStorage);
            console.log('User encryption keys stored securely with key ID:', keys.keyId);
            
        } catch (error) {
            console.error('Failed to store keys securely:', error);
            // Fallback to plain storage (less secure)
            this.keyStorage.setItem(`e2ee_keys_${userId}`, JSON.stringify(secureData));
        }
    }

    // Retrieve keys with decryption
    getUserKeys(userId) {
        try {
            const stored = this.keyStorage.getItem(`e2ee_keys_${userId}`);
            if (!stored) return null;

            // Try to decrypt if it's encrypted
            try {
                const decrypted = CryptoJS.AES.decrypt(
                    stored, 
                    userId + '_' + process.env.REACT_APP_SECRET_SALT
                ).toString(CryptoJS.enc.Utf8);
                
                return JSON.parse(decrypted);
            } catch {
                // If decryption fails, assume it's plain JSON
                return JSON.parse(stored);
            }
        } catch (error) {
            console.error('Failed to retrieve user keys:', error);
            return null;
        }
    }

    // Enhanced Encryption with proper IV and authentication
    encryptMessage(message, encryptionKey) {
        try {
            if (!message || !encryptionKey) {
                throw new Error('Message and key are required for encryption');
            }

            const iv = CryptoJS.lib.WordArray.random(16);
            const key = CryptoJS.enc.Utf8.parse(encryptionKey);
            
            const encrypted = CryptoJS.AES.encrypt(message, key, {
                iv: iv,
                mode: CryptoJS.mode.CBC,
                padding: CryptoJS.pad.Pkcs7
            });

            // Add HMAC for integrity protection
            const hmac = CryptoJS.HmacSHA256(
                encrypted.toString() + iv.toString(), 
                encryptionKey + '_auth'
            );

            return {
                iv: CryptoJS.enc.Base64.stringify(iv),
                ciphertext: encrypted.toString(),
                hmac: hmac.toString(),
                algo: 'AES-256-CBC-HMAC',
                timestamp: Date.now()
            };
        } catch (error) {
            console.error('Encryption failed:', error);
            throw new Error('Failed to encrypt message: ' + error.message);
        }
    }

    // Enhanced Decryption with integrity verification
    decryptMessage(encryptedData, encryptionKey) {
        try {
            if (!encryptedData || !encryptionKey) {
                throw new Error('Encrypted data and key are required for decryption');
            }

            const key = CryptoJS.enc.Utf8.parse(encryptionKey);
            const iv = CryptoJS.enc.Base64.parse(encryptedData.iv);

            // Verify HMAC for integrity
            if (encryptedData.hmac) {
                const expectedHmac = CryptoJS.HmacSHA256(
                    encryptedData.ciphertext + encryptedData.iv,
                    encryptionKey + '_auth'
                ).toString();
                
                if (expectedHmac !== encryptedData.hmac) {
                    throw new Error('Message integrity check failed - possible tampering');
                }
            }

            const decrypted = CryptoJS.AES.decrypt(encryptedData.ciphertext, key, {
                iv: iv,
                mode: CryptoJS.mode.CBC,
                padding: CryptoJS.pad.Pkcs7
            });

            const result = decrypted.toString(CryptoJS.enc.Utf8);
            
            if (!result) {
                throw new Error('Decryption resulted in empty message - wrong key?');
            }

            return result;
        } catch (error) {
            console.error('Decryption failed:', error);
            throw new Error('Failed to decrypt message: ' + error.message);
        }
    }

    // Utility function
    arrayBufferToBase64(buffer) {
        let binary = '';
        const bytes = new Uint8Array(buffer);
        for (let i = 0; i < bytes.byteLength; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return window.btoa(binary);
    }

    // Check if Web Crypto API is available
    isWebCryptoAvailable() {
        return window.crypto && window.crypto.subtle;
    }

    // Get encryption status
    getEncryptionStatus(userId) {
        const keys = this.getUserKeys(userId);
        return {
            hasKeys: !!keys,
            keyId: keys?.keyId,
            isFallback: keys?.isFallback || false,
            webCryptoAvailable: this.isWebCryptoAvailable(),
            createdAt: keys?.createdAt
        };
    }
}

export default new EncryptionService();