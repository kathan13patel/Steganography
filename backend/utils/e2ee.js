// e2ee.js - Client-side End-to-End Encryption
class E2EEClient {
    constructor() {
        this.algorithm = 'AES-GCM';
        this.keyLength = 256;
    }

    // Generate a key pair for key exchange
    async generateKeyPair() {
        try {
            const keyPair = await window.crypto.subtle.generateKey(
                {
                    name: "ECDH",
                    namedCurve: "P-256",
                },
                true,
                ["deriveKey", "deriveBits"]
            );
            
            // Export public key for sharing
            const publicKey = await window.crypto.subtle.exportKey(
                "raw",
                keyPair.publicKey
            );
            
            return {
                keyPair,
                publicKey: this.arrayBufferToBase64(publicKey)
            };
        } catch (error) {
            console.error('Key generation error:', error);
            throw error;
        }
    }

    // Derive shared secret from key exchange
    async deriveSharedSecret(privateKey, otherPartyPublicKey) {
        try {
            // Import other party's public key
            const publicKey = await window.crypto.subtle.importKey(
                "raw",
                this.base64ToArrayBuffer(otherPartyPublicKey),
                {
                    name: "ECDH",
                    namedCurve: "P-256",
                },
                true,
                []
            );

            // Derive shared secret
            const sharedSecret = await window.crypto.subtle.deriveBits(
                {
                    name: "ECDH",
                    public: publicKey,
                },
                privateKey,
                256
            );

            return sharedSecret;
        } catch (error) {
            console.error('Key derivation error:', error);
            throw error;
        }
    }

    // Derive AES key from shared secret
    async deriveAESKey(sharedSecret) {
        const importedKey = await window.crypto.subtle.importKey(
            "raw",
            sharedSecret,
            "HKDF",
            false,
            ["deriveKey"]
        );

        const aesKey = await window.crypto.subtle.deriveKey(
            {
                name: "HKDF",
                salt: new Uint8Array(0),
                info: new Uint8Array(),
                hash: "SHA-256"
            },
            importedKey,
            { name: "AES-GCM", length: 256 },
            false,
            ["encrypt", "decrypt"]
        );

        return aesKey;
    }

    // Encrypt message
    async encryptMessage(message, aesKey) {
        try {
            const iv = window.crypto.getRandomValues(new Uint8Array(12));
            const encodedMessage = new TextEncoder().encode(message);

            const ciphertext = await window.crypto.subtle.encrypt(
                {
                    name: "AES-GCM",
                    iv: iv
                },
                aesKey,
                encodedMessage
            );

            return {
                iv: this.arrayBufferToBase64(iv),
                ciphertext: this.arrayBufferToBase64(ciphertext),
                algo: 'AES-GCM-256'
            };
        } catch (error) {
            console.error('Encryption error:', error);
            throw error;
        }
    }

    // Decrypt message
    async decryptMessage(encryptedData, aesKey) {
        try {
            const { iv, ciphertext } = encryptedData;
            
            const decrypted = await window.crypto.subtle.decrypt(
                {
                    name: "AES-GCM",
                    iv: this.base64ToArrayBuffer(iv)
                },
                aesKey,
                this.base64ToArrayBuffer(ciphertext)
            );

            return new TextDecoder().decode(decrypted);
        } catch (error) {
            console.error('Decryption error:', error);
            throw error;
        }
    }

    // Utility methods
    arrayBufferToBase64(buffer) {
        const bytes = new Uint8Array(buffer);
        let binary = '';
        for (let i = 0; i < bytes.byteLength; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return window.btoa(binary);
    }

    base64ToArrayBuffer(base64) {
        const binary = window.atob(base64);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) {
            bytes[i] = binary.charCodeAt(i);
        }
        return bytes.buffer;
    }
}

// Export for use in other files
window.E2EEClient = E2EEClient;