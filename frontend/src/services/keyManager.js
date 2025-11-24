import E2EEClient from '../utils/e2ee.js';

class KeyManager {
    constructor() {
        this.e2ee = new E2EEClient();
        this.conversationKeys = new Map(); // conversationId -> aesKey
        this.keyPair = null;
        this.publicKey = null;
        this.isInitialized = false;
    }

    async initialize() {
        try {
            console.log('Initializing KeyManager...');
            
            // Generate key pair if not exists
            if (!this.keyPair) {
                console.log('Generating new key pair...');
                const keyData = await this.e2ee.generateKeyPair();
                this.keyPair = keyData.keyPair;
                this.publicKey = keyData.publicKey;
                console.log('Key pair generated successfully');
            }
            
            this.isInitialized = true;
            console.log('KeyManager initialized successfully');
            return true;
            
        } catch (error) {
            console.error('KeyManager initialization failed:', error);
            this.isInitialized = false;
            throw error;
        }
    }

    async registerPublicKey() {
        try {
            if (!this.publicKey) {
                throw new Error('No public key available');
            }

            // In a real app, you'd send this to your server
            console.log('Public key ready for registration:', {
                publicKey: this.publicKey.substring(0, 50) + '...',
                length: this.publicKey.length
            });
            
            return {
                success: true,
                publicKey: this.publicKey
            };
            
        } catch (error) {
            console.error('Public key registration failed:', error);
            throw error;
        }
    }

    async getPublicKey(userId) {
        try {
            console.log(`Getting public key for user: ${userId}`);
            
            // In a real implementation, this would fetch from your server
            // For now, we'll simulate this by returning null
            // You would typically make an API call here:
            // const response = await fetch(`/api/keys/${userId}`);
            // return response.public_key;
            
            console.log('Public key fetching not implemented - using fallback');
            return null;
            
        } catch (error) {
            console.error('Get public key error:', error);
            return null;
        }
    }

    async establishSecureChannel(otherUserId) {
        try {
            console.log(`Establishing secure channel with: ${otherUserId}`);
            
            // Get other user's public key
            const otherPublicKey = await this.getPublicKey(otherUserId);
            
            if (!otherPublicKey) {
                console.warn('No public key found for user, using simplified key derivation');
                // Fallback: use a simplified key derivation for demo purposes
                const fallbackKey = await this._createFallbackKey(otherUserId);
                this.conversationKeys.set(otherUserId, fallbackKey);
                return fallbackKey;
            }

            // Derive shared secret using ECDH
            console.log('Deriving shared secret...');
            const sharedSecret = await this.e2ee.deriveSharedSecret(
                this.keyPair.privateKey,
                otherPublicKey
            );

            // Derive AES key from shared secret
            console.log('Deriving AES key...');
            const aesKey = await this.e2ee.deriveAESKey(sharedSecret);
            
            // Store for this conversation
            this.conversationKeys.set(otherUserId, aesKey);
            
            console.log('Secure channel established successfully');
            return aesKey;
            
        } catch (error) {
            console.error('Secure channel establishment failed:', error);
            
            // Fallback to simplified key derivation
            console.log('Using fallback key derivation...');
            const fallbackKey = await this._createFallbackKey(otherUserId);
            this.conversationKeys.set(otherUserId, fallbackKey);
            return fallbackKey;
        }
    }

    async _createFallbackKey(otherUserId) {
        try {
            // Simplified key derivation for when proper ECDH fails
            // This is NOT cryptographically secure - for demo purposes only
            const conversationId = `${otherUserId}-conversation`;
            const encoder = new TextEncoder();
            const keyMaterial = encoder.encode(conversationId);
            
            const key = await window.crypto.subtle.importKey(
                'raw',
                keyMaterial,
                { name: 'AES-GCM' },
                false,
                ['encrypt', 'decrypt']
            );
            
            console.log('Using fallback key derivation');
            return key;
            
        } catch (error) {
            console.error('Fallback key creation failed:', error);
            throw error;
        }
    }

    async encryptMessage(message, otherUserId) {
        try {
            console.log(`Encrypting message for: ${otherUserId}`);
            
            let aesKey = this.conversationKeys.get(otherUserId);
            
            // Establish secure channel if not exists
            if (!aesKey) {
                console.log('No existing secure channel, establishing...');
                aesKey = await this.establishSecureChannel(otherUserId);
            }

            // Encrypt the message
            const encrypted = await this.e2ee.encryptMessage(message, aesKey);
            
            console.log('Message encrypted successfully');
            return encrypted;
            
        } catch (error) {
            console.error('Message encryption failed:', error);
            throw error;
        }
    }

    async decryptMessage(encryptedData, otherUserId) {
        try {
            console.log(`Decrypting message from: ${otherUserId}`);
            
            const aesKey = this.conversationKeys.get(otherUserId);
            if (!aesKey) {
                throw new Error('No encryption key found for this conversation');
            }

            const decrypted = await this.e2ee.decryptMessage(encryptedData, aesKey);
            
            console.log('Message decrypted successfully');
            return decrypted;
            
        } catch (error) {
            console.error('Message decryption failed:', error);
            throw error;
        }
    }

    // Utility methods
    getMyPublicKey() {
        return this.publicKey;
    }

    isReady() {
        return this.isInitialized && this.keyPair !== null;
    }

    // Clear conversation keys (useful for logout)
    clearKeys() {
        this.conversationKeys.clear();
        this.isInitialized = false;
        console.log('All conversation keys cleared');
    }

    // Get conversation participants
    getActiveConversations() {
        return Array.from(this.conversationKeys.keys());
    }
}

export default KeyManager;