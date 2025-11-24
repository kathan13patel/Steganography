// Client-side key management
class KeyManager {
    constructor() {
        this.e2ee = new E2EEClient();
        this.conversationKeys = new Map(); // conversationId -> aesKey
        this.keyPair = null;
    }

    async initialize() {
        // Generate key pair if not exists
        if (!this.keyPair) {
            this.keyPair = await this.e2ee.generateKeyPair();
            
            // Send public key to server
            await this.registerPublicKey();
        }
    }

    async registerPublicKey() {
        try {
            const response = await fetch('/api/keys/register', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${localStorage.getItem('token')}`
                },
                body: JSON.stringify({
                    public_key: this.keyPair.publicKey
                })
            });
            
            if (!response.ok) {
                throw new Error('Failed to register public key');
            }
            
            console.log('Public key registered with server');
        } catch (error) {
            console.error('Error registering public key:', error);
        }
    }

    async getPublicKey(userId) {
        try {
            const response = await fetch(`/api/keys/${userId}`, {
                headers: {
                    'Authorization': `Bearer ${localStorage.getItem('token')}`
                }
            });
            
            if (response.ok) {
                const data = await response.json();
                return data.public_key;
            }
            return null;
        } catch (error) {
            console.error('Error fetching public key:', error);
            return null;
        }
    }

    async establishSecureChannel(otherUserId) {
        try {
            // Get other user's public key
            const otherPublicKey = await this.getPublicKey(otherUserId);
            if (!otherPublicKey) {
                throw new Error('Could not get public key for user');
            }

            // Derive shared secret
            const sharedSecret = await this.e2ee.deriveSharedSecret(
                this.keyPair.keyPair.privateKey,
                otherPublicKey
            );

            // Derive AES key
            const aesKey = await this.e2ee.deriveAESKey(sharedSecret);
            
            // Store for this conversation
            this.conversationKeys.set(otherUserId, aesKey);
            
            return aesKey;
        } catch (error) {
            console.error('Error establishing secure channel:', error);
            throw error;
        }
    }

    async encryptMessage(message, otherUserId) {
        try {
            let aesKey = this.conversationKeys.get(otherUserId);
            
            // Establish secure channel if not exists
            if (!aesKey) {
                aesKey = await this.establishSecureChannel(otherUserId);
            }

            // Encrypt the message
            const encrypted = await this.e2ee.encryptMessage(message, aesKey);
            
            return encrypted;
        } catch (error) {
            console.error('Error encrypting message:', error);
            throw error;
        }
    }

    async decryptMessage(encryptedData, otherUserId) {
        try {
            const aesKey = this.conversationKeys.get(otherUserId);
            if (!aesKey) {
                throw new Error('No encryption key found for this conversation');
            }

            const decrypted = await this.e2ee.decryptMessage(encryptedData, aesKey);
            return decrypted;
        } catch (error) {
            console.error('Error decrypting message:', error);
            throw error;
        }
    }
}

window.KeyManager = KeyManager;