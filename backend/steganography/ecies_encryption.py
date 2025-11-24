from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os

class ECIESEncryption:
    def __init__(self):
        self.curve = ec.SECP256R1()
        self.backend = default_backend()
    
    def generate_key_pair(self):
        private_key = ec.generate_private_key(self.curve, self.backend)
        public_key = private_key.public_key()
        return private_key, public_key
    
    def encrypt(self, public_key, plaintext):
        # Generate ephemeral key pair
        ephemeral_private = ec.generate_private_key(self.curve, self.backend)
        ephemeral_public = ephemeral_private.public_key()
        
        # Perform ECDH
        shared_secret = ephemeral_private.exchange(ec.ECDH(), public_key)
        
        # Derive encryption key
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'ecies_encryption',
            backend=self.backend
        ).derive(shared_secret)
        
        # Encrypt with AES
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(derived_key), modes.GCM(iv), backend=self.backend)
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()
        
        # Return ephemeral public key, IV, ciphertext, and tag
        return {
            'ephemeral_public': ephemeral_public.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ),
            'iv': iv,
            'ciphertext': ciphertext,
            'tag': encryptor.tag
        }
    
    def decrypt(self, private_key, encrypted_data):
        # Load ephemeral public key
        ephemeral_public = serialization.load_pem_public_key(
            encrypted_data['ephemeral_public'],
            backend=self.backend
        )
        
        # Perform ECDH
        shared_secret = private_key.exchange(ec.ECDH(), ephemeral_public)
        
        # Derive decryption key
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'ecies_encryption',
            backend=self.backend
        ).derive(shared_secret)
        
        # Decrypt with AES
        cipher = Cipher(
            algorithms.AES(derived_key),
            modes.GCM(encrypted_data['iv'], encrypted_data['tag']),
            backend=self.backend
        )
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(encrypted_data['ciphertext']) + decryptor.finalize()
        
        return plaintext.decode()