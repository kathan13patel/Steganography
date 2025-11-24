# config.py
import os
from pathlib import Path

class Config:
    # Base directory
    BASE_DIR = Path(__file__).resolve().parent
    
    # JWT Secret Key - generate if not exists
    JWT_SECRET_KEY = None
    
    # Try to load from environment first
    JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY')
    
    # If not in environment, try to load from secret file
    if not JWT_SECRET_KEY:
        secret_file = BASE_DIR / '.jwt_secret'
        if secret_file.exists():
            with open(secret_file, 'r') as f:
                JWT_SECRET_KEY = f.read().strip()
        else:
            # Generate new secret
            import secrets
            JWT_SECRET_KEY = secrets.token_hex(64)
            with open(secret_file, 'w') as f:
                f.write(JWT_SECRET_KEY)
            print(f"Generated new JWT secret: {secret_file}")
    
    # Database configuration
    DATABASE_URL = os.getenv('DATABASE_URL', 'mongodb://localhost:27017/')