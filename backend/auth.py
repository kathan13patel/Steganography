import bcrypt
import jwt
import datetime
from database import MongoDB

class AuthManager:
    def __init__(self, db):
        self.db = db
        self.secret_key = "your-secret-key-here"  # Change in production

    def hash_password(self, password):
        return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    def verify_password(self, password, hashed_password):
        return bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))

    def generate_token(self, user_id):
        payload = {
            'user_id': user_id,
            'exp': datetime.datetime.now() + datetime.timedelta(hours=24),
            'iat': datetime.datetime.now()
        }
        return jwt.encode(payload, self.secret_key, algorithm='HS256')

    def verify_token(self, token):
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=['HS256'])
            return payload['user_id']
        except jwt.ExpiredSignatureError:
            return None
        except jwt.InvalidTokenError:
            return None

    def register_user(self, username, email, password, mobile):
        if self.db.get_user_by_username(username):
            return None, "Username already exists"
        
        # if self.db.get_user_by_email(email):
        #     return None, "Email already exists"
        
        hashed_password = self.hash_password(password)
        user_id = self.db.create_user({
            'username': username,
            'email': email,
            'password': hashed_password,
            'mobile': mobile,
            'profile_image': 'default.png',
            'created_at': datetime.datetime.now()
        })
        
        token = self.generate_token(str(user_id))
        return token, None

    def login_user(self, username, password):
        user = self.db.get_user_by_username(username)
        if not user or not self.verify_password(password, user['password']):
            return None, "Invalid credentials"
        
        token = self.generate_token(str(user['_id']))
        return token, None