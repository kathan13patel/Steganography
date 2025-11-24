import re
import datetime

def validate_email(email):
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def validate_password(password):
    # At least 8 characters, one uppercase, one lowercase, one number
    if len(password) < 8:
        return False
    if not re.search(r'[A-Z]', password):
        return False
    if not re.search(r'[a-z]', password):
        return False
    if not re.search(r'[0-9]', password):
        return False
    return True

def validate_mobile(mobile):
    # Simple mobile number validation
    pattern = r'^\+?[0-9]{10,15}$'
    return re.match(pattern, mobile) is not None

def validate_username(username):
    # Alphanumeric with underscores, 3-20 characters
    pattern = r'^[a-zA-Z0-9_]{3,20}$'
    return re.match(pattern, username) is not None

def validate_file_type(filename, allowed_types):
    ext = filename.split('.')[-1].lower()
    return ext in allowed_types

def validate_message_length(message, max_length=1000):
    return len(message) <= max_length