import os
import uuid
from werkzeug.utils import secure_filename

def save_file(file, file_type):
    # Create unique filename
    filename = f"{uuid.uuid4()}_{secure_filename(file.filename)}"
    
    # Determine upload directory based on file type
    if file_type == 'image':
        upload_dir = 'uploads/images/'
    elif file_type == 'audio':
        upload_dir = 'uploads/audio/'
    elif file_type == 'video':
        upload_dir = 'uploads/video/'
    else:
        upload_dir = 'uploads/'
    
    # Ensure directory exists
    os.makedirs(upload_dir, exist_ok=True)
    
    # Save file
    file_path = os.path.join(upload_dir, filename)
    file.save(file_path)
    
    return file_path, filename

def delete_file(file_path):
    if os.path.exists(file_path):
        os.remove(file_path)
        return True
    return False

def validate_file(file, allowed_extensions):
    filename = file.filename
    if '.' not in filename:
        return False
    
    ext = filename.rsplit('.', 1)[1].lower()
    return ext in allowed_extensions

def get_file_size(file_path):
    return os.path.getsize(file_path)

def cleanup_old_files(directory, max_age_hours=24):
    import time
    current_time = time.time()
    
    for filename in os.listdir(directory):
        file_path = os.path.join(directory, filename)
        if os.path.isfile(file_path):
            file_age = current_time - os.path.getmtime(file_path)
            if file_age > max_age_hours * 3600:
                delete_file(file_path)