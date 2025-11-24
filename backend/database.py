from pymongo import MongoClient
from bson import ObjectId
import datetime

class MongoDB:
    def __init__(self):
        self.client = MongoClient('mongodb://localhost:27017/')
        self.db = self.client['steganography_chat']
        self.users = self.db['users']
        self.messages = self.db['messages']
        self.stego_files = self.db['stego_files']

    def create_user(self, user_data):
        result = self.users.insert_one(user_data)
        return result.inserted_id

    def get_user_by_username(self, username):
        return self.users.find_one({'username': username})

    def get_user_by_email(self, email):
        return self.users.find_one({'email': email})

    def get_user_by_id(self, user_id):
        return self.users.find_one({'_id': ObjectId(user_id)})

    def update_user(self, user_id, update_data):
        self.users.update_one({'_id': ObjectId(user_id)}, {'$set': update_data})

    def get_all_users(self, exclude_user_id=None):
        query = {}
        if exclude_user_id:
            query['_id'] = {'$ne': ObjectId(exclude_user_id)}
        return list(self.users.find(query, {'password': 0}))

    def create_message(self, message_data):
        result = self.messages.insert_one(message_data)
        return result.inserted_id

    def get_messages(self, user_id, other_user_id, limit=50):
        return list(self.messages.find({
            '$or': [
                {'sender_id': user_id, 'receiver_id': other_user_id},
                {'sender_id': other_user_id, 'receiver_id': user_id}
            ]
        }).sort('timestamp', -1).limit(limit))

    def create_stego_file(self, file_data):
        result = self.stego_files.insert_one(file_data)
        return result.inserted_id

    def get_stego_file(self, file_id):
        return self.stego_files.find_one({'_id': ObjectId(file_id)})

    def delete_expired_files(self):
        current_time = datetime.datetime.utcnow()
        self.stego_files.delete_many({'expires_at': {'$lt': current_time}})