from asyncio import subprocess
import base64
import datetime
from datetime import datetime, timedelta
import http.server
import io
import json
import logging
import re
import shutil
import tempfile
import threading
import traceback
import bcrypt
import socketserver
from http import HTTPStatus
from urllib.parse import urlparse, parse_qs
import ffmpeg
from pymongo import MongoClient
from bson import ObjectId
from bson.errors import InvalidId
from PIL import Image
import json
import websockets
import jwt
import asyncio
import cgi
import websockets
import os
import functools
from dotenv import load_dotenv
import numpy as np
from scipy import fft
import pywt
import wave
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import hashlib
import base64
import av

# Load environment variables
load_dotenv()
connections = {}
UPLOADS_DIR = "uploads"

class Config:
    JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "your-super-secret-jwt-key")

class DatabaseManager:
    @staticmethod
    def initialize_database():
        """Initialize MongoDB connection with better error handling"""
        try:
            client = MongoClient(
                "mongodb://localhost:27017/", 
                serverSelectionTimeoutMS=5000,
                connectTimeoutMS=30000,
                socketTimeoutMS=30000
            )
            db = client["steganography_chat"]
            
            # Test the connection
            client.admin.command("ping")
            print(" Connected to MongoDB successfully")

            # Ensure collections exist with proper validation
            collections = db.list_collection_names()
            
            if "messages" not in collections:
                db.create_collection("messages")
                print("Created messages collection")
                
            if "users" not in collections:
                db.create_collection("users")
                # Create indexes for users collection
                db.users.create_index([("username", 1)], unique=True)
                db.users.create_index([("email", 1)], unique=True)
                print("Created users collection with indexes")
                
            if "user_keys" not in collections:
                db.create_collection("user_keys")
                # Create indexes for user_keys collection
                db.user_keys.create_index([("user_id", 1)], unique=True)
                db.user_keys.create_index([("public_key", 1)])
                print("Created user_keys collection with indexes for E2EE")

            # Create indexes for messages
            db.messages.create_index([("sender_id", 1), ("receiver_id", 1)])
            db.messages.create_index([("timestamp", 1)])
            
            return db

        except Exception as e:
            print(f" Database connection error: {e}")
            # Try to reconnect after delay
            print(" Will attempt to reconnect to database on next request")
            return None

class AuthManager:
    SECRET_KEY = Config.JWT_SECRET_KEY

    @staticmethod
    def validate_token(token):
        """Validate JWT token and return True if valid"""
        try:
            if not token:
                print("No token provided")
                return False

            jwt_secret = Config.JWT_SECRET_KEY
            payload = jwt.decode(token, jwt_secret, algorithms=["HS256"])
            
            # Check if token is expired
            if "exp" in payload:
                expiration = datetime.fromtimestamp(payload["exp"])
                if datetime.now() > expiration:
                    print("Token has expired")
                    return False

            print(f" Token validated for user: {payload.get('username', 'Unknown')}")
            return True
            
        except jwt.ExpiredSignatureError:
            print("Token expired")
            return False
        
        except jwt.InvalidTokenError as e:
            print(f"Invalid token: {e}")
            # Check if this is a signature verification error
            if "signature" in str(e).lower():
                print("JWT SECRET KEY MISMATCH! Check your .env file and restart the server.")
                print(f"Current secret: {Config.JWT_SECRET_KEY[:10]}...")
            return False
        
        except Exception as e:
            print(f"Token validation error: {e}")
            return False

class WebSocketServer:
    def __init__(self, db):
        self.db = db
        self.connections = {}

    async def handler(self, websocket, path):
        """Handler for WebSocket connections"""
        user_id = None
        try:
            print(f" WebSocket connection received to path: {path}")

            # Wait for authentication message first
            try:
                auth_message = await asyncio.wait_for(websocket.recv(), timeout=10.0)
                print(f" Received auth message: {auth_message}")

                auth_data = json.loads(auth_message)

                if auth_data.get("type") != "auth":
                    await websocket.close(
                        code=1008, reason="First message must be authentication"
                    )
                    return

                token = auth_data.get("token")
                user_id = auth_data.get("user_id")
                target_user_id = auth_data.get("target_user_id")

                print(f" Auth data - user_id: {user_id}, token: {token[:20]}...")

                if not token or not user_id:
                    await websocket.close(
                        code=1008, reason="Missing token or user_id in auth message"
                    )
                    return

                # Validate token
                payload = AuthManager.validate_token(token)
                if not payload:
                    print(" Token validation failed")
                    await websocket.close(code=1008, reason="Invalid token")
                    return

                print(f" WebSocket authenticated for user: {user_id}")

                # Store connection
                self.connections[user_id] = websocket
                print(f"Active connections: {list(self.connections.keys())}")

                await websocket.send(
                    json.dumps(
                        {
                            "type": "connection_established",
                            "message": "WebSocket connection established successfully",
                            "user_id": user_id,
                        }
                    )
                )
                
                async for message in websocket:
                    try:
                        message_data = json.loads(message)
                        print(f" Message from {user_id}: {message_data}")

                        # Handle different message types
                        if message_data.get("type") == "message":
                            await self._handle_message(message_data, user_id)
                        elif message_data.get("type") == "get_messages":
                            await self._handle_get_messages(message_data, user_id)
                        else:
                            print(f"️ Unknown message type: {message_data.get('type')}")

                    except json.JSONDecodeError:
                        print(f"️ Invalid JSON received: {message}")
                    except Exception as e:
                        print(f"️ Error processing message: {e}")

            except asyncio.TimeoutError:
                print(" Authentication timeout")
                await websocket.close(code=1008, reason="Authentication timeout")
                return
            except json.JSONDecodeError as e:
                print(f" JSON decode error: {e}")
                await websocket.close(code=1008, reason="Invalid JSON in auth message")
                return

        except websockets.exceptions.ConnectionClosed:
            print(f" WebSocket connection closed for user: {user_id}")
        except Exception as e:
            print(f" WebSocket error: {e}")
            import traceback
            traceback.print_exc()
        finally:
            if user_id and user_id in self.connections:
                del self.connections[user_id]
                print(f" Removed connection for {user_id}")

    async def _handle_message(self, message_data, sender_id):
        """Handle incoming messages and route to recipient"""
        try:
            message = message_data.get("message", {})
            receiver_id = message.get("receiver_id")

            if not receiver_id:
                print(" No receiver_id specified in message")
                return

            print(f" Routing ENCRYPTED message from {sender_id} to {receiver_id}")

            #  E2EE: Store encrypted message in database
            message_id = await self._store_encrypted_message_in_db(message, sender_id)
            if message_id:
                message["id"] = message_id

            # Add timestamp if not present
            if not message.get("timestamp"):
                message["timestamp"] = datetime.now().isoformat()

            # Send to recipient if online (REAL-TIME) - ENCRYPTED
            if receiver_id in self.connections:
                recipient_ws = self.connections[receiver_id]
                await recipient_ws.send(
                    json.dumps({"type": "message", "message": message})
                )
                print(f" ENCRYPTED message delivered to {receiver_id}")

                # Mark as delivered in DB
                self.db.messages.update_one(
                    {"_id": ObjectId(message_id)}, {"$set": {"delivered": True}}
                )
            else:
                print(f"️ User {receiver_id} is offline")
                # Message remains undelivered, will be picked up by polling

            # Send confirmation back to sender
            if sender_id in self.connections:
                sender_ws = self.connections[sender_id]
                await sender_ws.send(
                    json.dumps(
                        {
                            "type": "message_sent",
                            "message_id": message.get("id"),
                            "status": (
                                "delivered"
                                if receiver_id in self.connections
                                else "stored"
                            ),
                        }
                    )
                )

        except Exception as e:
            print(f" Error handling encrypted message: {e}")
            import traceback
            traceback.print_exc()

    async def _store_encrypted_message_in_db(self, message, sender_id):
        """Store ENCRYPTED message in MongoDB"""
        try:
            message_doc = {
                "sender_id": sender_id,
                "receiver_id": message["receiver_id"],
                "encrypted_content": message.get("encrypted_content", {}),  # Encrypted data
                "timestamp": datetime.now(),
                "file": message.get("file"),
                "status": "sent",
                "delivered": False,
            }

            result = self.db.messages.insert_one(message_doc)
            return str(result.inserted_id)

        except Exception as e:
            print(f" Error storing encrypted message in DB: {e}")
            return None
    
    async def _handle_get_messages(self, message_data, user_id):
        """Handle request to get messages"""
        try:
            target_user_id = message_data.get("target_user_id")
            if not target_user_id:
                return

            messages = await self._get_messages_from_db(user_id, target_user_id)
            
            if user_id in self.connections:
                await self.connections[user_id].send(
                    json.dumps({
                        "type": "messages",
                        "messages": messages,
                        "target_user_id": target_user_id
                    })
                )
                
        except Exception as e:
            print(f" Error getting messages: {e}")
    
    async def _get_messages_from_db(self, user_id, target_user_id):
        """Retrieve messages between two users from MongoDB"""
        try:
            messages = self.db.messages.find(
                {
                    "$or": [
                        {"sender_id": user_id, "receiver_id": target_user_id},
                        {"sender_id": target_user_id, "receiver_id": user_id},
                    ]
                }
            ).sort("timestamp", 1)

            messages_list = []
            for msg in messages:
                msg["id"] = str(msg["_id"])
                del msg["_id"]
                messages_list.append(msg)

            return messages_list

        except Exception as e:
            print(f" Error retrieving messages from DB: {e}")
            return []

    async def watch_for_messages(self):
        """Poll MongoDB for new messages and deliver to recipients"""
        try:
            print("Polling for new messages every 2 seconds...")

            while True:
                try:
                    # Use find() instead of async for regular MongoDB driver
                    undelivered_messages = self.db.messages.find(
                        {"delivered": {"$ne": True}}
                    )

                    message_count = 0
                    for message in undelivered_messages:
                        message_count += 1
                        receiver_id = message["receiver_id"]
                        print(
                            f" Found undelivered message {message_count} for {receiver_id}"
                        )

                        # Check if recipient is connected
                        if receiver_id in self.connections:
                            print(
                                f" Recipient {receiver_id} is online, attempting delivery..."
                            )
                            recipient_ws = self.connections[receiver_id]

                            try:
                                # Send the message
                                await recipient_ws.send(
                                    json.dumps(
                                        {
                                            "type": "message",
                                            "message": {
                                                "id": str(message["_id"]),
                                                "sender_id": message["sender_id"],
                                                "receiver_id": message["receiver_id"],
                                                "content": message["content"],
                                                "timestamp": message["timestamp"],
                                                "file": message.get("file"),
                                            },
                                        }
                                    )
                                )
                                print(f" Message delivered to {receiver_id}")

                                # Mark as delivered
                                self.db.messages.update_one(
                                    {"_id": message["_id"]},
                                    {"$set": {"delivered": True}},
                                )

                            except Exception as send_error:
                                print(
                                    f" Error sending message to {receiver_id}: {send_error}"
                                )
                                # Don't crash, just continue with next message
                        else:
                            print(
                                f"️ Recipient {receiver_id} offline (connections: {list(self.connections.keys())})"
                            )

                    if message_count == 0:
                        print(" No undelivered messages found")

                    # Wait before checking again
                    await asyncio.sleep(2)

                except Exception as e:
                    print(f" Error in message polling iteration: {e}")
                    # Wait a bit longer on error, but don't crash
                    await asyncio.sleep(5)

        except Exception as e:
            print(f" Critical error in message polling: {e}")
            # Don't re-raise to prevent server crash

    async def handle_notification(self, message_data):
        """Handle new message notifications from HTTP server"""
        try:
            receiver_id = message_data["receiver_id"]

            if receiver_id in self.connections:
                recipient_ws = self.connections[receiver_id]
                await recipient_ws.send(
                    json.dumps({"type": "message", "message": message_data})
                )
                print(f" Notification delivered to {receiver_id}")
            else:
                print(f"️ Recipient {receiver_id} offline, cannot deliver notification")

        except Exception as e:
            print(f" Error handling notification: {e}")

async def run_websocket_server(db, port=8001):
    """Run the WebSocket server"""
    try:
        server = WebSocketServer(db)

        # Create the WebSocket server with proper error handling
        print(f" Starting WebSocket server on port {port}...")

        # Test if port is available first
        import socket

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        result = sock.connect_ex(("localhost", port))
        sock.close()

        if result == 0:
            print(f" Port {port} is already in use! Trying port {port + 1}...")
            await run_websocket_server(db, port + 1)
            return

        # Start the WebSocket server
        async with websockets.serve(
            server.handler,
            "localhost",
            port,
            ping_interval=20,
            ping_timeout=20,
        ) as ws_server:
            print(f" WebSocket server successfully running on ws://localhost:{port}")
            print("Listening for connections...")

            # Keep the server running
            await asyncio.Future()  # Run forever

    except Exception as e:
        print(f" Failed to start WebSocket server: {e}")
        import traceback

        traceback.print_exc()
        # Don't crash the entire app, just log the error and continue
        print("️ WebSocket server failed, but HTTP server continues running")

class E2EEManager:
    def __init__(self):
        pass
    
    def generate_key_pair(self):
        """Generate key pair for key exchange (for client use)"""
        # This is just documentation - actual generation happens on client
        return {
            "instructions": "Key generation should happen on client-side using Web Crypto API"
        }
    
    def store_public_key(self, user_id, public_key):
        """Store user's public key (server only stores public keys)"""
        try:
            # In a real implementation, this would store in database
            # For now, we'll just print
            print(f" Storing public key for user {user_id}")
            return True
        except Exception as e:
            print(f" Error storing public key: {e}")
            return False
    
    def get_public_key(self, user_id):
        """Retrieve user's public key for key exchange"""
        try:
            # In a real implementation, this would query the database
            # For now, return None (clients should handle key exchange)
            return None
        except Exception as e:
            print(f" Error getting public key: {e}")
            return None
    
class SteganographyRequestHandler(http.server.BaseHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        self.db = DatabaseManager.initialize_database()
        self.e2ee_manager = E2EEManager()
        
        #  FIXED: Compare with None instead of using if self.db
        if self.db is not None:
            self.users_collection = self.db.users
            self.messages_collection = self.db.messages
            # Try to initialize keys collection
            try:
                collection_names = self.db.list_collection_names()
                if 'user_keys' in collection_names:
                    self.keys_collection = self.db.user_keys
                elif 'keys' in collection_names:
                    self.keys_collection = self.db.keys
                else:
                    self.keys_collection = None
            except Exception as e:
                print(f"️ Could not initialize keys collection: {e}")
                self.keys_collection = None
        else:
            # Set collections to None if db is None
            self.users_collection = None
            self.messages_collection = None
            self.keys_collection = None
        
        super().__init__(*args, **kwargs)
       
    def handle_key_exchange(self, post_data_str):
        """POST /api/keys/exchange - Exchange public keys"""
        try:
            auth_header = self.headers.get('Authorization', '')
            if not auth_header.startswith('Bearer '):
                self.send_auth_error()
                return
                
            token = auth_header[7:]
            payload = self.validate_token_and_get_payload(token)
            if not payload:
                self.send_auth_error()
                return

            data = json.loads(post_data_str)
            user_id = payload.get('_id')
            public_key = data.get('public_key')
            target_user_id = data.get('target_user_id')

            if not all([public_key, target_user_id]):
                self.send_error_response(HTTPStatus.BAD_REQUEST, "Missing required fields")
                return

            # Store public key
            self.db.user_keys.update_one(
                {"user_id": user_id},
                {"$set": {
                    "public_key": public_key,
                    "updated_at": datetime.now()
                }},
                upsert=True
            )

            self.send_json_response(HTTPStatus.OK, {
                "success": True,
                "message": "Public key stored successfully"
            })

        except Exception as e:
            print(f"Key exchange error: {e}")
            self.send_error_response(HTTPStatus.INTERNAL_SERVER_ERROR, "Key exchange failed")

    def handle_register_public_key(self, post_data_str):
        """POST /api/keys/register - Register user's public key"""
        try:
            auth_header = self.headers.get('Authorization', '')
            if not auth_header.startswith('Bearer '):
                self.send_auth_error()
                return
                
            token = auth_header[7:]
            payload = self.validate_token_and_get_payload(token)
            if not payload:
                self.send_auth_error()
                return

            data = json.loads(post_data_str)
            user_id = payload.get('_id')
            public_key = data.get('public_key')

            if not public_key:
                self.send_error_response(HTTPStatus.BAD_REQUEST, "Public key required")
                return

            # Store public key in database
            result = self.db.user_keys.update_one(
                {"user_id": user_id},
                {"$set": {
                    "public_key": public_key,
                    "updated_at": datetime.now()
                }},
                upsert=True
            )

            self.send_json_response(HTTPStatus.OK, {
                "success": True,
                "message": "Public key registered successfully"
            })

        except Exception as e:
            print(f"Public key registration error: {e}")
            self.send_error_response(HTTPStatus.INTERNAL_SERVER_ERROR, "Key registration failed")

    def handle_get_public_key(self, user_id):
        """GET /api/keys/{user_id} - Get user's public key"""
        try:
            auth_header = self.headers.get('Authorization', '')
            if not auth_header.startswith('Bearer '):
                self.send_auth_error()
                return
                
            token = auth_header[7:]
            if not self.validate_token(token):
                self.send_auth_error()
                return

            key_data = self.db.user_keys.find_one({"user_id": user_id})
            if not key_data:
                self.send_error_response(HTTPStatus.NOT_FOUND, "Public key not found")
                return

            self.send_json_response(HTTPStatus.OK, {
                "success": True,
                "public_key": key_data.get('public_key'),
                "user_id": user_id
            })

        except Exception as e:
            print(f"Get public key error: {e}")
            self.send_error_response(HTTPStatus.INTERNAL_SERVER_ERROR, "Failed to get public key")
       
    def generate_dynamic_key(self):
        """Generate random 32-byte AES key for each file"""
        return get_random_bytes(32)       
        
    def handle_get_profile(self):
        """GET /api/profile - Get user profile"""
        try:
            print(" Handling get profile request")
            
            # Validate authentication and get payload
            auth_header = self.headers.get('Authorization', '')
            if not auth_header.startswith('Bearer '):
                self.send_auth_error()
                return
                
            token = auth_header[7:]
            payload = self.validate_token_and_get_payload(token)
            if not payload:
                self.send_auth_error()
                return

            user_id = payload.get('_id')
            if not user_id:
                self.send_error_response(HTTPStatus.BAD_REQUEST, "Invalid user ID in token")
                return

            # Get user from database
            try:
                user = self.db.users.find_one({"_id": ObjectId(user_id)}, {"password": 0})
                if not user:
                    self.send_error_response(HTTPStatus.NOT_FOUND, "User not found")
                    return

                user_data = {
                    "id": str(user["_id"]),
                    "username": user.get("username", ""),
                    "email": user.get("email", ""),
                    "mobile": user.get("mobile", ""),
                    "profile_image": user.get("profile_image", "default.png"),
                    "created_at": user.get("created_at")
                }

                self.send_json_response(HTTPStatus.OK, user_data)
                
            except InvalidId:
                self.send_error_response(HTTPStatus.BAD_REQUEST, "Invalid user ID format")
                
        except Exception as e:
            print(f" Get profile error: {e}")
            self.send_error_response(HTTPStatus.INTERNAL_SERVER_ERROR, "Error fetching profile")

    def handle_update_profile(self, post_data_str):
        """PUT /api/profile/update - Update user profile"""
        try:
            print(" Handling update profile request")
            
            # Validate authentication and get payload
            auth_header = self.headers.get('Authorization', '')
            if not auth_header.startswith('Bearer '):
                self.send_auth_error()
                return
                
            token = auth_header[7:]
            payload = self.validate_token_and_get_payload(token)
            if not payload:
                self.send_auth_error()
                return

            user_id = payload.get('_id')
            if not user_id:
                self.send_error_response(HTTPStatus.BAD_REQUEST, "Invalid user ID in token")
                return

            # Parse JSON data
            user_data = json.loads(post_data_str)

            # Validate required fields
            required_fields = ['username', 'email']
            for field in required_fields:
                if field not in user_data:
                    self.send_error_response(HTTPStatus.BAD_REQUEST, f"Missing field: {field}")
                    return

            # Check if username (excluding current user)
            existing_user = self.db.users.find_one({
                "$and": [
                    {"_id": {"$ne": ObjectId(user_id)}},
                    {"$or": [
                        {"username": user_data["username"]}
                    ]}
                ]
            })
            
            if existing_user:
                self.send_error_response(HTTPStatus.CONFLICT, "Username already exists")
                return

            # Update user in database
            update_data = {
                "username": user_data["username"],
                "email": user_data["email"],
                "mobile": user_data.get("mobile", ""),
                "updated_at": datetime.now()
            }

            result = self.db.users.update_one(
                {"_id": ObjectId(user_id)},
                {"$set": update_data}
            )

            if result.modified_count == 0:
                self.send_error_response(HTTPStatus.NOT_FOUND, "User not found or no changes made")
                return

            self.send_json_response(HTTPStatus.OK, {
                "success": True,
                "message": "Profile updated successfully",
                "data": update_data
            })
            
        except json.JSONDecodeError:
            self.send_error_response(HTTPStatus.BAD_REQUEST, "Invalid JSON format")
        except InvalidId:
            self.send_error_response(HTTPStatus.BAD_REQUEST, "Invalid user ID format")
        except Exception as e:
            print(f" Update profile error: {e}")
            self.send_error_response(HTTPStatus.INTERNAL_SERVER_ERROR, "Error updating profile")

    def handle_upload_profile_image(self):
        """POST /api/profile/upload-image - Upload profile image"""
        try:
            print(" Handling profile image upload request")
            
            # Validate authentication and get payload
            auth_header = self.headers.get('Authorization', '')
            if not auth_header.startswith('Bearer '):
                self.send_auth_error()
                return
                
            token = auth_header[7:]
            payload = self.validate_token_and_get_payload(token)
            if not payload:
                self.send_auth_error()
                return

            user_id = payload.get('_id')
            if not user_id:
                self.send_error_response(HTTPStatus.BAD_REQUEST, "Invalid user ID in token")
                return

            # Parse multipart form data
            form_data = cgi.FieldStorage(
                fp=self.rfile,
                headers=self.headers,
                environ={'REQUEST_METHOD': 'POST'}
            )
            
            # Get the file from form data
            if 'image' not in form_data:
                self.send_error_response(HTTPStatus.BAD_REQUEST, "No image file provided")
                return
                
            file_item = form_data['image']
            if not file_item.file:
                self.send_error_response(HTTPStatus.BAD_REQUEST, "No image file provided")
                return

            # Validate file type
            filename = file_item.filename
            if not (filename.lower().endswith('.jpg') or filename.lower().endswith('.jpeg') or 
                    filename.lower().endswith('.png') or filename.lower().endswith('.gif')):
                self.send_error_response(HTTPStatus.BAD_REQUEST, "Invalid file type. Only JPG, PNG, and GIF are allowed.")
                return

            # Generate unique filename
            file_extension = os.path.splitext(filename)[1]
            new_filename = f"{user_id}_{int(datetime.now().timestamp())}{file_extension}"
            upload_path = os.path.join('uploads', 'profile_images', new_filename)
            
            # Create directory if it doesn't exist
            os.makedirs(os.path.dirname(upload_path), exist_ok=True)
            
            # Save the file
            with open(upload_path, 'wb') as f:
                f.write(file_item.file.read())
            
            # Update user profile with new image filename
            result = self.db.users.update_one(
                {"_id": ObjectId(user_id)},
                {"$set": {"profile_image": new_filename, "updated_at": datetime.now()}}
            )

            if result.modified_count == 0:
                self.send_error_response(HTTPStatus.NOT_FOUND, "User not found")
                return

            # Send success response
            self.send_response(HTTPStatus.OK)
            self.send_header('Content-type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            
            response_data = {
                "success": True,
                "message": "Profile image updated successfully",
                "filename": new_filename,
                "image_url": f"/uploads/profile_images/{new_filename}"
            }
            
            self.wfile.write(json.dumps(response_data).encode('utf-8'))
            
        except Exception as e:
            print(f" Profile image upload error: {e}")
            self.send_error_response(HTTPStatus.INTERNAL_SERVER_ERROR, "Error uploading profile image")
    
    def handle_change_password(self, post_data_str):
        """POST /api/profile/change-password - Change password"""
        try:
            print(" Handling change password request")
            
            # Validate authentication and get payload
            auth_header = self.headers.get('Authorization', '')
            if not auth_header.startswith('Bearer '):
                self.send_auth_error()
                return
                
            token = auth_header[7:]
            payload = self.validate_token_and_get_payload(token)
            if not payload:
                self.send_auth_error()
                return

            user_id = payload.get('_id')
            if not user_id:
                self.send_error_response(HTTPStatus.BAD_REQUEST, "Invalid user ID in token")
                return

            # Parse JSON data
            password_data = json.loads(post_data_str)

            # Validate required fields
            if 'currentPassword' not in password_data or 'newPassword' not in password_data:
                self.send_error_response(HTTPStatus.BAD_REQUEST, "Missing password fields")
                return

            # Get user from database to verify current password
            user = self.db.users.find_one({"_id": ObjectId(user_id)})
            if not user:
                self.send_error_response(HTTPStatus.NOT_FOUND, "User not found")
                return

            # Verify current password
            if not bcrypt.checkpw(password_data['currentPassword'].encode('utf-8'), user['password'].encode('utf-8')):
                self.send_error_response(HTTPStatus.UNAUTHORIZED, "Current password is incorrect")
                return

            # Hash new password
            hashed_password = bcrypt.hashpw(password_data['newPassword'].encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

            # Update password in database
            result = self.db.users.update_one(
                {"_id": ObjectId(user_id)},
                {"$set": {"password": hashed_password, "updated_at": datetime.now()}}
            )

            if result.modified_count == 0:
                self.send_error_response(HTTPStatus.INTERNAL_SERVER_ERROR, "Failed to update password")
                return

            self.send_json_response(HTTPStatus.OK, {
                "success": True,
                "message": "Password changed successfully"
            })
            
        except json.JSONDecodeError:
            self.send_error_response(HTTPStatus.BAD_REQUEST, "Invalid JSON format")
        except InvalidId:
            self.send_error_response(HTTPStatus.BAD_REQUEST, "Invalid user ID format")
        except Exception as e:
            print(f" Change password error: {e}")
            self.send_error_response(HTTPStatus.INTERNAL_SERVER_ERROR, "Error changing password")

    def validate_token_and_get_payload(self, token):
        """Validate JWT token and return payload if valid, None otherwise"""
        try:
            if not token:
                print("No token provided")
                return None

            jwt_secret = Config.JWT_SECRET_KEY
            payload = jwt.decode(token, jwt_secret, algorithms=["HS256"])
            
            # Check if token is expired
            if "exp" in payload:
                expiration = datetime.fromtimestamp(payload["exp"])
                if datetime.utcnow() > expiration:
                    print("Token has expired")
                    return None

            print(f" Token validated for user: {payload.get('username', 'Unknown')}")
            return payload
            
        except jwt.ExpiredSignatureError:
            print("Token expired")
            return None
        except jwt.InvalidTokenError as e:
            print(f"Invalid token: {e}")
            # Check if this is a signature verification error
            if "signature" in str(e).lower():
                print(" JWT SECRET KEY MISMATCH! Check your .env file and restart the server.")
                print(f"Current secret: {Config.JWT_SECRET_KEY[:10]}...")
            return None
        except Exception as e:
            print(f"Token validation error: {e}")
            return None

    def send_header(self, keyword, value):
        """Override send_header to prevent duplicate CORS headers"""
        if keyword == "Access-Control-Allow-Origin":
            # Check if this header was already sent
            if hasattr(self, '_cors_origin_sent'):
                print(f" BLOCKED duplicate CORS header: {keyword}: {value}")
                return  # Don't send duplicate
            self._cors_origin_sent = True
            print(f" Allowing CORS header: {keyword}: {value}")
        
        super().send_header(keyword, value)

    def do_OPTIONS(self):
        """Handle preflight CORS requests"""
        self.send_response(200)
        self.send_cors_headers()
        self.end_headers()

    def parse_multipart_form_data(self):
        """Parse multipart form data for file uploads"""
        content_type = self.headers.get("Content-Type", "")
        if not content_type.startswith("multipart/form-data"):
            return None, None

        # Get boundary from content type
        boundary = content_type.split("boundary=")[-1].encode()

        # Read the raw post data
        content_length = int(self.headers.get("Content-Length", 0))
        post_data = self.rfile.read(content_length)

        # Simple multipart parsing
        parts = post_data.split(b"--" + boundary)
        form_data = {}
        files = {}

        for part in parts:
            if b"Content-Disposition: form-data" in part:
                # Parse headers and content
                headers, content = part.split(b"\r\n\r\n", 1)
                content = content.rstrip(b"\r\n--")

                # Parse field name
                field_match = re.search(b'name="([^"]+)"', headers)
                if field_match:
                    field_name = field_match.group(1).decode()

                    # Check if it's a file
                    filename_match = re.search(b'filename="([^"]+)"', headers)
                    if filename_match:
                        # It's a file upload
                        filename = filename_match.group(1).decode()
                        files[field_name] = {"filename": filename, "content": content}
                    else:
                        # It's a regular form field
                        form_data[field_name] = content.decode().strip()

        return form_data, files

    def handle_debug_token(self):
        """Debug endpoint to check token issues"""
        auth_header = self.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header[7:]
            print(f"Token being verified: {token[:20]}...")
            print(f"JWT Secret being used: {Config.JWT_SECRET_KEY[:10]}...")

            try:
                jwt_secret = Config.JWT_SECRET_KEY
                payload = jwt.decode(token, jwt_secret, algorithms=["HS256"])
                self.send_json_response(HTTPStatus.OK, {"success": True, "valid": True, "payload": payload})
            except Exception as e:
                self.send_json_response(
                    HTTPStatus.OK, {"success": False, "valid": False, "error": str(e)}
                )
        else:
            self.send_json_response(
                HTTPStatus.BAD_REQUEST, {"success": False, "error": "No token provided"}
            )

    def do_GET(self):
        """Handle GET requests"""
        try:
            parsed_path = urlparse(self.path)
            path = parsed_path.path

            print(f"Received GET request for: {path}")

            if path.startswith("/uploads/profile_images/"):
                try:
                    # Extract filename from path
                    filename = path.split("/")[-1]
                    uploads_dir = os.path.join('uploads', 'profile_images')
                    file_path = os.path.join(uploads_dir, filename)
                    
                    print(f" Serving profile image: {filename}")
                    print(f" Looking for file at: {file_path}")
                    
                    # Check if file exists
                    if os.path.exists(file_path) and os.path.isfile(file_path):
                        print(f" Found image file: {file_path}")
                        
                        # Set content type based on file extension
                        if filename.lower().endswith('.png'):
                            content_type = 'image/png'
                        elif filename.lower().endswith('.jpg') or filename.lower().endswith('.jpeg'):
                            content_type = 'image/jpeg'
                        elif filename.lower().endswith('.gif'):
                            content_type = 'image/gif'
                        else:
                            content_type = 'application/octet-stream'
                        
                        # Send headers
                        self.send_response(HTTPStatus.OK)
                        self.send_header('Content-Type', content_type)
                        self.send_header('Cache-Control', 'public, max-age=3600')  # Cache for 1 hour
                        self.send_cors_headers()
                        self.end_headers()
                        
                        # Read and send file in chunks to avoid large file issues
                        try:
                            with open(file_path, 'rb') as f:
                                shutil.copyfileobj(f, self.wfile)
                            print(f" Successfully served image: {filename}")
                        except BrokenPipeError:
                            print("️ Client disconnected during image transfer")
                        except Exception as e:
                            print(f" Error reading image file: {e}")
                            
                    else:
                        print(f" Image file not found: {file_path}")
                        # Serve default profile image
                        default_image = os.path.join('static', 'profile.jpg')
                        if os.path.exists(default_image):
                            self.send_response(HTTPStatus.OK)
                            self.send_header('Content-Type', 'image/jpeg')
                            self.send_cors_headers()
                            self.end_headers()
                            with open(default_image, 'rb') as f:
                                shutil.copyfileobj(f, self.wfile)
                        else:
                            self.send_error_response(HTTPStatus.NOT_FOUND, "Profile image not found")
                            
                except Exception as e:
                    print(f" Error serving profile image: {e}")
                    self.send_error_response(HTTPStatus.INTERNAL_SERVER_ERROR, f"Error serving image: {str(e)}")
                return

            if path == "/api/users/search":
                self.handle_user_search()
                return
            elif path == "/api/profile":
                self.handle_get_profile()
                return
            elif path == "/health":
                self.send_json_response(
                    HTTPStatus.OK,
                    {
                        "success": True,
                        "status": "healthy",
                        "timestamp": str(datetime.now()),
                    },
                )
                return
            elif path == "/api/debug":
                self.send_json_response(
                    HTTPStatus.OK,
                    {
                        "success": True,
                        "message": "Server is running",
                        "timestamp": str(datetime.now()),
                    },
                )
                return
            elif path == "/api/debug-token":
                self.handle_debug_token()
                return
            elif path == "/api/users":
                self.handle_get_users()
                return
            elif path.startswith("/api/messages/"):
                user_id = path.split("/")[-1]
                self.handle_get_messages(user_id)
                return
            elif path == "/api/how-to-use":
                self.handle_how_to_use()
                return
            elif path == "/api/verify-token":
                self.handle_verify_token()
                return
            elif path == "/api/debug":
                self.send_json_response(
                    HTTPStatus.OK,
                    {
                        "success": True,
                        "message": "Debug endpoint working",
                        "server_time": str(datetime.now()),
                        "request_path": path,
                    },
                )
                return
            elif path.startswith("/api/keys/"):
                user_id = path.split("/")[-1]
                self.handle_get_public_key(user_id)
                return
            else:
                self.send_error_response(HTTPStatus.NOT_FOUND, "Endpoint not found")
        except Exception as e:
            print(f"GET error: {str(e)}")
            import traceback

            traceback.print_exc()
            self.send_error_response(
                HTTPStatus.INTERNAL_SERVER_ERROR, f"Server error: {str(e)}"
            )

    def do_POST(self):
        """Handle POST requests"""
        try:
            content_type = self.headers.get("Content-Type", "")
            parsed_path = urlparse(self.path)
            path = parsed_path.path

            print(f"NEW REQUEST: {path}")
            print(f"Content-Type: {content_type}")
            print(f" Is multipart: {content_type.startswith('multipart/form-data')}")
            print(f" Is JSON: {content_type.startswith('application/json')}")

            # Handle multipart form data
            if content_type.startswith("multipart/form-data"):
                print(" Processing as multipart/form-data")
                
                # Add this condition for profile image upload
                if path == "/api/profile/upload-image":
                    print(" Handling profile image upload")
                    self.handle_upload_profile_image()
                    return
                    
                form_data, files = self.parse_multipart_form_data()

                if path == "/api/encode":
                    print(" Calling encode handler")
                    # File type detection logic
                    if 'file' in files:
                        filename = files['file']['filename'].lower()
                        
                        # Audio detection
                        if filename.endswith('.wav'):
                            print(" Detected WAV audio file for encoding")
                            self.handle_encode_audio(form_data, files)
                        
                        # Video detection
                        elif any(filename.endswith(ext) for ext in ['.mp4', '.avi', '.mov', '.mkv', '.webm']):
                            print(" Detected video file for encoding")
                            self.handle_encode_video(form_data, files)
                        
                        # Regular file (image/text)
                        else:
                            print("Detected regular file for encoding")
                            self.handle_encode_multipart(form_data, files)
                    else:
                        print("No file detected, using multipart encode")
                        self.handle_encode_multipart(form_data, files)
                        
                elif path == "/api/decode":
                    print(" Calling decode handler")
                    # File type detection logic
                    if 'file' in files:
                        filename = files['file']['filename'].lower()
                        
                        # Audio detection
                        if filename.endswith('.wav'):
                            print(" Detected WAV audio file for decoding")
                            self.handle_decode_audio(form_data, files)
                        
                        # Video detection
                        elif any(filename.endswith(ext) for ext in ['.mp4', '.avi', '.mov', '.mkv', '.webm']):
                            print(" Detected video file for decoding")
                            self.handle_decode_video(form_data, files)
                        
                        # Regular file (image/text)
                        else:
                            print("Detected regular file for decoding")
                            self.handle_decode_multipart(form_data, files)
                    else:
                        print("No file detected, using multipart decode")
                        self.handle_decode_multipart(form_data, files)      
                elif path == "/api/send-message":
                    print("ERROR: /api/send-message received multipart data!")
                    print("This endpoint expects JSON, not multipart")
                    self.send_error_response(
                        HTTPStatus.BAD_REQUEST, "This endpoint expects JSON data"
                    )
                elif path == "/api/keys/exchange":
                    self.handle_key_exchange(post_data_str)
                    return
                elif path == "/api/keys/register":
                    self.handle_register_public_key(post_data_str)
                    return
                else:
                    self.send_error_response(HTTPStatus.NOT_FOUND, "Endpoint not found")
                return

            # Handle JSON data (your existing JSON handling remains unchanged)
            else:
                print(" Processing as JSON data")
                content_length = int(self.headers.get("Content-Length", 0))

                if content_length <= 0:
                    print("Empty request body received")
                    self.send_error_response(
                        HTTPStatus.BAD_REQUEST, "Empty request body"
                    )
                    return

                post_data_bytes = self.rfile.read(content_length)
                post_data_str = post_data_bytes.decode("utf-8", errors="replace")

                print(f"Raw data: '{post_data_str}'")

                if path == "/api/register":
                    self.handle_register(post_data_str)
                elif path == "/api/users/search":
                    self.handle_user_search(post_data_str)
                elif path == "/api/users":
                    self.handle_get_users(post_data_str)
                elif path == "/api/login":
                    self.handle_login(post_data_str)
                elif path == "/api/send-message":
                    print(" Calling send-message handler with JSON")
                    self.handle_send_message(post_data_str)
                elif path == "/api/profile/update":
                    self.handle_update_profile(post_data_str)
                elif path == "/api/profile/change-password":
                    self.handle_change_password(post_data_str)
                else:
                    self.send_error_response(HTTPStatus.NOT_FOUND, "Endpoint not found")

        except Exception as e:
            print(f"POST error: {str(e)}")
            import traceback
            traceback.print_exc()
            self.send_error_response(
                HTTPStatus.INTERNAL_SERVER_ERROR, f"Server error: {str(e)}"
            )
        
    def do_PUT(self):
        """Handle PUT requests for profile updates"""
        try:
            content_type = self.headers.get("Content-Type", "")
            parsed_path = urlparse(self.path)
            path = parsed_path.path

            print(f"PUT REQUEST: {path}")

            if path == "/api/profile/update" and content_type.startswith("application/json"):
                content_length = int(self.headers.get("Content-Length", 0))
                
                if content_length <= 0:
                    self.send_error_response(HTTPStatus.BAD_REQUEST, "Empty request body")
                    return

                post_data_bytes = self.rfile.read(content_length)
                post_data_str = post_data_bytes.decode("utf-8", errors="replace")
                
                self.handle_update_profile(post_data_str)
                
            else:
                self.send_error_response(HTTPStatus.NOT_FOUND, "Endpoint not found")
                
        except Exception as e:
            print(f"PUT error: {str(e)}")
            self.send_error_response(HTTPStatus.INTERNAL_SERVER_ERROR, f"Server error: {str(e)}")    
    
    def handle_user_search(self):
        """Handle user search endpoint with improved reliability"""
        try:
            # Parse query parameters
            parsed_path = urlparse(self.path)
            query_params = parse_qs(parsed_path.query)
            search_term = query_params.get("q", [""])[0].strip()

            print(f" Search request for: '{search_term}'")

            # Validate authorization
            auth_header = self.headers.get("Authorization", "")
            if not auth_header.startswith("Bearer "):
                print("Authorization header missing or invalid")
                self.send_auth_error()
                return

            token = auth_header[7:]  # Remove 'Bearer ' prefix

            # Validate token
            if not self.validate_token(token):
                print("Token validation failed")
                self.send_auth_error()
                return

            # Validate search term (reduced to 2 chars for better UX)
            if not search_term or len(search_term) < 0:
                self.send_json_response(
                    HTTPStatus.BAD_REQUEST,
                    {
                        "success": False
                    },
                )
                return

            print(f" Searching for: '{search_term}'")

            # Get user ID from token for exclusion
            try:
                jwt_secret = Config.JWT_SECRET_KEY
                payload = jwt.decode(token, jwt_secret, algorithms=["HS256"])
                current_user_id = payload.get("_id")
                print(f" Current user ID: {current_user_id}")
            except Exception as e:
                print(f" Error decoding token: {e}")
                self.send_auth_error()
                return

            # Search for users in MongoDB (excluding current user)
            try:
                users = self.search_users_in_mongodb(search_term, current_user_id)
                print(f" Found {len(users)} users matching search")
            except Exception as db_error:
                print(f" Database search error: {db_error}")
                self.send_json_response(
                    HTTPStatus.INTERNAL_SERVER_ERROR,
                    {"success": False, "message": "Database search failed"},
                )
                return

            # Format response
            users_data = []
            for user in users:
                users_data.append(
                    {
                        "id": str(user["_id"]),
                        "username": user["username"],
                        "email": user["email"],
                        "profile_image": user.get("profile_image", "default.png"),
                    }
                )

            # Send response
            self.send_response(200)
            self.send_cors_headers()
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(
                json.dumps(
                    {"success": True, "users": users_data, "count": len(users_data)}
                ).encode("utf-8")
            )

        except Exception as e:
            print(f" Search users error: {str(e)}")
            import traceback

            traceback.print_exc()
            self.send_json_response(
                HTTPStatus.INTERNAL_SERVER_ERROR,
                {
                    "success": False,
                    "message": "An error occurred while searching users",
                },
            )

    def search_users_in_mongodb(self, search_term, current_user_id):
        """Search users in MongoDB with improved search logic"""
        try:
            # Check database connection
            if self.db is None:
                print(" Database connection is None")
                # Try to reconnect
                self.initialize_database()
                if self.db is None:
                    return []

            # Create a case-insensitive search pattern
            search_pattern = re.compile(f".*{re.escape(search_term)}.*", re.IGNORECASE)

            # Build query - search in both username and email
            query = {"$or": [{"username": search_pattern}, {"email": search_pattern}]}

            # Exclude current user if valid ObjectId
            try:
                if current_user_id and current_user_id != "unknown":
                    user_obj_id = ObjectId(current_user_id)
                    query["_id"] = {"$ne": user_obj_id}
            except:
                # If not a valid ObjectId, try to exclude by string comparison
                query["_id"] = {"$ne": current_user_id}

            # Execute query with projection to only return needed fields
            users_cursor = self.db.users.find(
                query, {"username": 1, "email": 1, "profile_image": 1}
            ).limit(
                50
            )

            user_list = list(users_cursor)
            print(f"MongoDB query found {len(user_list)} users")
            return user_list

        except Exception as e:
            print(f" MongoDB search error: {str(e)}")
            import traceback

            traceback.print_exc()
            return []

    def send_auth_error(self):
        """Send authentication error response"""
        self.send_json_response(
            HTTPStatus.UNAUTHORIZED,
            {"success": False, "error": "Authentication required"},
        )

    def validate_token(self, token):
        """Validate JWT token"""
        try:
            jwt_secret = Config.JWT_SECRET_KEY

            # Decode and verify the token
            payload = jwt.decode(token, jwt_secret, algorithms=["HS256"])

            # Check if token is expired
            if "exp" in payload:
                expiration = datetime.fromtimestamp(payload["exp"])
                if datetime.now() > expiration:
                    print("Token has expired")
                    return False

            print(f"Token validated for user: {payload.get('username')}")
            return True

        except jwt.ExpiredSignatureError:
            print("Token expired")
            return False
        except jwt.InvalidTokenError as e:
            print(f"Invalid token: {e}")
            # Check if this is a signature verification error
            if "signature" in str(e).lower():
                print(
                    " JWT SECRET KEY MISMATCH! Check your .env file and restart the server."
                )
                print(f"Current secret: {Config.JWT_SECRET_KEY[:10]}...")
            return False
        except Exception as e:
            print(f"Token validation error: {e}")
            return False

    def send_cors_headers(self):
        """Send CORS headers to allow requests from frontend"""
        self.send_header("Access-Control-Allow-Origin", "http://localhost:3000")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization, Accept")
        self.send_header("Access-Control-Allow-Credentials", "true")

    def handle_send_message(self, post_data_str):
        try:
            print(f"=== HANDLE_SEND_MESSAGE CALLED ===")

            # Validate authentication
            auth_header = self.headers.get("Authorization", "")
            if not auth_header.startswith("Bearer "):
                self.send_auth_error()
                return

            token = auth_header[7:]
            if not self.validate_token(token):
                self.send_auth_error()
                return

            # Parse the message data
            try:
                data = json.loads(post_data_str)
                print(f"DEBUG parsed data: {data}")
            except json.JSONDecodeError:
                self.send_error_response(HTTPStatus.BAD_REQUEST, "Invalid JSON")
                return

            # Get current user from token for sender_id
            try:
                jwt_secret = Config.JWT_SECRET_KEY
                payload = jwt.decode(token, jwt_secret, algorithms=["HS256"])
                current_user_id = payload.get("_id")
                print(f" Current user ID from token: {current_user_id}")
            except Exception as e:
                print(f" Error decoding token: {e}")
                self.send_auth_error()
                return

            # Use current user from token as sender_id, not from request body
            message_data = data
            message_data["sender_id"] = current_user_id

            print(f" Final message data: {message_data}")

            # Validate required fields - UPDATED FOR E2EE
            required_fields = ["sender_id", "receiver_id", "encrypted_content"]
            for field in required_fields:
                if field not in message_data:
                    print(f"Missing field: {field}")
                    self.send_error_response(
                        HTTPStatus.BAD_REQUEST, f"Missing required field: {field}"
                    )
                    return

            #  E2EE: Store encrypted content directly - NO SERVER DECRYPTION
            message_doc = {
                "sender_id": message_data["sender_id"],
                "receiver_id": message_data["receiver_id"],
                "encrypted_content": message_data["encrypted_content"],  # Already encrypted by client
                "timestamp": datetime.now().isoformat(),
                "status": "sent",
            }

            # Add file data if present (file content should also be encrypted)
            if "file" in message_data and message_data["file"]:
                message_doc["file"] = message_data["file"]

            # Insert into MongoDB
            result = self.db.messages.insert_one(message_doc)
            message_doc["_id"] = result.inserted_id

            print(f" Encrypted message saved with ID: {result.inserted_id}")

            # Return success response
            self.send_json_response(
                HTTPStatus.OK,
                {
                    "success": True,
                    "message": "Encrypted message sent successfully",
                    "message_id": str(result.inserted_id),
                    "sender_id": message_doc["sender_id"],
                    "receiver_id": message_doc["receiver_id"],
                },
            )

        except Exception as e:
            print(f"Send message error: {str(e)}")
            import traceback
            traceback.print_exc()
            self.send_error_response(
                HTTPStatus.INTERNAL_SERVER_ERROR, f"Failed to send message: {str(e)}"
            )

    def handle_get_messages(self, user_id):
        try:
            print(f" Fetching ENCRYPTED messages for target user: {user_id}")

            # Validate authentication
            auth_header = self.headers.get("Authorization", "")
            if not auth_header.startswith("Bearer "):
                self.send_auth_error()
                return

            token = auth_header[7:]
            if not self.validate_token(token):
                self.send_auth_error()
                return

            # Get current user from token
            try:
                jwt_secret = Config.JWT_SECRET_KEY
                payload = jwt.decode(token, jwt_secret, algorithms=["HS256"])
                current_user_id = payload.get("_id")
                print(f" Current user from token: {current_user_id}")
            except:
                self.send_error_response(HTTPStatus.UNAUTHORIZED, "Invalid token")
                return

            # Debug: Print the query details
            print(f" Looking for messages between: {current_user_id} (me) and {user_id} (them)")

            query = {
                "$or": [
                    {"sender_id": current_user_id, "receiver_id": user_id},
                    {"sender_id": user_id, "receiver_id": current_user_id},
                ]
            }

            print(f"MongoDB query:", query)

            # Fetch messages - RETURN ENCRYPTED CONTENT AS-IS
            messages = list(
                self.db.messages.find(
                    query,
                    {
                        "file.content": 0,  # Exclude the actual file content
                        "file.data": 0,     # Exclude any other binary data
                    },
                ).sort("timestamp", 1)
            )

            print(f" Found {len(messages)} encrypted messages")

            # Convert ObjectId to string AND datetime to ISO string
            for message in messages:
                message["_id"] = str(message["_id"])

                # Convert datetime objects to ISO format strings
                if "timestamp" in message and isinstance(message["timestamp"], datetime):
                    message["timestamp"] = message["timestamp"].isoformat()

                # Also check for any other datetime fields
                for key, value in message.items():
                    if isinstance(value, datetime):
                        message[key] = value.isoformat()

                #  E2EE: Ensure we don't accidentally decrypt on server
                # The encrypted_content field is returned as-is to client for decryption
                if 'content' in message and 'encrypted_content' not in message:
                    # Legacy message - move to encrypted_content
                    message['encrypted_content'] = {
                        'ciphertext': message['content'],
                        'iv': '',  # No IV for legacy messages
                        'algo': 'legacy'
                    }
                    del message['content']

            print(f" Sending {len(messages)} ENCRYPTED messages to frontend for decryption")

            self.send_json_response(
                HTTPStatus.OK, {"success": True, "messages": messages}
            )

        except Exception as e:
            print(f" Error fetching messages: {str(e)}")
            import traceback
            traceback.print_exc()
            self.send_error_response(
                HTTPStatus.INTERNAL_SERVER_ERROR, f"Error fetching messages: {str(e)}"
            )

    def handle_delete_message(self, message_id):
        """DELETE /api/messages/{message_id} - Delete a specific message"""
        try:
            print(f" Handling delete message request for: {message_id}")
            
            # Validate authentication
            auth_header = self.headers.get('Authorization', '')
            if not auth_header.startswith('Bearer '):
                self.send_auth_error()
                return
                
            token = auth_header[7:]
            payload = self.validate_token_and_get_payload(token)
            if not payload:
                self.send_auth_error()
                return

            user_id = payload.get('_id')
            if not user_id:
                self.send_error_response(HTTPStatus.BAD_REQUEST, "Invalid user ID in token")
                return

            # Validate message_id
            if not message_id:
                self.send_error_response(HTTPStatus.BAD_REQUEST, "Message ID is required")
                return

            try:
                # Find the message first to verify ownership
                message = self.db.messages.find_one({"_id": ObjectId(message_id)})
                
                if not message:
                    self.send_error_response(HTTPStatus.NOT_FOUND, "Message not found")
                    return

                # Check if user is authorized to delete this message
                # Users can only delete their own sent messages or messages they received
                sender_id = message.get('sender_id')
                receiver_id = message.get('receiver_id')
                
                normalized_user_id = self.normalize_user_id(user_id)
                normalized_sender_id = self.normalize_user_id(sender_id)
                normalized_receiver_id = self.normalize_user_id(receiver_id)
                
                if normalized_user_id not in [normalized_sender_id, normalized_receiver_id]:
                    self.send_error_response(HTTPStatus.FORBIDDEN, "Not authorized to delete this message")
                    return

                # Delete the message
                result = self.db.messages.delete_one({"_id": ObjectId(message_id)})
                
                if result.deleted_count == 1:
                    print(f" Message {message_id} deleted successfully")
                    
                    # Also delete associated files from uploads directory if they exist
                    if message.get('file') and message['file'].get('url'):
                        self._cleanup_message_files(message)
                    
                    self.send_json_response(HTTPStatus.OK, {
                        "success": True,
                        "message": "Message deleted successfully",
                        "deleted_id": message_id
                    })
                else:
                    self.send_error_response(HTTPStatus.NOT_FOUND, "Message not found or already deleted")

            except InvalidId:
                self.send_error_response(HTTPStatus.BAD_REQUEST, "Invalid message ID format")
                
        except Exception as e:
            print(f" Delete message error: {e}")
            self.send_error_response(HTTPStatus.INTERNAL_SERVER_ERROR, "Error deleting message")

    def do_DELETE(self):
        """Handle DELETE requests"""
        try:
            parsed_path = urlparse(self.path)
            path = parsed_path.path

            print(f" DELETE request for: {path}")

            # Handle message deletion
            if path.startswith("/api/messages/"):
                message_id = path.split("/")[-1]
                self.handle_delete_message(message_id)
                return
            elif path == "/api/profile/delete":
                self.handle_delete_profile()
                return
            else:
                self.send_error_response(HTTPStatus.NOT_FOUND, "Endpoint not found")
                
        except Exception as e:
            print(f"DELETE error: {str(e)}")
            self.send_error_response(HTTPStatus.INTERNAL_SERVER_ERROR, f"Server error: {str(e)}")

    def _cleanup_message_files(self, message):
        """Clean up physical files associated with a message"""
        try:
            file_data = message.get('file', {})
            
            # Handle stego files
            if file_data.get('stego_url'):
                file_path = self._extract_file_path(file_data['stego_url'])
                if file_path and os.path.exists(file_path):
                    os.remove(file_path)
                    print(f" Deleted stego file: {file_path}")
            
            # Handle original files
            if file_data.get('original_url'):
                file_path = self._extract_file_path(file_data['original_url'])
                if file_path and os.path.exists(file_path):
                    os.remove(file_path)
                    print(f" Deleted original file: {file_path}")
                    
            # Handle file URL
            if file_data.get('url'):
                file_path = self._extract_file_path(file_data['url'])
                if file_path and os.path.exists(file_path):
                    os.remove(file_path)
                    print(f" Deleted file: {file_path}")
                    
        except Exception as e:
            print(f"️ Error cleaning up message files: {e}")

    def _extract_file_path(self, url):
        """Extract file path from URL"""
        try:
            if url.startswith('/uploads/'):
                return url[1:]  # Remove leading slash
            elif 'uploads/' in url:
                # Extract path from full URL
                parts = url.split('uploads/')
                if len(parts) > 1:
                    return 'uploads/' + parts[1]
            return None
        except:
            return None

    def normalize_user_id(self, user_id):
        """Normalize user ID for comparison"""
        if not user_id:
            return None
        if isinstance(user_id, ObjectId):
            return str(user_id)
        return str(user_id)

    def handle_login(self, post_data_str):
        try:
            data = json.loads(post_data_str)
            username = data.get("username", "").strip()
            password = data.get("password", "")

            print(f"Login attempt for username: '{username}'")

            if not username or not password:
                print("Missing username or password")
                self.send_json_response(
                    400,
                    {"success": False, "error": "Username and password are required"},
                )
                return

            # Check if user exists
            user = self.db.users.find_one({"username": username})

            if user:
                print(f" User found: {user['username']}")
                stored_password = user.get("password", "")
                
                # Verify password using bcrypt
                try:
                    password_matches = bcrypt.checkpw(
                        password.encode("utf-8"), 
                        stored_password.encode("utf-8") if isinstance(stored_password, str) else stored_password
                    )
                    print(f" Password verification result: {password_matches}")
                except Exception as bcrypt_error:
                    print(f" BCrypt error: {bcrypt_error}")
                    password_matches = False
            else:
                print(f" User not found: {username}")
                password_matches = False

            if user and password_matches:
                print("Login successful")

                jwt_secret = Config.JWT_SECRET_KEY
                jwt_payload = {
                    "_id": str(user["_id"]),
                    "username": user["username"],
                    "exp": datetime.now() + timedelta(hours=24),
                }

                try:
                    real_token = jwt.encode(jwt_payload, jwt_secret, algorithm="HS256")
                    print(f"Generated JWT token: {real_token}")

                    self.send_json_response(
                        200,
                        {
                            "success": True,
                            "token": real_token,
                            "user": {
                                "id": str(user["_id"]),
                                "username": user["username"],
                                "email": user["email"],
                            },
                        },
                    )
                except Exception as jwt_error:
                    print(f"JWT generation error: {jwt_error}")
                    self.send_json_response(
                        500, {"success": False, "error": "Token generation failed"}
                    )

            else:
                print("Login failed - invalid credentials")
                self.send_json_response(
                    401, {"success": False, "error": "Invalid username or password"}
                )

        except Exception as e:
            print(f"Login error: {str(e)}")
            import traceback

            traceback.print_exc()
            self.send_json_response(
                500, {"success": False, "error": "Login failed due to server error"}
            )

    def handle_register(self, post_data_str):
        """Handle user registration"""
        try:
            data = json.loads(post_data_str)
            username = data.get("username", "").strip()
            email = data.get("email", "").strip()
            password = data.get("password", "")

            print(f"Registration attempt for username: {username}, email: {email}")
            
            # Hash the password with bcrypt
            hashed_password = bcrypt.hashpw(
                password.encode("utf-8"), 
                bcrypt.gensalt()
            ).decode("utf-8")
            
            if not username or not email or not password:
                self.send_json_response(
                    HTTPStatus.BAD_REQUEST,
                    {"success": False, "error": "All fields are required"},
                )
                return

            # Check if user already exists
            if self.db.users.find_one({"$or": [{"username": username}]}):
                self.send_json_response(
                    HTTPStatus.BAD_REQUEST,
                    {"success": False, "error": "Username already exists"},
                )
                return

            user_data = {
                "username": username,
                "email": email,
                "password": hashed_password,
                "mobile": data.get("mobile", ""),
                "created_at": datetime.now(),
            }

            result = self.db.users.insert_one(user_data)

            # Generate proper JWT token for registration too
            jwt_secret = Config.JWT_SECRET_KEY
            jwt_payload = {
                "_id": str(result.inserted_id),
                "username": username,
                "exp": datetime.utcnow() + timedelta(hours=24),
            }
            real_token = jwt.encode(jwt_payload, jwt_secret, algorithm="HS256")

            self.send_json_response(
                HTTPStatus.OK,
                {
                    "success": True,
                    "token": real_token,  #  Use real token instead of mock
                    "user": {
                        "id": str(result.inserted_id),
                        "username": username,
                        "email": email,
                    },
                },
            )

        except Exception as e:
            print(f"Registration error: {str(e)}")
            self.send_json_response(
                HTTPStatus.INTERNAL_SERVER_ERROR,
                {"success": False, "error": "Registration failed due to server error"},
            )
    
    def handle_delete_profile(self):
        """Handle profile deletion"""
        try:
            print(" Starting profile deletion process...")
            
            # Get token from Authorization header
            auth_header = self.headers.get('Authorization', '')
            if not auth_header.startswith('Bearer '):
                self.send_error_response(HTTPStatus.UNAUTHORIZED, "Missing or invalid authorization token")
                return
                
            token = auth_header.split(' ')[1]
            
            # Verify token and get user
            payload = self.validate_token_and_get_payload(token)
            if not payload:
                self.send_error_response(HTTPStatus.UNAUTHORIZED, "Invalid or expired token")
                return
                
            user_id = payload.get('_id')
            
            print(f" Deleting user account: {user_id}")
            
            # Check if database is available - FIXED: compare with None
            if self.db is None:
                self.send_error_response(HTTPStatus.INTERNAL_SERVER_ERROR, "Database not available")
                return
            
            # Delete user from database
            result = self.db.users.delete_one({'_id': ObjectId(user_id)})
            
            if result.deleted_count == 1:
                print(f" User {user_id} deleted from database")
                
                # Also delete user's messages
                messages_result = self.db.messages.delete_many({
                    '$or': [
                        {'sender_id': user_id},
                        {'receiver_id': user_id}
                    ]
                })
                print(f" Deleted {messages_result.deleted_count} messages")
                
                # Delete user's public keys if collection exists
                try:
                    if hasattr(self.db, 'user_keys'):
                        keys_result = self.db.user_keys.delete_one({'user_id': user_id})
                        print(f" Deleted user's public keys")
                except Exception as keys_error:
                    print(f"️ Could not delete user keys: {keys_error}")
                
                # Delete profile image if exists
                if payload.get('profile_image') and payload['profile_image'] not in ['default.png', 'undefined', 'null']:
                    try:
                        image_path = os.path.join('uploads', 'profile_images', payload['profile_image'])
                        if os.path.exists(image_path):
                            os.remove(image_path)
                            print(f" Deleted profile image: {payload['profile_image']}")
                    except Exception as e:
                        print(f"️ Could not delete profile image: {e}")
                
                self.send_json_response(HTTPStatus.OK, {
                    "success": True,
                    "message": "Account deleted successfully"
                })
            else:
                print(f" User {user_id} not found in database")
                self.send_error_response(HTTPStatus.NOT_FOUND, "User not found")
                
        except Exception as e:
            print(f" Error deleting profile: {str(e)}")
            import traceback
            traceback.print_exc()
            self.send_error_response(HTTPStatus.INTERNAL_SERVER_ERROR, f"Error deleting account: {str(e)}")  
        
    def validate_token(self, token):
        """Validate JWT token"""
        try:
            jwt_secret = Config.JWT_SECRET_KEY

            # Decode and verify the token
            payload = jwt.decode(token, jwt_secret, algorithms=["HS256"])

            # Check if token is expired
            if "exp" in payload:
                expiration = datetime.fromtimestamp(payload["exp"])
                if datetime.utcnow() > expiration:
                    print("Token has expired")
                    return False

            print(f"Token validated for user: {payload.get('username')}")
            return True

        except jwt.ExpiredSignatureError:
            print("Token expired")
            return False
        except jwt.InvalidTokenError as e:
            print(f"Invalid token: {e}")
            return False
        except Exception as e:
            print(f"Token validation error: {e}")
            return False

    def send_json_response(self, status_code, data):
        """Send JSON response with proper headers - IMPROVED"""
        try:
            print(f" Sending JSON response: Status {status_code}")

            # Send HTTP headers
            self.send_response(status_code)
            self.send_cors_headers()
            self.send_header("Content-Type", "application/json")
            self.end_headers()

            # Ensure data is JSON serializable
            def default_serializer(obj):
                if isinstance(obj, (ObjectId, datetime)):
                    return str(obj)
                raise TypeError(f"Object of type {type(obj)} is not JSON serializable")

            try:
                json_data = json.dumps(
                    data, default=default_serializer, ensure_ascii=False
                )
                print(f" JSON payload length: {len(json_data)} characters")

                # Write response in chunks to avoid large data issues
                chunk_size = 8192
                for i in range(0, len(json_data), chunk_size):
                    chunk = json_data[i : i + chunk_size].encode("utf-8")
                    self.wfile.write(chunk)

            except TypeError as e:
                print(f" JSON serialization error: {e}")
                error_response = json.dumps(
                    {
                        "success": False,
                        "error": "Data serialization failed",
                        "details": str(e),
                    }
                )
                self.wfile.write(error_response.encode("utf-8"))

        except BrokenPipeError:
            print("️ Client disconnected during response")
        except Exception as e:
            print(f" Response sending error: {e}")

    def send_error_response(self, status, message):
        """Send error response as JSON"""
        error_data = {
            "success": False,
            "error": message,
            "status": status
        }
        
        self.send_json_response(status, error_data)
    
    def handle_encode_multipart(self, form_data, files):
        """Handle file encoding with multipart form data"""
        try:
            print(f"Encode request received: {form_data}")

            # Validate authentication
            auth_header = self.headers.get("Authorization", "")
            if not auth_header.startswith("Bearer "):
                print("No authorization header found")
                self.send_auth_error()
                return

            token = auth_header[7:]
            if not self.validate_token(token):
                print("Token validation failed")
                self.send_auth_error()
                return

            # Check if file was uploaded
            if "file" not in files:
                print("No file found in request")
                self.send_error_response(HTTPStatus.BAD_REQUEST, "No file provided")
                return

            # Get form data
            message = form_data.get("message", "")
            sender_id = form_data.get("sender_id", "")
            receiver_id = form_data.get("receiver_id", "")
            file_type = form_data.get("file_type", "image")

            print(f"Encoding parameters: message={message}, file_type={file_type}")

            if not message:
                self.send_error_response(HTTPStatus.BAD_REQUEST, "Message is required")
                return

            # Get the uploaded file
            file_data = files["file"]
            file_content = file_data["content"]
            filename = file_data["filename"]

            print(f"Encoding file: {filename}, size: {len(file_content)} bytes")

            # Convert to PIL Image
            try:
                image = Image.open(io.BytesIO(file_content))
                print(f"Image opened successfully: {image.size}, mode: {image.mode}")

                # Your steganography encoding logic here
                encoded_image = self.simple_encode(image, message)

                # Save encoded image to bytes
                output_buffer = io.BytesIO()

                if file_type.lower() == "image":
                    encoded_image.save(output_buffer, format="PNG")
                else:
                    # For other file types, just return the original for now
                    output_buffer = io.BytesIO(file_content)

                encoded_data = output_buffer.getvalue()
                encoded_base64 = base64.b64encode(encoded_data).decode("utf-8")

                print("Encoding successful, sending response")
                self.send_json_response(
                    HTTPStatus.OK,
                    {
                        "success": True,
                        "file_url": f"data:image/png;base64,{encoded_base64}",
                        "stego_url": f"data:image/png;base64,{encoded_base64}",
                        "message": "Encoding successful",
                    },
                )

            except Exception as e:
                print(f"Image processing error: {str(e)}")
                self.send_error_response(
                    HTTPStatus.INTERNAL_SERVER_ERROR,
                    f"Error processing image: {str(e)}",
                )

        except Exception as e:
            print(f"Encode error: {str(e)}")
            self.send_error_response(
                HTTPStatus.INTERNAL_SERVER_ERROR, f"Encoding failed: {str(e)}"
            )

    def handle_decode_multipart(self, form_data, files):
        """Handle file decoding with multipart form data - IMPROVED"""
        try:
            print(" Starting decode process...")

            # Validate authentication
            auth_header = self.headers.get("Authorization", "")
            if not auth_header.startswith("Bearer "):
                self.send_auth_error()
                return

            token = auth_header[7:]
            if not self.validate_token(token):
                self.send_auth_error()
                return

            # Check if file was uploaded
            if "file" not in files:
                self.send_error_response(HTTPStatus.BAD_REQUEST, "No file provided")
                return

            # Get the uploaded file
            file_data = files["file"]
            file_content = file_data["content"]
            filename = file_data["filename"]

            print(f" Decoding file: {filename}, size: {len(file_content)} bytes")

            # Convert to PIL Image and decode
            try:
                image = Image.open(io.BytesIO(file_content))
                print(f" Image loaded: {image.size}, mode: {image.mode}")

                # CHANGE THIS LINE: Use LSB decoding instead of DWT/DCT
                decoded_message = self.decode_image_lsb(image)

                print(f" Decoded message: '{decoded_message}'")

                self.send_json_response(
                    HTTPStatus.OK,
                    {
                        "success": True,
                        "decoded_message": decoded_message,
                        "message": "Decoding completed",
                        "file_info": {
                            "filename": filename,
                            "size": len(file_content),
                            "format": image.format,
                        },
                    },
                )

            except Exception as image_error:
                print(f" Image processing error: {image_error}")
                self.handle_decode_error(f"Image processing failed: {image_error}")

        except Exception as e:
            print(f" Decode endpoint error: {e}")
            self.handle_decode_error(f"Server error: {e}")

    # image processing
    def encode_image_lsb(self, image, message):
        """LSB encoding for images with DYNAMIC KEY"""
        try:
            print(f" Starting LSB encoding with dynamic key")

            # Encrypt with dynamic key
            encrypted_message, dynamic_key = self.encrypt_message(message)
            if not dynamic_key:
                return image

            # Convert key + encrypted message to binary
            key_binary = "".join(format(byte, "08b") for byte in dynamic_key)
            message_binary = "".join(format(ord(char), "08b") for char in encrypted_message)
            
            # Add headers: [key_length(16bits)][key][message_length(32bits)][message]
            key_length_header = format(len(key_binary), "016b")
            message_length_header = format(len(message_binary), "032b")
            full_binary_message = key_length_header + key_binary + message_length_header + message_binary

            print(f"Dynamic key bits: {len(key_binary)}, Message bits: {len(message_binary)}")

            # Your existing LSB embedding code continues...
            img_array = np.array(image.convert("RGB"))
            height, width, channels = img_array.shape
            
            # Embed the full_binary_message using your existing LSB code
            bit_index = 0
            for channel in range(channels):
                for y in range(height):
                    for x in range(width):
                        if bit_index >= len(full_binary_message):
                            break
                        current_bit = int(full_binary_message[bit_index])
                        img_array[y, x, channel] = (img_array[y, x, channel] & 0xFE) | current_bit
                        bit_index += 1

            print(f" Embedded {bit_index} bits with dynamic key")
            return Image.fromarray(img_array.astype(np.uint8))

        except Exception as e:
            print(f" Dynamic LSB encoding error: {e}")
            return image

    def decode_image_lsb(self, image):
        """LSB decoding for images with DYNAMIC KEY"""
        try:
            print(f" Starting LSB decoding with dynamic key")

            # Extract LSBs from all pixels
            img_array = np.array(image.convert("RGB"))
            height, width, channels = img_array.shape
            
            binary_message = ""
            for channel in range(channels):
                for y in range(height):
                    for x in range(width):
                        lsb = img_array[y, x, channel] & 1
                        binary_message += str(lsb)

            print(f"Extracted {len(binary_message)} bits")

            if len(binary_message) < 48:  # Minimum for headers
                return "No message found (insufficient data)"

            # Extract dynamic key (first 16 bits = key length)
            key_length_bits = binary_message[:16]
            key_length = int(key_length_bits, 2)
            
            # Extract key data
            key_binary = binary_message[16:16 + key_length]
            dynamic_key = bytes(int(key_binary[i:i+8], 2) for i in range(0, len(key_binary), 8))
            
            # Extract message length
            msg_length_bits = binary_message[16 + key_length:16 + key_length + 32]
            msg_length = int(msg_length_bits, 2)
            
            # Extract encrypted message
            msg_start = 16 + key_length + 32
            encrypted_binary = binary_message[msg_start:msg_start + msg_length]
            
            # Convert to encrypted string
            encrypted_message = ""
            for i in range(0, len(encrypted_binary), 8):
                if i + 8 <= len(encrypted_binary):
                    byte = encrypted_binary[i:i+8]
                    encrypted_message += chr(int(byte, 2))

            print(f" Extracted encrypted message: {len(encrypted_message)} chars")
            
            # Decrypt with extracted dynamic key
            return self.decrypt_with_key(encrypted_message, dynamic_key)

        except Exception as e:
            print(f" Dynamic LSB decoding error: {e}")
            return f"Decoding error: {str(e)}"
    
    # audio processing
    def encode_audio_lsb(self, audio_data, message):
        """LSB encoding for WAV audio with DYNAMIC AES encryption"""
        try:
            print(f" Starting LSB encoding for audio with dynamic key")
            
            # 1. Encrypt the message with DYNAMIC KEY
            encrypted_message, dynamic_key = self.encrypt_message(message)
            if not dynamic_key:
                return audio_data
                
            print(f" Encrypted with dynamic key: {dynamic_key.hex()[:20]}...")
            
            # 2. Convert KEY + encrypted message to binary with headers
            key_binary = ''.join(format(byte, '08b') for byte in dynamic_key)
            encrypted_binary = ''.join(format(ord(char), '08b') for char in encrypted_message)
            
            # Add headers: [key_length(16bits)][key][message_length(32bits)][message]
            key_length_header = format(len(key_binary), '016b')
            msg_length_header = format(len(encrypted_binary), '032b')
            full_binary_message = key_length_header + key_binary + msg_length_header + encrypted_binary
            
            total_bits = len(full_binary_message)
            print(f"Total bits to embed: {total_bits} (Key: {len(key_binary)}, Message: {len(encrypted_binary)})")
            
            # 3. Read audio data
            audio_buffer = io.BytesIO(audio_data)
            with wave.open(audio_buffer, 'rb') as wav_file:
                params = wav_file.getparams()
                frames = wav_file.readframes(params.nframes)
            
            # 4. Convert to numpy array
            audio_array = np.frombuffer(frames, dtype=np.int16)
            total_samples = len(audio_array)
            
            print(f"Audio samples: {total_samples}, bits to embed: {total_bits}")
            
            # 5. Check if message fits
            if total_bits > total_samples:
                print(f" Message too large for audio capacity")
                return audio_data
            
            # 6. Embed bits using LSB
            audio_modified = audio_array.copy()
            for i in range(total_bits):
                current_bit = int(full_binary_message[i])
                # Preserve the original audio quality by only modifying LSB
                audio_modified[i] = (audio_modified[i] & 0xFFFE) | current_bit
            
            # 7. Convert back to bytes
            modified_frames = audio_modified.tobytes()
            
            # 8. Create new WAV file in memory
            output_buffer = io.BytesIO()
            with wave.open(output_buffer, 'wb') as wav_out:
                wav_out.setparams(params)
                wav_out.writeframes(modified_frames)
            
            print(f" Successfully embedded {total_bits} bits with dynamic key")
            return output_buffer.getvalue()
            
        except Exception as e:
            print(f" Audio LSB encoding error: {e}")
            import traceback
            traceback.print_exc()
            return audio_data
    
    def decode_audio_lsb(self, audio_data):
        """LSB decoding for WAV audio with DYNAMIC AES decryption"""
        try:
            print(f" Starting LSB decoding for audio with dynamic key")
            
            # 1. Read audio data
            audio_buffer = io.BytesIO(audio_data)
            with wave.open(audio_buffer, 'rb') as wav_file:
                params = wav_file.getparams()
                frames = wav_file.readframes(params.nframes)
            
            # 2. Convert to numpy array
            audio_array = np.frombuffer(frames, dtype=np.int16)
            
            print(f"Audio samples: {len(audio_array)}")
            
            # 3. Extract LSBs from all samples
            binary_message = ""
            for sample in audio_array:
                lsb = sample & 1
                binary_message += str(lsb)
            
            print(f"Extracted {len(binary_message)} bits")
            
            # 4. Check if we have enough data for headers
            if len(binary_message) < 48:  # Minimum for key header
                print(" Not enough bits for headers")
                return "No message found"
            
            # 5. Extract DYNAMIC KEY (first 16 bits = key length)
            key_length_bits = binary_message[:16]
            key_length = int(key_length_bits, 2)
            
            # 6. Extract key data
            key_binary = binary_message[16:16 + key_length]
            dynamic_key = bytes(int(key_binary[i:i+8], 2) for i in range(0, len(key_binary), 8))
            
            # 7. Extract message length
            msg_length_bits = binary_message[16 + key_length:16 + key_length + 32]
            msg_length = int(msg_length_bits, 2)
            
            # 8. Extract encrypted message
            msg_start = 16 + key_length + 32
            encrypted_binary = binary_message[msg_start:msg_start + msg_length]
            
            # 9. Convert to encrypted string
            encrypted_message = ""
            for i in range(0, len(encrypted_binary), 8):
                if i + 8 <= len(encrypted_binary):
                    byte = encrypted_binary[i:i+8]
                    encrypted_message += chr(int(byte, 2))

            print(f" Extracted encrypted message: {len(encrypted_message)} chars")
            print(f" Using dynamic key: {dynamic_key.hex()[:20]}...")
            
            # 10. Decrypt with EXTRACTED DYNAMIC KEY
            if encrypted_message:
                decrypted = self.decrypt_message(encrypted_message, dynamic_key)
                if decrypted and not decrypted.startswith("Decryption failed"):
                    return decrypted
                else:
                    print(f" Dynamic decryption failed")
                    return "Decryption failed"
            
            return "No valid message found"
            
        except Exception as e:
            print(f" Audio LSB decoding error: {e}")
            import traceback
            traceback.print_exc()
            return f"Decoding error: {str(e)}"
    
    def handle_encode_audio(self, form_data, files):
        """Handle audio encoding specifically"""
        try:
            print(f" Audio encode request received")
            
            # Validate authentication
            auth_header = self.headers.get('Authorization', '')
            if not auth_header.startswith('Bearer '):
                self.send_auth_error()
                return
                
            token = auth_header[7:]
            if not self.validate_token(token):
                self.send_auth_error()
                return

            # Check if file was uploaded
            if 'file' not in files:
                self.send_error_response(HTTPStatus.BAD_REQUEST, 'No audio file provided')
                return

            # Get form data
            message = form_data.get('message', '')
            if not message:
                self.send_error_response(HTTPStatus.BAD_REQUEST, 'Message is required')
                return

            # Get the uploaded audio file
            file_data = files['file']
            file_content = file_data['content']
            filename = file_data['filename']

            print(f" Encoding audio: {filename}, size: {len(file_content)} bytes")

            # Check if it's a WAV file
            if not filename.lower().endswith('.wav'):
                self.send_error_response(HTTPStatus.BAD_REQUEST, 'Only WAV files are supported for audio steganography')
                return

            # Encode the audio
            try:
                encoded_audio = self.encode_audio_lsb(file_content, message)
                
                # Return the encoded audio as base64
                encoded_base64 = base64.b64encode(encoded_audio).decode('utf-8')
                
                self.send_json_response(HTTPStatus.OK, {
                    'success': True,
                    'file_url': f'data:audio/wav;base64,{encoded_base64}',
                    'stego_url': f'data:audio/wav;base64,{encoded_base64}',
                    'message': 'Audio encoding successful',
                    'file_type': 'audio'
                })
                
            except Exception as e:
                print(f" Audio encoding error: {str(e)}")
                self.send_error_response(HTTPStatus.INTERNAL_SERVER_ERROR, f'Error processing audio: {str(e)}')

        except Exception as e:
            print(f" Audio encode error: {str(e)}")
            self.send_error_response(HTTPStatus.INTERNAL_SERVER_ERROR, f'Audio encoding failed: {str(e)}')

    def handle_decode_audio(self, form_data, files):
        """Handle audio decoding specifically"""
        try:
            print(" Starting audio decode process...")

            # Validate authentication
            auth_header = self.headers.get('Authorization', '')
            if not auth_header.startswith('Bearer '):
                self.send_auth_error()
                return
                
            token = auth_header[7:]
            if not self.validate_token(token):
                self.send_auth_error()
                return

            # Check if file was uploaded
            if 'file' not in files:
                self.send_error_response(HTTPStatus.BAD_REQUEST, 'No audio file provided')
                return

            # Get the uploaded audio file
            file_data = files['file']
            file_content = file_data['content']
            filename = file_data['filename']

            print(f" Decoding audio: {filename}, size: {len(file_content)} bytes")

            # Check if it's a WAV file
            if not filename.lower().endswith('.wav'):
                self.send_error_response(HTTPStatus.BAD_REQUEST, 'Only WAV files are supported for audio steganography')
                return

            # Decode the audio
            try:
                decoded_message = self.decode_audio_lsb(file_content)
                
                self.send_json_response(HTTPStatus.OK, {
                    'success': True,
                    'decoded_message': decoded_message,
                    'message': 'Audio decoding completed',
                    'file_info': {
                        'filename': filename,
                        'size': len(file_content),
                        'type': 'audio/wav'
                    }
                })
                
            except Exception as audio_error:
                print(f" Audio processing error: {audio_error}")
                self.send_error_response(HTTPStatus.INTERNAL_SERVER_ERROR, f'Audio processing failed: {audio_error}')
                
        except Exception as e:
            print(f" Audio decode endpoint error: {e}")
            self.send_error_response(HTTPStatus.INTERNAL_SERVER_ERROR, f'Server error: {e}')
    
    # video processing   
    def encrypt_message_for_video(self, message):
        """Video-specific encryption that includes IV"""
        try:
            # Use your existing encryption first (for compatibility)
            encrypted = self.encrypt_message(message)
            
            # If it's already working format, return as-is
            if not encrypted.startswith("Error"):
                return encrypted
                
            # If main encryption fails, use video-specific method
            iv = os.urandom(16)
            cipher = AES.new(self.encryption_key, AES.MODE_CBC, iv)
            
            # Pad and encrypt
            padded_data = np.pad(message.encode(), AES.block_size)
            encrypted_data = cipher.encrypt(padded_data)
            
            # Return IV + encrypted data
            return base64.b64encode(iv + encrypted_data).decode('utf-8')
            
        except Exception as e:
            print(f" Video encryption error: {e}")
            return message
          
    def decrypt_message_for_video(self, encrypted_message):
        """Video-specific decryption that handles IV"""
        try:
            # First try your existing decryption (for compatibility)
            try:
                result = self.decrypt_message(encrypted_message)
                if not result.startswith("Decryption failed"):
                    return result
            except:
                pass
                
            # If main decryption fails, try video-specific method
            from Crypto.Util.Padding import unpad  # ADD THIS IMPORT
            import base64
            
            encrypted_data = base64.b64decode(encrypted_message)
            
            # Check if message has IV (should be at least 16 bytes IV + some data)
            if len(encrypted_data) < 20:  # IV + minimum encrypted data
                return "Message too short for decryption"
                
            # Extract IV (first 16 bytes) and encrypted data
            iv = encrypted_data[:16]
            actual_encrypted = encrypted_data[16:]
            
            # Decrypt with IV
            from Crypto.Cipher import AES  # ADD THIS IMPORT
            cipher = AES.new(self.encryption_key, AES.MODE_CBC, iv)
            decrypted_padded = cipher.decrypt(actual_encrypted)
            
            # Remove padding - FIXED: use unpad instead of unpadder
            decrypted = unpad(decrypted_padded, AES.block_size)
            
            return decrypted.decode('utf-8')
            
        except Exception as e:
            print(f" Video decryption error: {e}")
            return f"Decryption failed: {str(e)}"       
          
    def encode_video_with_encryption(self, video_data, message):
        """Video encoding with AES encryption - SIMPLIFIED & RELIABLE"""
        import time
        start_time = time.time()
        
        try:
            print(f" Starting video decoding")
            step_start = time.time()
            print(f" Starting video encoding with encryption")
            
            # 1. Encrypt the message
            encrypted_message = self.encrypt_message_for_video(message)
            print(f" Encrypted message for video: '{encrypted_message}'")
            
            # 2. Create temporary files
            with tempfile.NamedTemporaryFile(suffix='.mp4', delete=False) as temp_input:
                temp_input.write(video_data)
                input_path = temp_input.name
                
            print(f"⏰ File setup: {time.time() - step_start:.2f}s")
            step_start = time.time()
            
            output_path = input_path + '_output.mp4'
            audio_path = input_path + '_audio.wav'
            
            # 3. Extract audio using subprocess
            import subprocess
            result = subprocess.run([
                'ffmpeg', '-i', input_path,
                '-vn', '-acodec', 'pcm_s16le',
                '-ar', '44100', '-ac', '2',
                '-y', audio_path
            ], capture_output=True, timeout=30)
            
            print(f"⏰ Audio extraction: {time.time() - step_start:.2f}s")
            step_start = time.time()
            
            if result.returncode != 0:
                print(f" FFmpeg error: {result.stderr.decode()}")
                return video_data
            
            # 4. Encode message in audio
            with open(audio_path, 'rb') as f:
                audio_data = f.read()
            
            encoded_audio = self.encode_audio_lsb(audio_data, encrypted_message)
            
            # 5. Save encoded audio
            encoded_audio_path = input_path + '_encoded_audio.wav'
            with open(encoded_audio_path, 'wb') as f:
                f.write(encoded_audio)
            
            # 6. Replace audio in video
            result = subprocess.run([
                'ffmpeg',
                '-i', input_path,          # Original video
                '-i', encoded_audio_path,  # New audio
                '-c:v', 'copy',            # Copy video without re-encoding
                '-c:a', 'aac',             # Encode audio to AAC
                '-map', '0:v:0',           # Video from first input
                '-map', '1:a:0',           # Audio from second input
                '-shortest',               # Use shortest duration
                '-y', output_path          # Output file
            ], capture_output=True, timeout=30)
            
            if result.returncode != 0:
                print(f" FFmpeg muxing error: {result.stderr.decode()}")
                return video_data
            
            # 7. Read result
            with open(output_path, 'rb') as f:
                encoded_video = f.read()
            
            print(f" Video encoding successful")
            
            decoded_message = self.decode_audio_lsb(audio_data)
        
            print(f"⏰ Audio decoding: {time.time() - step_start:.2f}s")
            print(f" Total decoding time: {time.time() - start_time:.2f}s")
            
            # 8. Cleanup
            for path in [input_path, audio_path, encoded_audio_path, output_path]:
                try:
                    os.unlink(path)
                except:
                    pass
            
            return encoded_video
            
        except subprocess.TimeoutExpired:
            print(" Video encoding timeout")
            return video_data
        except Exception as e:
            print(f" Video encoding error: {e}")
            return video_data
        
    def decode_video_with_decryption(self, video_data):
        """Video decoding with AES decryption - FIXED"""
        try:
            print(f" Starting video decoding with decryption")
            
            # 1. Create temporary file
            with tempfile.NamedTemporaryFile(suffix='.mp4', delete=False) as temp_file:
                temp_file.write(video_data)
                input_path = temp_file.name
            
            audio_path = input_path + '_audio.wav'
            
            # 2. Extract audio using subprocess
            import subprocess
            result = subprocess.run([
                'ffmpeg', '-i', input_path,
                '-vn', '-acodec', 'pcm_s16le',
                '-ar', '44100', '-ac', '2',
                '-y', audio_path
            ], capture_output=True, timeout=30)
            
            if result.returncode != 0:
                print(f" FFmpeg error: {result.stderr.decode()}")
                return "Error extracting audio"
            
            # 3. Read audio and decode
            with open(audio_path, 'rb') as f:
                audio_data = f.read()
            
            # This returns the ENCRYPTED message
            encrypted_message = self.decode_audio_lsb(audio_data)
            
            print(f" Extracted encrypted message: {encrypted_message}")
            
            # 4. DECRYPT the message (THIS WAS MISSING!)
            decrypted_message = self.decrypt_message(encrypted_message)
            
            print(f" Decrypted message: {decrypted_message}")
            
            # 5. Cleanup
            for path in [input_path, audio_path]:
                try:
                    os.unlink(path)
                except:
                    pass
            
            return decrypted_message
            
        except subprocess.TimeoutExpired:
            print(" Video decoding timeout")
            return "Decoding timeout"
        except Exception as e:
            print(f" Video decoding error: {e}")
            return f"Decoding error: {str(e)}"
            
    def handle_encode_video(self, form_data, files):
        """Handle video encoding with detailed debugging"""
        try:
            print(f" Video encode request received - START")
            
            # 1. Authentication
            auth_header = self.headers.get('Authorization', '')
            print(f" Auth header: {auth_header}")
            if not auth_header.startswith('Bearer '):
                print(" No bearer token")
                self.send_auth_error()
                return
                
            token = auth_header[7:]
            if not self.validate_token(token):
                print(" Invalid token")
                self.send_auth_error()
                return

            # 2. Validation
            if 'file' not in files:
                print(" No file in request")
                self.send_error_response(HTTPStatus.BAD_REQUEST, 'No video file provided')
                return

            message = form_data.get('message', '')
            if not message:
                print(" No message in request")
                self.send_error_response(HTTPStatus.BAD_REQUEST, 'Message is required')
                return

            # 3. Get file data
            file_data = files['file']
            file_content = file_data['content']
            file_size = len(file_content)
            filename = file_data['filename']

            print(f" File: {filename}, Size: {file_size} bytes, Message: {message}")

            # 4. Size limit
            MAX_SIZE = 10 * 1024 * 1024
            if file_size > MAX_SIZE:
                print(f" File too large: {file_size} > {MAX_SIZE}")
                self.send_json_response(HTTPStatus.BAD_REQUEST, {
                    'success': False,
                    'message': 'Video too large. Maximum size is 10MB',
                    'max_size': MAX_SIZE,
                    'your_size': file_size
                })
                return

            print(" Validation passed, starting encoding...")
            
            # 5. SIMPLIFIED - No threading, just direct call
            encoded_video = self.encode_video_with_encryption(file_content, message)
            
            if encoded_video is None or encoded_video == file_content:
                print(" Encoding failed - no change or error")
                self.send_error_response(HTTPStatus.INTERNAL_SERVER_ERROR, 'Video encoding failed')
                return
            
            print(" Encoding completed successfully")
                
            # 6. Return success response
            encoded_base64 = base64.b64encode(encoded_video).decode('utf-8')
            
            response_data = {
                'success': True,
                'file_url': f'data:video/mp4;base64,{encoded_base64}',
                'stego_url': f'data:video/mp4;base64,{encoded_base64}',
                'message': 'Video encoding successful',
                'file_size': len(encoded_video),
                'original_size': file_size
            }
            
            print(" Sending response...")
            self.send_json_response(HTTPStatus.OK, response_data)
            print(" Response sent successfully")
            
        except Exception as e:
            print(f" Video encode error: {str(e)}")
            import traceback
            traceback.print_exc()
            self.send_error_response(HTTPStatus.INTERNAL_SERVER_ERROR, f'Video encoding failed: {str(e)}')                
        
    def handle_decode_video(self, form_data, files):
        """Handle video decoding requests"""
        try:
            print(" Starting video decode process...")

            # 1. Authentication
            auth_header = self.headers.get('Authorization', '')
            if not auth_header.startswith('Bearer '):
                self.send_auth_error()
                return
                
            token = auth_header[7:]
            if not self.validate_token(token):
                self.send_auth_error()
                return

            # 2. Validation
            if 'file' not in files:
                self.send_error_response(HTTPStatus.BAD_REQUEST, 'No video file provided')
                return

            # 3. Get file data
            file_data = files['file']
            file_content = file_data['content']
            filename = file_data['filename']

            print(f" Decoding video: {filename}, size: {len(file_content)} bytes")

            # 4. Decode video with decryption
            decoded_message = self.decode_video_with_decryption(file_content)
            
            # 5. Return result
            self.send_json_response(HTTPStatus.OK, {
                'success': True,
                'decoded_message': decoded_message,
                'message': 'Video decoding completed',
                'file_info': {
                    'filename': filename,
                    'size': len(file_content),
                    'type': 'video/mp4'
                }
            })
            
        except Exception as e:
            print(f" Video decode error: {e}")
            self.send_error_response(HTTPStatus.INTERNAL_SERVER_ERROR, f'Video decoding failed: {e}')
          
    def simple_encode(self, image, message):
        try:
            print(f"Encoding message using LSB: '{message}'")
            encoded_image = self.encode_image_lsb(image, message)

            # Verify the encoding worked by trying to decode immediately
            try:
                test_decode = self.decode_image_lsb(encoded_image)
                print(f" Encoding verification: '{test_decode}'")
            except Exception as test_error:
                print(f"️ Encoding verification failed: {test_error}")

            return encoded_image
        except Exception as e:
            print(f" LSB encoding failed: {e}")
            import traceback

            traceback.print_exc()
            return image

    def simple_decode(self, image):
        try:
            result = self.decode_image_lsb(image)
            print(f"LSB decode result: '{result}'")
            return result
        except Exception as e:
            print(f" LSB decoding failed: {e}")
            import traceback

            traceback.print_exc()
            return f"Error decoding: {str(e)}"

    def encrypt_message(self, message):
        """Encrypt with dynamic key and return (encrypted_data, key)"""
        try:
            if not message or not isinstance(message, str):
                return message, None

            # Generate unique key for this encryption
            dynamic_key = self.generate_dynamic_key()
            iv = get_random_bytes(16)
            cipher = AES.new(dynamic_key, AES.MODE_CBC, iv)

            # Pad and encrypt
            padded_message = self._pad_message(message)
            ciphertext = cipher.encrypt(padded_message)

            # Return IV + ciphertext as base64
            encrypted_data = base64.urlsafe_b64encode(iv + ciphertext).decode("utf-8")
            print(f" Dynamic encryption - Key: {dynamic_key.hex()[:20]}...")
            return encrypted_data, dynamic_key

        except Exception as e:
            print(f" Dynamic encryption error: {e}")
            return message, None
    
    def decrypt_with_key(self, encrypted_message, key):
        """Decrypt using provided dynamic key"""
        try:
            if not encrypted_message or not isinstance(encrypted_message, str):
                return "Invalid encrypted message"

            # Decode base64
            encrypted_data = base64.urlsafe_b64decode(encrypted_message)
            iv = encrypted_data[:16]
            ciphertext = encrypted_data[16:]

            # Decrypt with provided key
            cipher = AES.new(key, AES.MODE_CBC, iv)
            decrypted_padded = cipher.decrypt(ciphertext)
            
            # Remove padding
            decrypted_message = self._unpad_message(decrypted_padded)
            return decrypted_message.decode("utf-8")

        except Exception as e:
            print(f" Dynamic decryption error: {e}")
            return f"Decryption failed: {str(e)}"
    
    def decrypt_message(self, encrypted_message, key):
        """Simple decryption with dynamic key"""
        try:
            if not encrypted_message or not isinstance(encrypted_message, str):
                return "Invalid encrypted message"

            if not key:
                return "Decryption key required"

            print(f" Decrypting with dynamic key: {key.hex()[:20]}...")

            # Decode base64
            encrypted_data = base64.urlsafe_b64decode(encrypted_message)
            iv = encrypted_data[:16]
            ciphertext = encrypted_data[16:]

            # Decrypt
            cipher = AES.new(key, AES.MODE_CBC, iv)
            decrypted_padded = cipher.decrypt(ciphertext)
            
            # Remove padding and return
            decrypted_message = self._unpad_message(decrypted_padded)
            result = decrypted_message.decode("utf-8")
            
            print(f" Decryption successful: '{result}'")
            return result

        except Exception as e:
            print(f" Decryption error: {e}")
            return f"Decryption failed: {str(e)}"

    def _pad_message(self, message):
        """Pad message for AES encryption - PROPER PKCS7 PADDING"""
        try:
            # Convert to bytes if it's a string
            if isinstance(message, str):
                message = message.encode("utf-8")

            block_size = 16
            padding_length = block_size - (len(message) % block_size)

            # Use proper PKCS7 padding: each padding byte equals the padding length
            padding = bytes([padding_length] * padding_length)
            padded_message = message + padding

            print(
                f"Original: {len(message)} bytes, Padded: {len(padded_message)} bytes, Padding: {padding_length} bytes"
            )
            return padded_message

        except Exception as e:
            print(f" Padding error: {e}")
            # Fallback: simple zero padding
            message_bytes = (
                message.encode("utf-8") if isinstance(message, str) else message
            )
            padding_length = 16 - (len(message_bytes) % 16)
            return message_bytes + bytes([0] * padding_length)

    def _unpad_message(self, padded_message):
        """Remove PKCS7 padding from decrypted message - ROBUST"""
        try:
            if not padded_message or len(padded_message) == 0:
                return b""

            # Get the padding length from the last byte
            padding_length = padded_message[-1]

            # Validate padding length (should be between 1 and 16)
            if padding_length < 1 or padding_length > 16:
                print(f"️ Invalid padding length: {padding_length}")
                # Try to auto-detect padding by checking the last few bytes
                for possible_padding in range(1, 17):
                    if len(padded_message) >= possible_padding:
                        # Check if the last 'possible_padding' bytes all equal 'possible_padding'
                        expected_padding = bytes([possible_padding] * possible_padding)
                        if padded_message[-possible_padding:] == expected_padding:
                            print(
                                f" Auto-detected PKCS7 padding: {possible_padding} bytes"
                            )
                            return padded_message[:-possible_padding]

                # If no valid PKCS7 padding found, try to remove common padding patterns
                print("️ No valid PKCS7 padding found, trying fallback unpadding")

                # Remove trailing zeros (common in some implementations)
                unpadded = padded_message.rstrip(b"\x00")
                if len(unpadded) < len(padded_message):
                    print(
                        f" Removed {len(padded_message) - len(unpadded)} zero bytes"
                    )
                    return unpadded

                # Remove any non-printable characters from the end
                for i in range(
                    len(padded_message) - 1, max(0, len(padded_message) - 20), -1
                ):
                    if padded_message[i] < 32 or padded_message[i] > 126:
                        continue
                    else:
                        # Found a printable character, return everything up to this point
                        return padded_message[: i + 1]

                return padded_message  # Return as-is if no padding can be determined

            # Check that all padding bytes are correct (PKCS7 validation)
            expected_padding = bytes([padding_length] * padding_length)
            actual_padding = padded_message[-padding_length:]

            if actual_padding == expected_padding:
                return padded_message[:-padding_length]
            else:
                print(f"️ Padding bytes don't match PKCS7 pattern")
                print(f"   Expected: {expected_padding.hex()}")
                print(f"   Actual: {actual_padding.hex()}")

                # Try to find where the actual message ends
                # Look for the first non-padding byte from the end
                for i in range(len(padded_message) - 1, -1, -1):
                    if padded_message[i] != padding_length:
                        return padded_message[: i + 1]

                return padded_message  # Return original if all bytes seem to be padding

        except Exception as e:
            print(f" Unpadding error: {e}")
            import traceback

            traceback.print_exc()
            # Return the message as-is (might contain some padding)
            return padded_message

        # def encode_image_dwt_dct(self, image, message):
        """DWT + DCT encoding for images - FIXED VERSION"""
        try:
            print(f" Starting DWT+DCT encoding for message: '{message}'")

            # Encrypt the message first
            encrypted_message = self.encrypt_message(message)
            print(f" Encrypted message length: {len(encrypted_message)}")
            print(f" Encrypted message: '{encrypted_message[:100]}...'")

            # Convert message to binary with length header
            binary_message = "".join(
                format(ord(char), "08b") for char in encrypted_message
            )
            message_length = len(binary_message)

            # Add 32-bit length header
            length_header = format(message_length, "032b")
            full_binary_message = length_header + binary_message

            print(f"Message length: {message_length} bits")
            print(f" Total bits to embed: {len(full_binary_message)}")

            # Convert image to numpy array
            img_array = np.array(image.convert("RGB"))
            height, width, _ = img_array.shape
            print(f"Image dimensions: {width}x{height}")

            bit_index = 0
            total_bits = len(full_binary_message)

            # Embed bits in all channels
            for channel in range(3):
                if bit_index >= total_bits:
                    break

                # Apply DWT
                coeffs = pywt.dwt2(img_array[:, :, channel], "haar")
                LL, (LH, HL, HH) = coeffs

                # Apply DCT to LL subband
                LL_dct = fft.dct(
                    fft.dct(LL, axis=0, norm="ortho"), axis=1, norm="ortho"
                )

                # Embed bits in DCT coefficients
                rows, cols = LL_dct.shape
                for i in range(rows):
                    for j in range(cols):
                        if bit_index >= total_bits:
                            break

                        # Get current bit
                        current_bit = int(full_binary_message[bit_index])

                        # Modify LSB of DCT coefficient
                        LL_dct[i, j] = self._set_lsb(LL_dct[i, j], current_bit)
                        bit_index += 1

            # Inverse DCT
            LL_modified = fft.idct(
                fft.idct(LL_dct, axis=0, norm="ortho"), axis=1, norm="ortho"
            )

            # Inverse DWT
            coeffs_modified = (LL_modified, (LH, HL, HH))
            img_array[:, :, channel] = pywt.idwt2(coeffs_modified, "haar")

            print(f" Embedded {bit_index} bits successfully")

            # Convert back to PIL Image
            encoded_image = Image.fromarray(img_array.astype(np.uint8))
            return encoded_image

        except Exception as e:
            print(f" DWT+DCT encoding error: {e}")
            import traceback

            traceback.print_exc()
            return image

        # def encode_image_dwt_dct(self, image, message):
        #     """DWT + DCT encoding for images - COMPLETELY FIXED"""
        #     try:
        #         print(f" Starting DWT+DCT encoding for message: '{message}'")

        #         # Encrypt the message first
        #         encrypted_message = self.encrypt_message(message)
        #         print(f" Encrypted message: '{encrypted_message[:50]}...'")

        #         # Convert message to binary with length header
        #         binary_message = ''.join(format(ord(char), '08b') for char in encrypted_message)
        #         message_length = len(binary_message)

        #         # Add 32-bit length header
        #         length_header = format(message_length, '032b')
        #         full_binary_message = length_header + binary_message

        #         print(f"Message length: {message_length} bits")
        #         print(f" Total bits to embed: {len(full_binary_message)}")

        #         # Convert image to numpy array
        #         img_array = np.array(image.convert('RGB'))
        #         original_shape = img_array.shape
        #         print(f"Image dimensions: {original_shape}")

        #         bit_index = 0
        #         total_bits = len(full_binary_message)

        #         # Process each channel separately
        #         for channel in range(3):
        #             if bit_index >= total_bits:
        #                 break

        #             channel_data = img_array[:, :, channel].astype(np.float32)

        #             # Apply DWT
        #             coeffs = pywt.dwt2(channel_data, 'haar')
        #             LL, (LH, HL, HH) = coeffs

        #             # Apply DCT to LL subband
        #             LL_dct = fft.dct(fft.dct(LL, axis=0, norm='ortho'), axis=1, norm='ortho')

        #             # Embed bits in DCT coefficients
        #             rows, cols = LL_dct.shape
        #             for i in range(rows):
        #                 for j in range(cols):
        #                     if bit_index >= total_bits:
        #                         break

        #                     # Get current bit
        #                     current_bit = int(full_binary_message[bit_index])

        #                     # Modify LSB of DCT coefficient
        #                     original_value = LL_dct[i, j]
        #                     modified_value = self._set_lsb(original_value, current_bit)
        #                     LL_dct[i, j] = modified_value
        #                     bit_index += 1

        #             # Inverse DCT
        #             LL_modified = fft.idct(fft.idct(LL_dct, axis=0, norm='ortho'), axis=1, norm='ortho')

        #             # Inverse DWT - FIXED: Use the modified LL with original LH, HL, HH
        #             coeffs_modified = (LL_modified, (LH, HL, HH))
        #             reconstructed_channel = pywt.idwt2(coeffs_modified, 'haar')

        #             # Ensure the reconstructed channel has the same shape as original
        #             if reconstructed_channel.shape != channel_data.shape:
        #                 # Trim or pad to match original shape
        #                 reconstructed_channel = reconstructed_channel[:channel_data.shape[0], :channel_data.shape[1]]

        #             # Update the image array
        #             img_array[:, :, channel] = reconstructed_channel.astype(np.uint8)

        #         print(f" Embedded {bit_index} bits successfully")

        #         # Convert back to PIL Image
        #         encoded_image = Image.fromarray(img_array)
        #         return encoded_image

        #     except Exception as e:
        #         print(f" DWT+DCT encoding error: {e}")
        #         import traceback
        #         traceback.print_exc()
        #         return image

        # def decode_image_dwt_dct(self, image):
        """DWT + DCT decoding for images - ROBUST VERSION"""
        try:
            print(f" Starting DWT+DCT decoding")

            # Convert image to numpy array
            try:
                img_array = np.array(image.convert("RGB"))
                height, width, channels = img_array.shape
                print(f"Image dimensions: {width}x{height}, channels: {channels}")
            except Exception as img_error:
                print(f" Image conversion error: {img_error}")
                return "Error: Invalid image format"

            binary_message = ""
            extracted_bits = 0
            max_bits_to_extract = 10000  # Increased limit

            print(" Extracting bits from image channels...")

            # Extract bits from all channels
            for channel in range(min(3, channels)):  # Safety check for channel count
                if extracted_bits >= max_bits_to_extract:
                    break

                try:
                    # Apply DWT
                    channel_data = img_array[:, :, channel].astype(np.float32)
                    coeffs = pywt.dwt2(channel_data, "haar")
                    LL, (LH, HL, HH) = coeffs

                    # Apply DCT to LL subband
                    LL_dct = fft.dct(
                        fft.dct(LL, axis=0, norm="ortho"), axis=1, norm="ortho"
                    )

                    # Extract bits from DCT coefficients
                    rows, cols = LL_dct.shape
                    print(f"Channel {channel}: DCT matrix size {rows}x{cols}")

                    for i in range(min(rows, 100)):  # Limit extraction
                        for j in range(min(cols, 100)):
                            if extracted_bits >= max_bits_to_extract:
                                break
                            try:
                                bit = self._get_lsb_robust(LL_dct[i, j])
                                binary_message += str(bit)
                                extracted_bits += 1
                            except Exception as bit_error:
                                print(
                                    f"️ Bit extraction error at ({i},{j}): {bit_error}"
                                )
                                continue

                except Exception as channel_error:
                    print(f"️ Channel {channel} processing error: {channel_error}")
                    continue

            print(f" Total bits extracted: {len(binary_message)}")

            if len(binary_message) < 40:  # Minimum for header + some data
                print(" Not enough bits extracted for decoding")
                return "No message found (insufficient data)"

            # Try to extract message with length header
            try:
                # Extract message length (first 32 bits)
                if len(binary_message) >= 32:
                    length_bits = binary_message[:32]
                    message_length = int(length_bits, 2)
                    print(f"Message length from header: {message_length} bits")

                    # Validate message length
                    if 0 < message_length <= 5000 and (32 + message_length) <= len(
                        binary_message
                    ):
                        message_bits = binary_message[32 : 32 + message_length]

                        # Convert binary to string
                        encrypted_message = ""
                        for i in range(0, len(message_bits), 8):
                            if i + 8 > len(message_bits):
                                break
                            byte = message_bits[i : i + 8]
                            try:
                                char_code = int(byte, 2)
                                if 0 <= char_code <= 255:  # Valid ASCII range
                                    encrypted_message += chr(char_code)
                                else:
                                    print(f"️ Invalid char code: {char_code}")
                            except:
                                continue

                        print(
                            f" Encrypted message extracted: {len(encrypted_message)} chars"
                        )

                        if encrypted_message:
                            # Decrypt with AES
                            decrypted = self.decrypt_message(encrypted_message)
                            if decrypted and not decrypted.startswith(
                                "Decryption failed"
                            ):
                                return decrypted
            except Exception as header_error:
                print(f"️ Header-based extraction failed: {header_error}")

            # Fallback: try to extract without header
            print(" Trying fallback extraction without header...")
            return self._extract_without_length_header(binary_message)

        except Exception as e:
            print(f" DWT+DCT decoding error: {e}")
            import traceback

            traceback.print_exc()
            return f"Decoding error: {str(e)}"

    def _extract_without_length_header(self, binary_message):
        """Simple fallback extraction without length header"""
        try:
            print(
                f" Trying simple fallback extraction from {len(binary_message)} bits"
            )

            # Try different starting positions
            for start_offset in [0, 8, 16, 24, 32]:
                message = ""

                for i in range(start_offset, len(binary_message), 8):
                    if i + 8 > len(binary_message):
                        break

                    byte = binary_message[i : i + 8]

                    try:
                        char_code = int(byte, 2)

                        # Accept printable ASCII characters
                        if 32 <= char_code <= 126:
                            message += chr(char_code)
                        else:
                            # Try to fix single bit errors
                            fixed_char = self._try_fix_single_bit_error(byte)
                            if fixed_char and 32 <= ord(fixed_char) <= 126:
                                message += fixed_char
                            else:
                                continue

                        # Stop if we have enough characters
                        if len(message) >= 50:
                            break

                    except:
                        break

                if message and len(message) >= 5:
                    print(f" Found message: {message[:30]}...")
                    return message

            return "No valid message found"

        except Exception as e:
            print(f" Fallback extraction error: {e}")
            return "No valid message found"

    def _set_lsb(self, value, bit):
        """Set the least significant bit of a value - IMPROVED"""
        try:
            # Handle both float and integer values
            if isinstance(value, float):
                # For DCT coefficients which are floats
                int_value = int(round(value))
                modified_int = (int_value & ~1) | bit
                return float(modified_int)
            else:
                # For integer values
                int_value = int(value)
                return (int_value & ~1) | bit
        except Exception as e:
            print(f" Set LSB error: {e}")
            return value

    def _get_lsb(self, value):
        """Get the least significant bit of a value - IMPROVED"""
        try:
            if isinstance(value, float):
                int_value = int(round(value))
            else:

                int_value = int(value)
            return int_value & 1
        except Exception as e:
            print(f" Get LSB error: {e}")
            return 0

    def _get_lsb_robust(self, value):
        """Get LSB with maximum robustness - ensures exact bit extraction"""
        try:
            if isinstance(value, float):
                # Use the most reliable method: direct bit manipulation on the float's binary representation
                # Convert to integer using the same method as encoding
                int_value = int(round(value))

                # Additional validation: ensure we're in a reasonable range
                if (
                    abs(int_value) > 100000
                ):  # Very large coefficient - might be corrupted
                    print(f"️ Very large DCT coefficient: {value}, using fallback")
                    # Try alternative extraction methods
                    alt_methods = [
                        int(value + 0.5) & 1,
                        int(value) & 1,
                        int(value - 0.5) & 1,
                    ]
                    # Return the most common result
                    return max(set(alt_methods), key=alt_methods.count)

                return int_value & 1
            else:
                int_value = int(value)
                return int_value & 1
        except Exception as e:
            print(f" LSB extraction error: {e}, value: {value}")
            return 0

    def _convert_binary_to_text(self, binary_message):
        """Convert binary message to text with clean error handling"""
        try:
            if len(binary_message) < 8:
                return "No valid message found (too few bits)"

            print(f" Converting {len(binary_message)} bits to text...")

            # Try different starting positions
            for start_offset in [0, 8, 16, 24, 32]:
                message = ""
                valid_chars = 0
                total_chars = 0

                for i in range(start_offset, len(binary_message), 8):
                    if i + 8 > len(binary_message):
                        break

                    byte = binary_message[i : i + 8]
                    try:
                        char_code = int(byte, 2)

                        # Accept printable ASCII characters
                        if 32 <= char_code <= 126:
                            message += chr(char_code)
                            valid_chars += 1
                        else:
                            # Try to fix single bit errors
                            fixed_char = self._try_fix_single_bit_error(byte)
                            if fixed_char and 32 <= ord(fixed_char) <= 126:
                                message += fixed_char
                                valid_chars += 1
                            else:
                                continue

                        total_chars += 1

                        # Stop if we have enough characters
                        if len(message) >= 50:
                            break

                    except:
                        break

                if message and len(message) >= 5:
                    # Check if this looks like a valid message
                    readable_ratio = valid_chars / max(1, total_chars)

                    if readable_ratio > 0.7:  # Mostly readable
                        print(
                            f" Found readable message: {message[:30]}... (ratio: {readable_ratio:.2f})"
                        )
                        return message

            return "No valid message found (no readable text found)"

        except Exception as e:
            print(f" Binary to text conversion error: {e}")
            return "No valid message found (conversion error)"

    def _try_fix_single_bit_error(self, binary_byte):
        """Try to fix single bit errors in a binary byte"""
        try:
            # Try flipping each bit to see if we get a valid character
            for i in range(8):
                # Flip bit at position i
                flipped_byte = (
                    binary_byte[:i]
                    + ("1" if binary_byte[i] == "0" else "0")
                    + binary_byte[i + 1 :]
                )
                try:
                    fixed_code = int(flipped_byte, 2)
                    if 32 <= fixed_code <= 126:  # Printable ASCII
                        return chr(fixed_code)
                except:
                    continue

            # If no single bit fix works, return None
            return None
        except:
            return None

    def _get_lsb_with_redundancy(self, values):
        """Get LSB with redundancy - takes multiple values and uses majority vote"""
        try:
            if not values:
                return 0

            results = []
            for value in values:
                if isinstance(value, float):
                    approaches = [
                        int(round(value)),
                        int(value + 0.5),
                        int(value),
                        int(value - 0.5),
                    ]
                else:
                    approaches = [int(value)]

                for approach in approaches:
                    try:
                        results.append(approach & 1)
                    except:
                        continue

            if results:
                # Return the most common bit across all values
                return max(set(results), key=results.count)
            else:
                return 0
        except:
            return 0

    def handle_get_users(self):
        try:
            users = list(self.db.users.find({}, {"password": 0}).limit(50))
            users_data = [
                {
                    "id": str(user["_id"]),
                    "username": user["username"],
                    "email": user["email"],
                }
                for user in users
            ]

            self.send_json_response(
                HTTPStatus.OK, {"success": True, "users": users_data}
            )
        except Exception as e:
            self.send_error_response(
                HTTPStatus.INTERNAL_SERVER_ERROR, f"Error fetching users: {str(e)}"
            )

    def handle_how_to_use(self):
        self.send_json_response(
            HTTPStatus.OK,
            {
                "success": True,
                "guide": {
                    "title": "Steganography Chat App Guide",
                    "sections": [
                        {
                            "title": "Registration",
                            "content": "Create an account with username, email, and password",
                        },
                        {
                            "title": "Login",
                            "content": "Use your credentials to access the chat features",
                        },
                    ],
                },
            },
        )

    def handle_verify_token(self):
        auth_header = self.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header[7:]
            valid = self.validate_token(token)
            self.send_json_response(HTTPStatus.OK, {"success": True, "valid": valid})
        else:
            self.send_json_response(
                HTTPStatus.UNAUTHORIZED,
                {"success": False, "valid": False, "error": "No token provided"},
            )

def run_http_server(port=8000):
    """Start the HTTP server - BLOCKING version"""
    server_address = ("localhost", port)

    try:
        # Use simple TCPServer (no threading issues)
        httpd = socketserver.TCPServer(server_address, SteganographyRequestHandler)
        print(f" HTTP Server running on http://localhost:{port}...")
        print(f" API endpoints available at http://localhost:{port}/api/")
        print("Press Ctrl+C to stop the server...")

        # Test if server is actually running
        import socket

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        result = sock.connect_ex(("localhost", port))
        if result == 0:
            print(f" Port {port} is open and accepting connections")
        else:
            print(f" Port {port} is not accessible")
        sock.close()

        httpd.serve_forever()

    except OSError as e:
        if e.errno == 10048:  # Address already in use
            print(f" Port {port} is already in use. Trying port {port + 1}...")
            run_http_server(port + 1)
        else:
            print(f" HTTP Server OSError: {e}")
    except KeyboardInterrupt:
        print("\n Shutting down HTTP server gracefully...")
    except Exception as e:
        print(f" HTTP Server error: {e}")

async def main():
    """Main function to run both servers"""
    # Initialize database
    db = DatabaseManager.initialize_database()

    if db is None:
        print(" Failed to initialize database. Exiting.")
        return

    print(" Starting servers...")

    # Start HTTP server in a separate thread (this will block)
    def start_http_server():
        print(" Starting HTTP server on port 8000...")
        try:
            run_http_server(8000)
        except Exception as e:
            print(f" HTTP server failed: {e}")

    http_thread = threading.Thread(target=start_http_server, daemon=True)
    http_thread.start()

    # Give HTTP server time to start
    await asyncio.sleep(2)

    try:
        import requests

        response = requests.get("http://localhost:8000/health", timeout=2)
        if response.status_code == 200:
            print(" HTTP server is running")
        else:
            print(" HTTP server responded with error")
    except:
        print(" HTTP server not responding - check if port 8000 is available")

    # Start WebSocket server with error handling
    print(" Starting WebSocket server on port 8001...")
    try:
        await run_websocket_server(db, 8001)
    except Exception as e:
        print(f"WebSocket server failed: {e}")
        print("ℹHTTP server continues running without WebSocket functionality")
        # Keep the main thread alive so HTTP server continues
        while True:
            await asyncio.sleep(3600)  # Sleep for 1 hour at a time

if __name__ == "__main__":
    # Set event loop policy for Windows if needed
    if os.name == "nt":  # Windows
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nServer shutdown requested by user")
    except Exception as e:
        print(f"Unexpected error: {e}")
    finally:
        print("Server stopped")