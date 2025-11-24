import asyncio
from urllib.parse import parse_qs, urlparse
import websockets
import json
import jwt
from pymongo import MongoClient
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

class Config:
    JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY', 'fallback_dev_secret_key_change_in_production')
    print(f"Using JWT Secret: {JWT_SECRET_KEY[:10]}...")

class DatabaseManager:
    @staticmethod
    def initialize_database():
        """Initialize MongoDB connection"""
        try:
            client = MongoClient('mongodb://localhost:27017/', serverSelectionTimeoutMS=5000)
            db = client['steganography_chat']
            client.admin.command('ping')
            print(" Connected to MongoDB successfully")
            return db
        except Exception as e:
            print(f" Database connection error: {e}")
            return None

class AuthManager:
    SECRET_KEY = Config.JWT_SECRET_KEY

    @staticmethod
    def validate_token(token):
        try:
            if not token:
                print(" No token provided")
                return None
                
            payload = jwt.decode(token, AuthManager.SECRET_KEY, algorithms=["HS256"])
            print(f" Token validated for user: {payload.get('username', 'Unknown')}")
            return payload
        except jwt.ExpiredSignatureError:
            print(" Token expired")
            return None
        except jwt.InvalidTokenError as e:
            print(f" Invalid token: {e}")
            return None
        except Exception as e:
            print(f" Token validation error: {e}")
            return None

class WebSocketServer:
    def __init__(self):
        self.db = DatabaseManager.initialize_database()
        self.connections = {}

    async def process_request(self, path, request_headers):
        """Handle CORS preflight requests"""
        if request_headers.get('Origin'):
            # Handle preflight OPTIONS request
            if request_headers.get('Access-Control-Request-Method'):
                response_headers = [
                    ('Access-Control-Allow-Origin', '*'),
                    ('Access-Control-Allow-Methods', 'GET'),
                    ('Access-Control-Allow-Headers', 'Authorization, Content-Type'),
                ]
                return (200, response_headers, b'')
        
        return None

    async def handler(self, websocket, path):
        """Handler for WebSocket connections"""
        user_id = None
        try:
            print(f"Connection attempt to: {path}")
            
            # Parse the URL
            parsed_path = urlparse(path)
            query_params = parse_qs(parsed_path.query)
            
            token = query_params.get('token', [''])[0]
            
            if not token:
                print(" No token provided")
                await websocket.close(1008, 'Authentication failed: No token provided')
                return

            # Validate token
            payload = AuthManager.validate_token(token)
            if not payload:
                await websocket.close(1008, 'Authentication failed: Invalid token')
                return

            # Extract user ID from path
            if path.startswith("/ws/chat/"):
                user_id = path[len("/ws/chat/"):].split('?')[0]  # Remove query parameters
            else:
                user_id = path.strip('/')

            if not user_id:
                print(" No user ID provided")
                await websocket.close(1008, 'Invalid user ID')
                return

            print(f"WebSocket authenticated for user: {user_id}")
            
            # Store connection
            self.connections[user_id] = websocket

            # Send connection acknowledgement
            await websocket.send(json.dumps({
                'type': 'connection_established',
                'message': 'WebSocket connection established successfully',
                'user_id': user_id
            }))

            # Keep connection alive and handle messages
            async for message in websocket:
                await self.handle_message(user_id, message, payload)

        except websockets.exceptions.ConnectionClosed:
            print(f"Connection closed for user: {user_id}")
        except Exception as e:
            print(f" WebSocket error: {e}")
        finally:
            if user_id and user_id in self.connections:
                del self.connections[user_id]
                print(f"Removed connection for user: {user_id}")

    async def handle_message(self, user_id, message, user_payload):
        try:
            data = json.loads(message)
            print(f"Received from {user_id}: {data}")
            
            # Add metadata
            data['sender_id'] = user_payload.get('_id')
            data['sender_username'] = user_payload.get('username')
            data['timestamp'] = asyncio.get_event_loop().time()
            
            # Save to MongoDB
            if self.db:
                result = self.db.messages.insert_one(data)
                print(f" Message saved to database with ID: {result.inserted_id}")
            
            # Echo back for confirmation
            if user_id in self.connections:
                await self.connections[user_id].send(json.dumps({
                    'type': 'message_ack',
                    'status': 'success',
                    'message_id': str(data.get('_id', 'unknown')),
                    'timestamp': data['timestamp']
                }))
                
        except json.JSONDecodeError:
            print(f" Invalid JSON from {user_id}")
            if user_id in self.connections:
                await self.connections[user_id].send(json.dumps({
                    'type': 'error',
                    'message': 'Invalid JSON format'
                }))
        except Exception as e:
            print(f" Message handling error: {e}")

async def main():
    server = WebSocketServer()
    
    # Start WebSocket server
    try:
        # Create server with process_request handler for CORS
        start_server = websockets.serve(
            server.handler,
            "localhost", 
            8000,
            ping_interval=20,
            ping_timeout=30,
            max_size=2**20,  # 1MB max message size
            process_request=server.process_request
        )
        
        server_instance = await start_server
        print("WebSocket server running at ws://localhost:8000")
        print("Connect using: ws://localhost:8000/ws/chat/USER_ID?token=JWT_TOKEN")
        await server_instance.wait_closed()
            
    except OSError as e:
        if e.errno == 10048:  # Address already in use
            print(f" Port 8000 is already in use. Try a different port.")
        else:
            print(f" OSError: {e}")
    except Exception as e:
        print(f" Failed to start server: {e}")

if __name__ == "__main__":
    # Set event loop policy for Windows if needed
    if os.name == 'nt':  # Windows
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    
    asyncio.run(main())