import http.server
import json
import re
import urllib.parse
from http import HTTPStatus
from pymongo import MongoClient
from bson import ObjectId

class UserSearchHandler(http.server.BaseHTTPRequestHandler):
    def do_OPTIONS(self):
        # Handle preflight requests for all endpoints
        self.send_response(200)
        self.send_cors_headers()
        self.end_headers()
    
    def do_GET(self):
        # Parse the path to handle both exact matches and query parameters
        parsed_path = urllib.parse.urlparse(self.path)
        
        # Only handle the search endpoint
        if parsed_path.path == '/api/users/search':
            self.handle_user_search()
        else:
            self.send_error(HTTPStatus.NOT_FOUND, "Endpoint not found")
    
    def send_cors_headers(self):
        """Send CORS headers to allow requests from the frontend"""
        self.send_header('Access-Control-Allow-Origin', 'http://localhost:3000')
        self.send_header('Access-Control-Allow-Methods', 'GET, OPTIONS, POST, PUT, DELETE')
        self.send_header('Access-Control-Allow-Headers', 'Authorization, Content-Type')
        self.send_header('Access-Control-Allow-Credentials', 'true')
        self.send_header('Access-Control-Max-Age', '86400')  # 24 hours
    
    def handle_user_search(self):
        try:
            # Parse query parameters
            parsed_path = urllib.parse.urlparse(self.path)
            query_params = urllib.parse.parse_qs(parsed_path.query)
            search_term = query_params.get('q', [''])[0].strip()
            
            # Validate authorization
            auth_header = self.headers.get('Authorization', '')
            if not auth_header.startswith('Bearer '):
                self.send_auth_error()
                return
                
            token = auth_header[7:]  # Remove 'Bearer ' prefix
            
            # Validate token (simplified - in real app, use proper JWT validation)
            if not self.validate_token(token):
                self.send_auth_error()
                return
            
            # Validate search term
            if not search_term or len(search_term) < 3:
                self.send_response(HTTPStatus.BAD_REQUEST)
                self.send_header('Content-type', 'application/json')
                self.send_cors_headers()
                self.end_headers()
                response = {
                    'success': False,
                    'message': 'Search term must be at least 3 characters long'
                }
                self.wfile.write(json.dumps(response).encode())
                return
            
            # Get user ID from token (simplified)
            user_id = self.get_user_id_from_token(token)
            
            # Search for users in MongoDB
            users = self.search_users_in_mongodb(search_term, user_id)
            
            # Format response
            users_data = []
            for user in users:
                users_data.append({
                    'id': str(user['_id']),
                    'username': user['username'],
                    'email': user['email'],
                    'profile_image': user.get('profile_image', '')
                })
            
            self.send_response(HTTPStatus.OK)
            self.send_header('Content-type', 'application/json')
            self.send_cors_headers()
            self.end_headers()
            response = {
                'success': True,
                'users': users_data
            }
            self.wfile.write(json.dumps(response).encode())
            
        except Exception as e:
            print(f"Search users error: {str(e)}")
            self.send_response(HTTPStatus.INTERNAL_SERVER_ERROR)
            self.send_header('Content-type', 'application/json')
            self.send_cors_headers()
            self.end_headers()
            response = {
                'success': False,
                'message': 'An error occurred while searching users'
            }
            self.wfile.write(json.dumps(response).encode())
    
    def validate_token(self, token):
        # Simplified token validation - in a real app, use proper JWT validation
        # This is just a placeholder that checks if token looks like a JWT
        return bool(re.match(r'^[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]*$', token))
    
    def get_user_id_from_token(self, token):
        # Simplified - extract user ID from token
        # In a real app, you would decode the JWT and extract the user ID
        try:
            # This is a mock implementation - replace with actual JWT decoding
            parts = token.split('.')
            if len(parts) >= 2:
                # Mock: use the length of the first part as user ID
                return str(len(parts[0]))
        except:
            pass
        return "default_user_id"  # Default fallback
    
    def search_users_in_mongodb(self, search_term, current_user_id):
        # Connect to MongoDB
        client = MongoClient('mongodb://localhost:27017/')
        db = client['steganography_chat']  # Replace with your database name
        users_collection = db['users']  # Replace with your collection name
        
        # Search for users by username (case-insensitive)
        regex_pattern = f'.*{re.escape(search_term)}.*'
        
        # Create query based on whether current_user_id is a valid ObjectId
        try:
            # Try to convert to ObjectId if it looks like one
            user_obj_id = ObjectId(current_user_id)
            query = {
                'username': {'$regex': regex_pattern, '$options': 'i'},
                '_id': {'$ne': user_obj_id}
            }
        except:
            # If not a valid ObjectId, use string comparison
            query = {
                'username': {'$regex': regex_pattern, '$options': 'i'},
                '_id': {'$ne': current_user_id}
            }
        
        users = users_collection.find(query).limit(20)
        return list(users)
    
    def send_auth_error(self):
        self.send_response(HTTPStatus.UNAUTHORIZED)
        self.send_header('Content-type', 'application/json')
        self.send_cors_headers()
        self.end_headers()
        response = {
            'success': False,
            'message': 'Authentication required'
        }
        self.wfile.write(json.dumps(response).encode())
    
    def log_message(self, format, *args):
        # Custom log message format to see what's being requested
        print("%s - - [%s] %s\n" %
              (self.address_string(),
               self.log_date_time_string(),
               format % args))

def run_server(port=8000):
    server_address = ('', port)
    httpd = http.server.HTTPServer(server_address, UserSearchHandler)
    print(f"Starting user search server on port {port}...")
    httpd.serve_forever()

if __name__ == '__main__':
    run_server()