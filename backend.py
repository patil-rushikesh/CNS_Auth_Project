"""
Secure Authentication & Authorization API
Features: JWT, OAuth 2.0, RBAC, MFA (TOTP & Email OTP)
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
from functools import wraps
from datetime import datetime, timedelta
import jwt
import bcrypt
import pyotp
import secrets
import re
from typing import Dict, List, Optional
from pymongo import MongoClient
from bson.objectid import ObjectId
import os

app = Flask(__name__)
CORS(app)

# Configuration
SECRET_KEY = secrets.token_hex(32)
JWT_EXPIRATION = timedelta(hours=1)
REFRESH_TOKEN_EXPIRATION = timedelta(days=7)

# MongoDB Configuration
MONGO_URI = os.getenv('MONGO_URI', 'mongodb://localhost:27017/')
DATABASE_NAME = os.getenv('DATABASE_NAME', 'secure_auth_db')

# Initialize MongoDB
try:
    client = MongoClient(MONGO_URI)
    db = client[DATABASE_NAME]
    
    # Collections
    users_collection = db.users
    refresh_tokens_collection = db.refresh_tokens
    otp_storage_collection = db.otp_storage
    oauth_clients_collection = db.oauth_clients
    
    # Create indexes for better performance
    users_collection.create_index("email", unique=True)
    users_collection.create_index("user_id", unique=True)
    refresh_tokens_collection.create_index("token", unique=True)
    refresh_tokens_collection.create_index("expires", expireAfterSeconds=0)
    otp_storage_collection.create_index("expires", expireAfterSeconds=0)
    oauth_clients_collection.create_index("expires", expireAfterSeconds=0)
    
    print("✅ MongoDB connected successfully")
except Exception as e:
    print(f"❌ MongoDB connection failed: {e}")
    exit(1)

# Role definitions
ROLES = {
    'admin': ['read', 'write', 'delete', 'manage_users'],
    'moderator': ['read', 'write', 'delete'],
    'user': ['read', 'write'],
    'guest': ['read']
}

# Helper Functions
def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

def verify_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode(), hashed.encode())

def generate_jwt(user_id: str, role: str) -> str:
    payload = {
        'user_id': user_id,
        'role': role,
        'exp': datetime.utcnow() + JWT_EXPIRATION,
        'iat': datetime.utcnow()
    }
    return jwt.encode(payload, SECRET_KEY, algorithm='HS256')

def generate_refresh_token(user_id: str) -> str:
    token = secrets.token_urlsafe(32)
    refresh_tokens_collection.insert_one({
        'token': token,
        'user_id': user_id,
        'expires': datetime.utcnow() + REFRESH_TOKEN_EXPIRATION
    })
    return token

def verify_jwt(token: str) -> Optional[Dict]:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        # Verify token hasn't been tampered with and user still exists
        user = users_collection.find_one({'user_id': payload.get('user_id')})
        if not user:
            return None
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None
    except Exception:
        return None

def validate_email(email: str) -> bool:
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def validate_password(password: str) -> tuple[bool, str]:
    if len(password) < 8:
        return False, "Password must be at least 8 characters"
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain uppercase letter"
    if not re.search(r'[a-z]', password):
        return False, "Password must contain lowercase letter"
    if not re.search(r'[0-9]', password):
        return False, "Password must contain number"
    return True, "Valid"

# Decorators
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token or not token.startswith('Bearer '):
            return jsonify({'error': 'Token missing'}), 401
        
        token = token.split(' ')[1]
        payload = verify_jwt(token)
        
        if not payload:
            return jsonify({'error': 'Invalid or expired token'}), 401
        
        return f(payload, *args, **kwargs)
    return decorated

def role_required(required_permissions: List[str]):
    def decorator(f):
        @wraps(f)
        def decorated(payload, *args, **kwargs):
            user_role = payload.get('role')
            user_permissions = ROLES.get(user_role, [])
            
            if not all(perm in user_permissions for perm in required_permissions):
                return jsonify({'error': 'Insufficient permissions'}), 403
            
            return f(payload, *args, **kwargs)
        return decorated
    return decorator

# Routes
@app.route('/api/register', methods=['POST'])
def register():
    data = request.json
    email = data.get('email')
    password = data.get('password')
    username = data.get('username')
    role = data.get('role', 'user')
    
    if not email or not password or not username:
        return jsonify({'error': 'Missing required fields'}), 400
    
    if not validate_email(email):
        return jsonify({'error': 'Invalid email format'}), 400
    valid, msg = validate_password(password)
    if not valid:
        return jsonify({'error': msg}), 400
    
    if role not in ROLES:
        return jsonify({'error': 'Invalid role'}), 400
    
    # Check if user already exists
    existing_user = users_collection.find_one({'email': email})
    if existing_user:
        return jsonify({'error': 'User already exists'}), 409
    
    # Create user
    user_id = secrets.token_urlsafe(16)
    user_data = {
        'user_id': user_id,
        'username': username,
        'email': email,
        'password': hash_password(password),
        'role': role,
        'mfa_enabled': False,
        'mfa_secret': None,
        'created_at': datetime.utcnow()
    }
    users_collection.insert_one(user_data)
    
    return jsonify({
        'message': 'User registered successfully',
        'user_id': user_id,
        'username': username,
        'role': role
    }), 201

@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    email = data.get('email')
    password = data.get('password')
    
    if not email or not password:
        return jsonify({'error': 'Missing credentials'}), 400
    
    user = users_collection.find_one({'email': email})
    if not user or not verify_password(password, user['password']):
        return jsonify({'error': 'Invalid credentials'}), 401
    
    # Check if MFA is enabled
    if user.get('mfa_enabled'):
        # Generate email OTP
        otp = secrets.randbelow(900000) + 100000
        otp_storage_collection.insert_one({
            'email': email,
            'otp': str(otp),
            'expires': datetime.utcnow() + timedelta(minutes=5)
        })
        
        return jsonify({
            'message': 'MFA required',
            'mfa_required': True,
            'otp_sent': True,
            'otp': str(otp)  # In production, send via email
        }), 200
    
    # Generate tokens
    access_token = generate_jwt(user['user_id'], user['role'])
    refresh_token = generate_refresh_token(user['user_id'])
    
    return jsonify({
        'message': 'Login successful',
        'access_token': access_token,
        'refresh_token': refresh_token,
        'user': {
            'user_id': user['user_id'],
            'username': user['username'],
            'email': user['email'],
            'role': user['role']
        }
    }), 200

@app.route('/api/verify-mfa', methods=['POST'])
def verify_mfa():
    data = request.json
    email = data.get('email')
    otp_code = data.get('otp')
    
    if not email or not otp_code:
        return jsonify({'error': 'Missing required fields'}), 400
    
    user = users_collection.find_one({'email': email})
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    # Verify TOTP if enabled
    if user.get('mfa_secret'):
        totp = pyotp.TOTP(user['mfa_secret'])
        if not totp.verify(otp_code):
            return jsonify({'error': 'Invalid OTP'}), 401
    else:
        # Verify email OTP
        stored_otp = otp_storage_collection.find_one({'email': email})
        if not stored_otp:
            return jsonify({'error': 'No OTP found'}), 400
        
        if datetime.utcnow() > stored_otp['expires']:
            return jsonify({'error': 'OTP expired'}), 401
        
        if stored_otp['otp'] != otp_code:
            return jsonify({'error': 'Invalid OTP'}), 401
        
        otp_storage_collection.delete_one({'email': email})
    
    # Generate tokens
    access_token = generate_jwt(user['user_id'], user['role'])
    refresh_token = generate_refresh_token(user['user_id'])
    
    return jsonify({
        'message': 'MFA verification successful',
        'access_token': access_token,
        'refresh_token': refresh_token,
        'user': {
            'user_id': user['user_id'],
            'username': user['username'],
            'email': user['email'],
            'role': user['role']
        }
    }), 200

@app.route('/api/enable-mfa', methods=['POST'])
@token_required
def enable_mfa(payload):
    user_id = payload['user_id']
    user = users_collection.find_one({'user_id': user_id})
    
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    # Generate TOTP secret
    secret = pyotp.random_base32()
    users_collection.update_one(
        {'user_id': user_id},
        {'$set': {'mfa_secret': secret, 'mfa_enabled': True}}
    )
    
    totp = pyotp.TOTP(secret)
    provisioning_uri = totp.provisioning_uri(
        user['email'],
        issuer_name='SecureAuth App'
    )
    
    return jsonify({
        'message': 'MFA enabled',
        'secret': secret,
        'provisioning_uri': provisioning_uri,
        'qr_code_url': f'https://api.qrserver.com/v1/create-qr-code/?size=200x200&data={provisioning_uri}'
    }), 200

@app.route('/api/refresh', methods=['POST'])
def refresh():
    data = request.json
    refresh_token = data.get('refresh_token')
    
    # Find refresh token in MongoDB
    token_data = refresh_tokens_collection.find_one({'token': refresh_token})
    if not token_data:
        return jsonify({'error': 'Invalid refresh token'}), 401
    
    if datetime.utcnow() > token_data['expires']:
        refresh_tokens_collection.delete_one({'token': refresh_token})
        return jsonify({'error': 'Refresh token expired'}), 401
    
    user = users_collection.find_one({'user_id': token_data['user_id']})
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    # Remove old refresh token and generate new one
    refresh_tokens_collection.delete_one({'token': refresh_token})
    new_refresh_token = generate_refresh_token(user['user_id'])
    access_token = generate_jwt(user['user_id'], user['role'])
    
    return jsonify({
        'access_token': access_token,
        'refresh_token': new_refresh_token
    }), 200

@app.route('/api/protected/user', methods=['GET'])
@token_required
@role_required(['read'])
def user_endpoint(payload):
    return jsonify({
        'message': 'User endpoint',
        'user_id': payload['user_id'],
        'role': payload['role'],
        'data': 'This is accessible to all authenticated users'
    }), 200

@app.route('/api/protected/moderator', methods=['GET'])
@token_required
@role_required(['delete'])
def moderator_endpoint(payload):
    return jsonify({
        'message': 'Moderator endpoint',
        'user_id': payload['user_id'],
        'role': payload['role'],
        'data': 'This is accessible to moderators and admins'
    }), 200

@app.route('/api/protected/admin', methods=['GET'])
@token_required
@role_required(['manage_users'])
def admin_endpoint(payload):
    return jsonify({
        'message': 'Admin endpoint',
        'user_id': payload['user_id'],
        'role': payload['role'],
        'data': 'This is accessible to admins only',
        'users': [{
            'user_id': u['user_id'],
            'username': u['username'],
            'email': u['email'],
            'role': u['role']
        } for u in users_collection.find({})]
    }), 200

@app.route('/api/oauth/authorize', methods=['POST'])
def oauth_authorize():
    data = request.json
    client_id = data.get('client_id')
    redirect_uri = data.get('redirect_uri')
    
    # Simplified OAuth flow
    auth_code = secrets.token_urlsafe(32)
    oauth_clients_collection.insert_one({
        'auth_code': auth_code,
        'client_id': client_id,
        'redirect_uri': redirect_uri,
        'expires': datetime.utcnow() + timedelta(minutes=10)
    })
    
    return jsonify({
        'authorization_code': auth_code,
        'redirect_uri': redirect_uri
    }), 200

@app.route('/api/oauth/token', methods=['POST'])
def oauth_token():
    data = request.json
    auth_code = data.get('code')
    
    client_data = oauth_clients_collection.find_one({'auth_code': auth_code})
    if not client_data:
        return jsonify({'error': 'Invalid authorization code'}), 401
    
    if datetime.utcnow() > client_data['expires']:
        oauth_clients_collection.delete_one({'auth_code': auth_code})
        return jsonify({'error': 'Authorization code expired'}), 401
    
    # Generate access token
    access_token = secrets.token_urlsafe(32)
    
    oauth_clients_collection.delete_one({'auth_code': auth_code})
    
    return jsonify({
        'access_token': access_token,
        'token_type': 'Bearer',
        'expires_in': 3600
    }), 200

@app.route('/api/health', methods=['GET'])
def health():
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.utcnow().isoformat()
    }), 200

if __name__ == '__main__':
    print("🚀 Secure Authentication API Starting...")
    print(f"📝 Secret Key: {SECRET_KEY[:16]}...")
    print("🔐 Features: JWT, OAuth 2.0, RBAC, MFA")
    print("🌐 Server running on http://localhost:5000")
    app.run(debug=True, port=5000)