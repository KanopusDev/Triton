import os
import uuid
from flask import Flask, render_template, request, jsonify, redirect, url_for, session, g
from azure.ai.inference import ChatCompletionsClient, EmbeddingsClient
from azure.ai.inference.models import SystemMessage, UserMessage, AssistantMessage, ChatCompletionsToolCall, ChatCompletionsToolDefinition, CompletionsFinishReason, FunctionDefinition, ToolMessage
from azure.core.credentials import AzureKeyCredential
import google.generativeai as genai
import faiss
import numpy as np
from bs4 import BeautifulSoup
import markdown
import requests
import json
from typing import List, Dict, Any, Optional, Tuple, Union, Set
import sqlite3
from datetime import datetime, timedelta
from contextlib import contextmanager
from dotenv import load_dotenv
from werkzeug.utils import secure_filename
import pytesseract
from pdf2image import convert_from_path
import fitz  # PyMuPDF
import time
import threading
from functools import wraps
import logging
from tenacity import retry, stop_after_attempt, wait_exponential
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import quote_plus, urlparse
import secrets
import sys
import traceback
import atexit
from pathlib import Path
from socket import gethostname
import asyncio
import aiohttp
import bcrypt
import jwt
import click
from flask.cli import with_appcontext
import re
import html
from bs4.element import Comment

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("triton.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("triton")

# Load environment variables
load_dotenv()

# Application configuration
class Config:
    """Application configuration"""
    SECRET_KEY = os.getenv("SECRET_KEY") or secrets.token_hex(32)
    DEBUG = os.getenv("DEBUG", "false").lower() == "true"
    TESTING = os.getenv("TESTING", "false").lower() == "true"
    DATABASE_PATH = os.getenv("DATABASE_PATH", "triton.db")
    UPLOAD_FOLDER = os.getenv("UPLOAD_FOLDER", "uploads")
    MAX_CONTENT_LENGTH = int(os.getenv("MAX_UPLOAD_SIZE", "50")) * 1024 * 1024  # Default 50MB
    SESSION_COOKIE_SECURE = os.getenv("SESSION_COOKIE_SECURE", "true").lower() == "true"
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    PRESERVE_CONTEXT_ON_EXCEPTION = False
    CORS_ORIGINS = os.getenv("CORS_ORIGINS", "*").split(",")
    LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
    TIMEOUT = int(os.getenv("REQUEST_TIMEOUT", "60"))  # Default 60 seconds

# Initialize Flask app with config
app = Flask(__name__)
app.config.from_object(Config)

# Configure CORS
from flask_cors import CORS
CORS(app,
     origins=app.config["CORS_ORIGINS"],
     supports_credentials=True)

# Set log level
logger.setLevel(getattr(logging, app.config["LOG_LEVEL"]))

# Add CORS headers to all responses
@app.after_request
def after_request(response):
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization,X-Requested-With')
    response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS')
    response.headers.add('Access-Control-Allow-Credentials', 'true')
    response.headers.add('X-Content-Type-Options', 'nosniff')
    response.headers.add('X-Frame-Options', 'DENY')
    response.headers.add('Strict-Transport-Security', 'max-age=31536000; includeSubDomains')
    return response

# User roles and permissions
class UserRole:
    """User role definitions"""
    ADMIN = "admin"
    USER = "user"
    
    @staticmethod
    def get_permissions(role):
        """Get permissions for a role"""
        permissions = {
            UserRole.ADMIN: ["manage_users", "invite_users", "manage_all_conversations", "manage_system"],
            UserRole.USER: ["manage_own_conversations"]
        }
        return permissions.get(role, [])

# Extended database initialization to include authentication tables
@contextmanager
def get_db_connection():
    """Context manager for database connections"""
    conn = sqlite3.connect(app.config["DATABASE_PATH"])
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()

def init_db():
    """Initialize the database with required tables"""
    with get_db_connection() as conn:
        # Existing tables
        conn.execute('''
        CREATE TABLE IF NOT EXISTS conversations (
            conversation_id TEXT PRIMARY KEY,
            conversation_name TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            message_count INTEGER DEFAULT 0,
            first_message TEXT,
            last_message TIMESTAMP,
            user_id TEXT
        )
        ''')
        
        conn.execute('''
        CREATE TABLE IF NOT EXISTS messages (
            message_id TEXT PRIMARY KEY,
            conversation_id TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            user_message TEXT,
            assistant_message TEXT,
            reasoning TEXT,
            search_context TEXT,
            model TEXT,
            features TEXT,
            FOREIGN KEY (conversation_id) REFERENCES conversations (conversation_id) ON DELETE CASCADE
        )
        ''')
        
        conn.execute('''
        CREATE TABLE IF NOT EXISTS documents (
            doc_id TEXT PRIMARY KEY,
            conversation_id TEXT,
            name TEXT,
            path TEXT,
            content TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (conversation_id) REFERENCES conversations (conversation_id) ON DELETE CASCADE
        )
        ''')
        
        # New authentication tables
        conn.execute('''
        CREATE TABLE IF NOT EXISTS users (
            user_id TEXT PRIMARY KEY,
            username TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP,
            active INTEGER DEFAULT 1
        )
        ''')
        
        conn.execute('''
        CREATE TABLE IF NOT EXISTS sessions (
            session_id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            token TEXT UNIQUE NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            expires_at TIMESTAMP NOT NULL,
            ip_address TEXT,
            user_agent TEXT,
            FOREIGN KEY (user_id) REFERENCES users (user_id) ON DELETE CASCADE
        )
        ''')
        
        conn.execute('''
        CREATE TABLE IF NOT EXISTS invitations (
            invitation_id TEXT PRIMARY KEY,
            email TEXT UNIQUE NOT NULL,
            token TEXT UNIQUE NOT NULL,
            created_by TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            expires_at TIMESTAMP NOT NULL,
            used INTEGER DEFAULT 0,
            FOREIGN KEY (created_by) REFERENCES users (user_id) ON DELETE CASCADE
        )
        ''')
        
        conn.commit()

# Initialize database on startup
init_db()

# Authentication helpers
def hash_password(password):
    """Hash a password with bcrypt"""
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(password, password_hash):
    """Verify a password against a hash"""
    return bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8'))

def generate_jwt_token(user_id, expires_in=24):
    """Generate a JWT token for authentication"""
    payload = {
        'user_id': user_id,
        'exp': datetime.utcnow() + timedelta(hours=expires_in)
    }
    return jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')

def verify_jwt_token(token):
    """Verify a JWT token and return user_id if valid"""
    try:
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        return payload.get('user_id')
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

def create_session(user_id, request_info=None):
    """Create a new session for the user"""
    session_id = str(uuid.uuid4())
    token = secrets.token_urlsafe(64)
    expires_at = datetime.utcnow() + timedelta(days=30)
    
    ip_address = None
    user_agent = None
    
    if request_info:
        ip_address = request_info.get('ip')
        user_agent = request_info.get('user_agent')
    
    with get_db_connection() as conn:
        conn.execute(
            """INSERT INTO sessions 
            (session_id, user_id, token, expires_at, ip_address, user_agent) 
            VALUES (?, ?, ?, ?, ?, ?)""",
            (session_id, user_id, token, expires_at.isoformat(), ip_address, user_agent)
        )
        conn.commit()
    
    return token

def get_user_by_id(user_id):
    """Get user by ID"""
    with get_db_connection() as conn:
        user = conn.execute(
            """SELECT user_id, username, email, role, created_at, last_login, active
            FROM users WHERE user_id = ? AND active = 1""",
            (user_id,)
        ).fetchone()
        
        if user:
            return {
                "user_id": user["user_id"],
                "username": user["username"],
                "email": user["email"],
                "role": user["role"],
                "created_at": user["created_at"],
                "last_login": user["last_login"],
                "active": bool(user["active"])
            }
    
    return None

def get_user_by_email(email):
    """Get user by email"""
    with get_db_connection() as conn:
        user = conn.execute(
            """SELECT user_id, username, email, password_hash, role 
            FROM users WHERE email = ? AND active = 1""",
            (email.lower(),)
        ).fetchone()
        
        if user:
            return {
                "user_id": user["user_id"],
                "username": user["username"],
                "email": user["email"],
                "password_hash": user["password_hash"],
                "role": user["role"]
            }
    
    return None

def validate_session(token):
    """Validate a session token and return user_id if valid"""
    with get_db_connection() as conn:
        session_data = conn.execute(
            """SELECT user_id FROM sessions 
            WHERE token = ? AND expires_at > ?""",
            (token, datetime.utcnow().isoformat())
        ).fetchone()
        
        if session_data:
            return session_data["user_id"]
    
    return None

def get_current_user():
    """Get the current authenticated user"""
    # First check HTTP-only cookie session
    session_token = session.get('auth_token')
    if session_token:
        user_id = validate_session(session_token)
        if user_id:
            return get_user_by_id(user_id)
    
    # Then check Authorization header for JWT tokens (API usage)
    auth_header = request.headers.get('Authorization')
    if auth_header and auth_header.startswith('Bearer '):
        token = auth_header.split(' ')[1]
        user_id = verify_jwt_token(token)
        if user_id:
            return get_user_by_id(user_id)
    
    return None

def create_invitation(email, created_by):
    """Create an invitation for a new user"""
    invitation_id = str(uuid.uuid4())
    token = secrets.token_urlsafe(32)
    expires_at = datetime.utcnow() + timedelta(days=7)
    
    with get_db_connection() as conn:
        # Check for existing invitations for this email
        existing = conn.execute(
            "SELECT invitation_id FROM invitations WHERE email = ? AND used = 0",
            (email.lower(),)
        ).fetchone()
        
        if existing:
            # Update existing invitation
            conn.execute(
                """UPDATE invitations SET 
                token = ?, created_by = ?, created_at = ?, expires_at = ? 
                WHERE invitation_id = ?""",
                (
                    token,
                    created_by,
                    datetime.utcnow().isoformat(),
                    expires_at.isoformat(),
                    existing["invitation_id"]
                )
            )
        else:
            # Create new invitation
            conn.execute(
                """INSERT INTO invitations 
                (invitation_id, email, token, created_by, expires_at) 
                VALUES (?, ?, ?, ?, ?)""",
                (
                    invitation_id,
                    email.lower(),
                    token,
                    created_by,
                    expires_at.isoformat()
                )
            )
        
        conn.commit()
    
    return token

def verify_invitation(email, token):
    """Verify an invitation token and return the invitation_id if valid"""
    with get_db_connection() as conn:
        invitation = conn.execute(
            """SELECT invitation_id FROM invitations 
            WHERE email = ? AND token = ? AND used = 0 AND expires_at > ?""",
            (email.lower(), token, datetime.utcnow().isoformat())
        ).fetchone()
        
        if invitation:
            return invitation["invitation_id"]
    
    return None

def mark_invitation_used(invitation_id):
    """Mark an invitation as used"""
    with get_db_connection() as conn:
        conn.execute(
            "UPDATE invitations SET used = 1 WHERE invitation_id = ?",
            (invitation_id,)
        )
        conn.commit()

# Authentication decorators (middleware)
def login_required(f):
    """Decorator to require authentication for a route"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user = get_current_user()
        if not user:
            return jsonify({"error": "Authentication required"}), 401
        
        # Set user in Flask's g object for the request
        g.user = user
        return f(*args, **kwargs)
    
    return decorated_function

def admin_required(f):
    """Decorator to require admin role for a route"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user = get_current_user()
        if not user:
            return jsonify({"error": "Authentication required"}), 401
        
        if user["role"] != UserRole.ADMIN:
            return jsonify({"error": "Administrator privileges required"}), 403
        
        # Set user in Flask's g object for the request
        g.user = user
        return f(*args, **kwargs)
    
    return decorated_function

# Authentication endpoints
@app.route('/auth/login', methods=['POST'])
def login():
    """User login endpoint"""
    try:
        data = request.json
        
        if not data:
            return jsonify({"error": "No data provided"}), 400
        
        email = data.get('email', '').strip().lower()
        password = data.get('password', '')
        
        if not email or not password:
            return jsonify({"error": "Email and password are required"}), 400
        
        # Find user by email
        user = get_user_by_email(email)
        if not user:
            # Use consistent error message to prevent email enumeration
            return jsonify({"error": "Invalid email or password"}), 401
        
        # Verify password
        if not verify_password(password, user["password_hash"]):
            return jsonify({"error": "Invalid email or password"}), 401
        
        # Create a new session
        request_info = {
            'ip': request.remote_addr,
            'user_agent': request.headers.get('User-Agent')
        }
        session_token = create_session(user["user_id"], request_info)
        
        # Generate JWT token for API use
        jwt_token = generate_jwt_token(user["user_id"])
        
        # Update last login timestamp
        with get_db_connection() as conn:
            conn.execute(
                "UPDATE users SET last_login = ? WHERE user_id = ?",
                (datetime.utcnow().isoformat(), user["user_id"])
            )
            conn.commit()
        
        # Set HTTP-only cookie
        session['auth_token'] = session_token
        
        # Remove password hash from response
        user_data = {k: v for k, v in user.items() if k != 'password_hash'}
        
        return jsonify({
            "status": "success",
            "message": "Login successful",
            "token": jwt_token,  # For API clients
            "user": user_data
        })
        
    except Exception as e:
        logger.error(f"Login error: {str(e)}\n{traceback.format_exc()}")
        return jsonify({"error": "Authentication failed"}), 500

@app.route('/auth/logout', methods=['POST'])
@login_required
def logout():
    """User logout endpoint"""
    try:
        # Get session token from cookie
        session_token = session.get('auth_token')
        
        # Remove session from database
        if session_token:
            with get_db_connection() as conn:
                conn.execute("DELETE FROM sessions WHERE token = ?", (session_token,))
                conn.commit()
        
        # Clear session cookie
        session.pop('auth_token', None)
        
        return jsonify({
            "status": "success",
            "message": "Logout successful"
        })
        
    except Exception as e:
        logger.error(f"Logout error: {str(e)}")
        return jsonify({"error": "Logout failed"}), 500

@app.route('/auth/register', methods=['POST'])
def register():
    """User registration endpoint (requires invitation)"""
    try:
        data = request.json
        
        if not data:
            return jsonify({"error": "No data provided"}), 400
        
        username = data.get('username', '').strip()
        email = data.get('email', '').strip().lower()
        password = data.get('password', '')
        invitation_token = data.get('invitation_token', '')
        
        # Validate inputs
        if not username or not email or not password or not invitation_token:
            return jsonify({"error": "All fields are required"}), 400
        
        if len(password) < 8:
            return jsonify({"error": "Password must be at least 8 characters long"}), 400
        
        # Verify the invitation
        invitation_id = verify_invitation(email, invitation_token)
        if not invitation_id:
            return jsonify({"error": "Invalid or expired invitation"}), 403
        
        # Check if user with email already exists
        existing_user = get_user_by_email(email)
        if existing_user:
            return jsonify({"error": "An account with this email already exists"}), 409
        
        # Create new user
        user_id = str(uuid.uuid4())
        password_hash = hash_password(password)
        
        with get_db_connection() as conn:
            conn.execute(
                """INSERT INTO users 
                (user_id, username, email, password_hash, role, created_at) 
                VALUES (?, ?, ?, ?, ?, ?)""",
                (
                    user_id,
                    username,
                    email,
                    password_hash,
                    UserRole.USER,  # Default role is regular user
                    datetime.utcnow().isoformat()
                )
            )
            
            # Mark invitation as used
            mark_invitation_used(invitation_id)
            
            conn.commit()
        
        # Create session for new user
        request_info = {
            'ip': request.remote_addr,
            'user_agent': request.headers.get('User-Agent')
        }
        session_token = create_session(user_id, request_info)
        
        # Generate JWT for API access
        jwt_token = generate_jwt_token(user_id)
        
        # Set HTTP-only cookie
        session['auth_token'] = session_token
        
        return jsonify({
            "status": "success",
            "message": "Registration successful",
            "token": jwt_token,
            "user": {
                "user_id": user_id,
                "username": username,
                "email": email,
                "role": UserRole.USER,
                "created_at": datetime.utcnow().isoformat()
            }
        })
        
    except Exception as e:
        logger.error(f"Registration error: {str(e)}\n{traceback.format_exc()}")
        return jsonify({"error": "Registration failed"}), 500

@app.route('/auth/me', methods=['GET'])
@login_required
def get_current_user_info():
    """Get current user information"""
    return jsonify({
        "status": "success",
        "user": g.user
    })

@app.route('/auth/change-password', methods=['POST'])
@login_required
def change_password():
    """Change user password"""
    try:
        data = request.json
        
        if not data:
            return jsonify({"error": "No data provided"}), 400
        
        current_password = data.get('current_password', '')
        new_password = data.get('new_password', '')
        
        if not current_password or not new_password:
            return jsonify({"error": "Current and new passwords are required"}), 400
        
        if len(new_password) < 8:
            return jsonify({"error": "New password must be at least 8 characters long"}), 400
        
        # Verify current password
        with get_db_connection() as conn:
            user = conn.execute(
                "SELECT password_hash FROM users WHERE user_id = ?",
                (g.user["user_id"],)
            ).fetchone()
            
            if not user or not verify_password(current_password, user["password_hash"]):
                return jsonify({"error": "Current password is incorrect"}), 401
            
            # Update password
            password_hash = hash_password(new_password)
            conn.execute(
                "UPDATE users SET password_hash = ? WHERE user_id = ?",
                (password_hash, g.user["user_id"])
            )
            
            # Invalidate all other sessions (optional security measure)
            current_token = session.get('auth_token')
            if current_token:
                conn.execute(
                    "DELETE FROM sessions WHERE user_id = ? AND token != ?",
                    (g.user["user_id"], current_token)
                )
            
            conn.commit()
        
        return jsonify({
            "status": "success",
            "message": "Password changed successfully"
        })
        
    except Exception as e:
        logger.error(f"Password change error: {str(e)}")
        return jsonify({"error": "Password change failed"}), 500

@app.route('/auth/invite', methods=['POST'])
@login_required
def invite_user():
    """Invite a new user (requires appropriate permissions)"""
    try:
        # Check if user has invite permission (admin or explicitly granted)
        has_permission = g.user["role"] == UserRole.ADMIN or "invite_users" in UserRole.get_permissions(g.user["role"])
        if not has_permission:
            return jsonify({"error": "You do not have permission to invite users"}), 403
        
        data = request.json
        
        if not data:
            return jsonify({"error": "No data provided"}), 400
        
        email = data.get('email', '').strip().lower()
        
        if not email:
            return jsonify({"error": "Email is required"}), 400
        
        # Validate email format
        if '@' not in email or '.' not in email:
            return jsonify({"error": "Invalid email address"}), 400
        
        # Check if user already exists
        existing_user = get_user_by_email(email)
        if existing_user:
            return jsonify({"error": "User with this email already exists"}), 409
        
        # Create invitation
        invitation_token = create_invitation(email, g.user["user_id"])
        
        # Generate invitation URL using production domain
        invitation_url = f"https://triton.kanopus.org/register?email={email}&token={invitation_token}"
        
        return jsonify({
            "status": "success",
            "message": f"Invitation sent to {email}",
            "invitation_url": invitation_url,
            "token": invitation_token  # In production, you would NOT include this in the response
        })
        
    except Exception as e:
        logger.error(f"Invitation error: {str(e)}")
        return jsonify({"error": "Could not create invitation"}), 500

# Admin endpoints
@app.route('/admin/users', methods=['GET'])
@admin_required
def list_users():
    """List all users (admin only)"""
    try:
        with get_db_connection() as conn:
            users = conn.execute(
                """SELECT user_id, username, email, role, created_at, last_login, active
                FROM users ORDER BY created_at DESC"""
            ).fetchall()
            
            result = []
            for user in users:
                result.append({
                    "user_id": user["user_id"],
                    "username": user["username"],
                    "email": user["email"],
                    "role": user["role"],
                    "created_at": user["created_at"],
                    "last_login": user["last_login"],
                    "active": bool(user["active"])
                })
            
            return jsonify({
                "status": "success",
                "users": result
            })
            
    except Exception as e:
        logger.error(f"List users error: {str(e)}")
        return jsonify({"error": "Failed to list users"}), 500

@app.route('/admin/users/<user_id>', methods=['PUT'])
@admin_required
def update_user(user_id):
    """Update user properties (admin only)"""
    try:
        data = request.json
        
        if not data:
            return jsonify({"error": "No data provided"}), 400
        
        # Fields that can be updated
        allowed_fields = {
            'username': str,
            'role': str,
            'active': bool
        }
        
        # Build update query
        updates = {}
        for field, field_type in allowed_fields.items():
            if field in data:
                value = data[field]
                if not isinstance(value, field_type):
                    return jsonify({"error": f"Invalid type for field {field}"}), 400
                updates[field] = value
        
        if not updates:
            return jsonify({"error": "No valid fields to update"}), 400
        
        with get_db_connection() as conn:
            # Check if user exists
            user = conn.execute(
                "SELECT user_id FROM users WHERE user_id = ?",
                (user_id,)
            ).fetchone()
            
            if not user:
                return jsonify({"error": "User not found"}), 404
            
            # Build SQL query
            fields = ', '.join([f"{field} = ?" for field in updates.keys()])
            query = f"UPDATE users SET {fields} WHERE user_id = ?"
            
            # Build parameters
            params = list(updates.values())
            params.append(user_id)
            
            # Execute update
            conn.execute(query, params)
            conn.commit()
            
            # Get updated user
            updated_user = get_user_by_id(user_id)
            if not updated_user:
                return jsonify({"error": "Failed to retrieve updated user"}), 500
            
            return jsonify({
                "status": "success",
                "message": "User updated successfully",
                "user": updated_user
            })
            
    except Exception as e:
        logger.error(f"Update user error: {str(e)}")
        return jsonify({"error": "Failed to update user"}), 500

@app.route('/admin/stats', methods=['GET'])
@admin_required
def get_admin_stats():
    """Get admin dashboard statistics"""
    try:
        with get_db_connection() as conn:
            # Get total users count
            total_users = conn.execute("SELECT COUNT(*) as count FROM users").fetchone()["count"]
            
            # Get active users in last 30 days
            thirty_days_ago = (datetime.now() - timedelta(days=30)).isoformat()
            active_users = conn.execute(
                "SELECT COUNT(*) as count FROM users WHERE last_login > ?", 
                (thirty_days_ago,)
            ).fetchone()["count"]
            
            # Get total conversations
            total_conversations = conn.execute(
                "SELECT COUNT(*) as count FROM conversations"
            ).fetchone()["count"]
            
            # Get total messages
            total_messages = conn.execute(
                "SELECT COUNT(*) as count FROM messages"
            ).fetchone()["count"]
            
            # Get documents uploaded
            documents_uploaded = conn.execute(
                "SELECT COUNT(*) as count FROM documents"
            ).fetchone()["count"]
            
            # Get user activity data for chart (last 7 days)
            seven_days_ago = (datetime.now() - timedelta(days=7)).isoformat()
            user_activity_query = """
                SELECT date(last_login) as date, COUNT(*) as count 
                FROM users 
                WHERE last_login > ? 
                GROUP BY date(last_login)
                ORDER BY date(last_login)
            """
            user_activity_result = conn.execute(user_activity_query, (seven_days_ago,)).fetchall()
            
            user_activity = []
            for row in user_activity_result:
                user_activity.append({
                    "date": row["date"],
                    "count": row["count"]
                })
            
            # Fill in missing days with zero
            current_date = datetime.now().date()
            for i in range(7):
                date_str = (current_date - timedelta(days=i)).isoformat()
                if not any(item["date"] == date_str for item in user_activity):
                    user_activity.append({
                        "date": date_str,
                        "count": 0
                    })
            
            # Sort by date
            user_activity.sort(key=lambda x: x["date"])
            
            # Get model usage data
            model_usage_query = """
                SELECT model, COUNT(*) as count
                FROM messages
                WHERE model IS NOT NULL
                GROUP BY model
                ORDER BY count DESC
                LIMIT 5
            """
            model_usage_result = conn.execute(model_usage_query).fetchall()
            
            model_usage = []
            for row in model_usage_result:
                model_name = row["model"].split('/')[-1] if '/' in row["model"] else row["model"]
                model_usage.append({
                    "model": model_name,
                    "count": row["count"]
                })
            
            return jsonify({
                "status": "success",
                "stats": {
                    "totalUsers": total_users,
                    "activeUsers": active_users,
                    "totalConversations": total_conversations,
                    "totalMessages": total_messages,
                    "documentsUploaded": documents_uploaded
                },
                "userActivity": user_activity,
                "modelUsage": model_usage
            })
    except Exception as e:
        logger.error(f"Admin stats error: {str(e)}\n{traceback.format_exc()}")
        return jsonify({"error": str(e)}), 500

# CLI Commands for first admin user
@click.command('create-admin')
@click.option('--username', required=True, help='Admin username')
@click.option('--email', required=True, help='Admin email')
@click.option('--password', required=True, help='Admin password')
@with_appcontext
def create_admin_command(username, email, password):
    """Create the first admin user (CLI only)"""
    try:
        # Check if any users exist
        with get_db_connection() as conn:
            existing_users = conn.execute("SELECT COUNT(*) as count FROM users").fetchone()
            
            # Only allow first admin creation if no users exist, or override with env var
            if existing_users and existing_users["count"] > 0:
                force_create = os.environ.get('FORCE_ADMIN_CREATE', 'false').lower() == 'true'
                if not force_create:
                    click.echo("Error: Users already exist. Use FORCE_ADMIN_CREATE=true to override.", err=True)
                    return 1
            
            # Check if email is already used
            email = email.strip().lower()
            existing_email = conn.execute(
                "SELECT user_id FROM users WHERE email = ?", 
                (email,)
            ).fetchone()
            
            if existing_email:
                click.echo(f"Error: Email {email} is already registered.", err=True)
                return 1
            
            # Validate password
            if len(password) < 8:
                click.echo("Error: Password must be at least 8 characters long.", err=True)
                return 1
            
            # Create admin user
            user_id = str(uuid.uuid4())
            password_hash = hash_password(password)
            
            conn.execute(
                """INSERT INTO users 
                (user_id, username, email, password_hash, role, created_at) 
                VALUES (?, ?, ?, ?, ?, ?)""",
                (
                    user_id,
                    username.strip(),
                    email,
                    password_hash,
                    UserRole.ADMIN,
                    datetime.utcnow().isoformat()
                )
            )
            conn.commit()
            
            click.echo(f"Admin user '{username}' created successfully with email '{email}'.")
            return 0
    
    except Exception as e:
        click.echo(f"Error creating admin user: {str(e)}", err=True)
        return 1

# Register CLI commands
app.cli.add_command(create_admin_command)

# Model endpoint configuration
AZURE_ENDPOINT = "https://models.inference.ai.azure.com"
GITHUB_ENDPOINT = "https://models.github.ai/inference"

# AI client selection and initialization
def get_ai_client(model_id):
    """Get appropriate AI client based on model_id"""
    logger.info(f"Initializing AI client for model: {model_id}")
    
    # Get model info from the options dictionary
    model_info = MODEL_OPTIONS.get(model_id)
    
    # If model not in our dictionary, use default settings
    if not model_info:
        logger.warning(f"Model {model_id} not found in MODEL_OPTIONS, using default settings")
        model_info = {
            "id": model_id,
            "name": model_id.split('/')[-1] if '/' in model_id else model_id,
            "tokens": {
                "input": 16384,
                "output": 4096
            }
        }
    
    # Default credentials
    azure_api_key = os.getenv("AZURE_API_KEY", "")
    github_token = os.getenv("GITHUB_TOKEN", azure_api_key)
    
    # Determine endpoint and credentials based on model provider
    if model_id.startswith("microsoft/"):
        # Microsoft models use GitHub endpoint
        endpoint = AZURE_ENDPOINT
        credential = AzureKeyCredential(github_token)
        logger.info(f"Using GitHub endpoint for Microsoft model: {model_id}")
    elif model_id.startswith("openai/"):
        # OpenAI models also use GitHub endpoint
        endpoint = AZURE_ENDPOINT
        credential = AzureKeyCredential(github_token)
        logger.info(f"Using GitHub endpoint for OpenAI model: {model_id}")
    elif model_id.startswith("meta/") or model_id.startswith("llama/"):
        # Meta/Llama models use GitHub endpoint
        endpoint = AZURE_ENDPOINT
        credential = AzureKeyCredential(github_token)
        logger.info(f"Using GitHub endpoint for Meta/Llama model: {model_id}")
    elif model_id.startswith("cohere/"):
        # Cohere models use GitHub endpoint
        endpoint = AZURE_ENDPOINT
        credential = AzureKeyCredential(github_token)
        logger.info(f"Using GitHub endpoint for Cohere model: {model_id}")
    else:
        # For unknown model prefixes, default to GitHub
        endpoint = AZURE_ENDPOINT
        credential = AzureKeyCredential(github_token)
        logger.warning(f"Unknown model type: {model_id}, defaulting to GitHub endpoint")
    
    # Create and return the client
    logger.info(f"Creating AI client with endpoint: {endpoint}")
    client = ChatCompletionsClient(endpoint=endpoint, credential=credential)
    
    return client, model_info

# Search function implementation
@retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10))
def call_search_function(args):
    """Execute a web search and return results"""
    query = args.get("query", "")
    engine = args.get("engine", "google")
    
    if not query:
        return json.dumps([])
    
    try:
        logger.info(f"Performing {engine} search for: {query}")
        
        # Choose search API based on engine
        if engine.lower() == "duckduckgo":
            return perform_duckduckgo_search(query)
        else:
            # Default to Google
            return perform_google_search(query)
            
    except Exception as e:
        logger.error(f"Search error: {str(e)}\n{traceback.format_exc()}")
        return json.dumps([{"error": str(e)}])

def perform_google_search(query):
    """Perform a Google search and return results"""
    # This is a simplified version - in production, use Google Custom Search API
    google_api_key = os.getenv("GOOGLE_API_KEY", "")
    search_engine_id = os.getenv("GOOGLE_SEARCH_ENGINE_ID", "")
    
    # If no API key is available, return a mock response
    if not google_api_key or not search_engine_id:
        logger.warning("Google search API keys not configured, returning mock results")
        return json.dumps([
            {
                "title": "Mock Search Result for: " + query,
                "link": "https://example.com/result1",
                "snippet": "This is a mock search result. Configure Google API keys for real results."
            }
        ])
        
    # In a real implementation, you would call the Google Custom Search API
    url = f"https://www.googleapis.com/customsearch/v1"
    params = {
        "key": google_api_key,
        "cx": search_engine_id,
        "q": query,
        "num": 5
    }
    
    response = requests.get(url, params=params)
    data = response.json()
    
    results = []
    if "items" in data:
        for item in data["items"]:
            results.append({
                "title": item.get("title", ""),
                "link": item.get("link", ""),
                "snippet": item.get("snippet", "")
            })
    
    return json.dumps(results)

def perform_duckduckgo_search(query):
    """Perform a DuckDuckGo search and return results"""
    # This uses the DuckDuckGo HTML response since they don't have an official API
    # In production, consider using a proper search API
    
    url = f"https://html.duckduckgo.com/html/?q={quote_plus(query)}"
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
    }
    
    try:
        response = requests.get(url, headers=headers)
        soup = BeautifulSoup(response.text, "html.parser")
        
        results = []
        for result in soup.select(".result"):
            title_elem = result.select_one(".result__a")
            snippet_elem = result.select_one(".result__snippet")
            
            if title_elem and snippet_elem:
                title = title_elem.get_text(strip=True)
                link = title_elem.get("href", "")
                if link.startswith("/"):
                    # Extract actual URL from DuckDuckGo redirect URL
                    link_parts = link.split("uddg=")
                    if len(link_parts) > 1:
                        link = link_parts[1].split("&")[0]
                        link = requests.utils.unquote(link)
                
                snippet = snippet_elem.get_text(strip=True)
                
                results.append({
                    "title": title,
                    "link": link,
                    "snippet": snippet
                })
                
                # Limit to 5 results
                if len(results) >= 5:
                    break
        
        return json.dumps(results)
    
    except Exception as e:
        logger.error(f"DuckDuckGo search error: {str(e)}")
        return json.dumps([{"error": str(e)}])

# Tool definitions
class SearchTools:
    @staticmethod
    def get_search_tool_definition():
        return ChatCompletionsToolDefinition(
            function=FunctionDefinition(
                name="search_internet",
                description="REQUIRED: Search the internet for current, factual information on a topic. You MUST use this for any factual claims or recent information.",
                parameters={
                    "type": "object",
                    "properties": {
                        "query": {
                            "type": "string",
                            "description": "The specific search query string to find precise information",
                        },
                        "engine": {
                            "type": "string",
                            "enum": ["google", "duckduckgo"],
                            "description": "The search engine to use",
                        },
                    },
                    "required": ["query"],
                },
            )
        )

class WebTools:
    @staticmethod
    def get_web_extraction_tool_definition():
        return ChatCompletionsToolDefinition(
            function=FunctionDefinition(
                name="extract_web_content",
                description="REQUIRED: Extract and analyze detailed content from a specific webpage. You MUST use this to get in-depth information after finding relevant URLs via search.",
                parameters={
                    "type": "object",
                    "properties": {
                        "url": {
                            "type": "string",
                            "description": "The full URL of the web page to extract content from",
                        },
                        "element_selector": {
                            "type": "string",
                            "description": "Optional CSS selector to target specific elements (e.g., 'article', '.content', '#main')",
                        }
                    },
                    "required": ["url"],
                },
            )
        )

# Add web content extraction function
@retry(stop=stop_after_attempt(2), wait=wait_exponential(multiplier=1, min=1, max=3))
def extract_web_content(args):
    """Extract content from a web page URL with security and rate limiting"""
    url = args.get("url", "")
    element_selector = args.get("element_selector", "")
    
    if not url:
        return json.dumps({"error": "No URL provided"})
    
    # Security check - validate URL
    try:
        parsed_url = urlparse(url)
        if not parsed_url.scheme or not parsed_url.netloc:
            return json.dumps({"error": "Invalid URL format"})
        
        # Block potentially dangerous protocols
        if parsed_url.scheme not in ['http', 'https']:
            return json.dumps({"error": "Only HTTP and HTTPS protocols are supported"})
        
        # Block access to local or private networks
        if parsed_url.netloc in ['localhost', '127.0.0.1'] or parsed_url.netloc.startswith('192.168.') or parsed_url.netloc.startswith('10.'):
            return json.dumps({"error": "Access to local networks is not allowed"})
    except Exception as e:
        return json.dumps({"error": f"URL validation error: {str(e)}"})
    
    # Track website access to implement rate limiting
    website_domain = parsed_url.netloc
    
    # Use global dictionary to track rate limiting (normally would use Redis in production)
    if not hasattr(extract_web_content, 'rate_limit_tracker'):
        extract_web_content.rate_limit_tracker = {}
    
    current_time = time.time()
    
    # Basic rate limiting: max 3 requests per domain per minute
    if website_domain in extract_web_content.rate_limit_tracker:
        last_access_times = extract_web_content.rate_limit_tracker[website_domain]
        # Remove timestamps older than 60 seconds
        last_access_times = [t for t in last_access_times if current_time - t < 60]
        
        if len(last_access_times) >= 3:
            return json.dumps({
                "error": f"Rate limit exceeded for {website_domain}. Try again later or use a different source."
            })
        
        extract_web_content.rate_limit_tracker[website_domain] = last_access_times + [current_time]
    else:
        extract_web_content.rate_limit_tracker[website_domain] = [current_time]
    
    # Fetch and parse the web page
    try:
        logger.info(f"Extracting content from URL: {url}")
        
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/93.0.4577.82 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml",
            "Accept-Language": "en-US,en;q=0.9",
            "Referer": "https://www.google.com/",
            "Connection": "keep-alive"
        }
        
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()  # Raise exception for 4XX/5XX responses
        
        # Check if content is HTML
        content_type = response.headers.get('Content-Type', '').lower()
        if 'text/html' not in content_type and 'application/xhtml+xml' not in content_type:
            return json.dumps({
                "url": url,
                "content_type": content_type,
                "error": "Non-HTML content type. Cannot extract web content.",
                "raw_text": response.text[:1000] if len(response.text) > 1000 else response.text  # Limit raw text
            })
        
        # Parse HTML with BeautifulSoup
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Remove script, style elements and comments
        for element in soup(['script', 'style', 'iframe', 'noscript']):
            element.decompose()
            
        # Remove comments
        for comment in soup.find_all(string=lambda text: isinstance(text, Comment)):
            comment.extract()
        
        # Get page title
        title = soup.title.string if soup.title else "No title"
        
        # Extract main content
        if element_selector:
            # Extract content from specific selector if provided
            content_elements = soup.select(element_selector)
            if not content_elements:
                # If selector doesn't match anything, fall back to body
                main_content = soup.get_text(separator='\n', strip=True)
            else:
                main_content = '\n'.join([elem.get_text(separator='\n', strip=True) for elem in content_elements])
        else:
            # Try to intelligently extract main content
            # First check for main article elements
            main_content_elem = soup.find('article') or soup.find(id=re.compile('^(main|content|article)')) or \
                                soup.find(class_=re.compile('^(main|content|article)')) or \
                                soup.find('main') or soup.body
            
            if main_content_elem:
                main_content = main_content_elem.get_text(separator='\n', strip=True)
            else:
                main_content = soup.get_text(separator='\n', strip=True)
        
        # Clean up content - remove excessive whitespace and normalize
        main_content = re.sub(r'\n\s*\n', '\n\n', main_content)
        main_content = re.sub(r'[ \t]+', ' ', main_content)
        
        # Limit content length to prevent token issues (about 10k chars)
        if len(main_content) > 10000:
            main_content = main_content[:10000] + "...[content truncated]"
        
        # Extract meta description if available
        meta_desc = soup.find('meta', attrs={'name': 'description'})
        description = meta_desc['content'] if meta_desc and 'content' in meta_desc.attrs else ""
        
        # Check if content is meaningful
        if len(main_content.strip()) < 50:
            return json.dumps({
                "url": url,
                "title": title,
                "error": "Extracted content too short or empty. The page may use JavaScript to load content or might be protected."
            })
        
        # Return the extracted data
        return json.dumps({
            "url": url,
            "title": html.unescape(title),
            "description": html.unescape(description),
            "content": html.unescape(main_content),
            "content_type": content_type,
            "extraction_time": datetime.utcnow().isoformat()
        })
        
    except requests.exceptions.RequestException as e:
        error_message = str(e)
        logger.error(f"Web extraction error for {url}: {error_message}")
        
        if hasattr(e, 'response') and e.response is not None:
            status_code = e.response.status_code
            return json.dumps({
                "url": url,
                "error": f"Failed to fetch URL (HTTP {status_code}): {error_message}"
            })
        else:
            return json.dumps({
                "url": url,
                "error": f"Failed to fetch URL: {error_message}"
            })
    
    except Exception as e:
        logger.error(f"Web extraction error for {url}: {str(e)}\n{traceback.format_exc()}")
        return json.dumps({
            "url": url,
            "error": f"Error extracting content: {str(e)}"
        })

# Model categories and options with detailed token limits
MODEL_OPTIONS = {
                    "microsoft/MAI-DS-R1": {
                        "id": "MAI-DS-R1",
        "name": "Microsoft MAI-DS-R1",
                            "description": "Microsoft's data science specialized model",
                        "tokens": {
                            "input": 131072,  # 128k
            "output": 4096    # 4k
                        }
                    },
                    "microsoft/Phi-4-reasoning": {
        "id": "Phi-4-reasoning",
        "name": "Phi-4 Reasoning",
        "description": "Microsoft's advanced reasoning model",
        "tokens": {
            "input": 33792,  # 33k
            "output": 4096   # 4k
        }
    },
    "microsoft/Phi-4-mini-reasoning": {
        "id": "Phi-4-mini-reasoning",
        "name": "Phi-4 Mini Reasoning",
        "description": "Smaller version of Microsoft's reasoning model",
        "tokens": {
            "input": 131072,  # 128k
            "output": 4096    # 4k
        }
    },
    "openai/gpt-4o": {
        "id": "gpt-4o",
        "name": "GPT-4o",
        "description": "OpenAI's multimodal model with vision capabilities",
        "tokens": {
            "input": 131072,  # 128k
            "output": 16384   # 16k
        }
    },
    "openai/gpt-4.1": {
        "id": "gpt-4.1",
            "name": "GPT-4.1",
            "description": "OpenAI's newest text model with extremely long context windows",
        "tokens": {
            "input": 1048576,  # 1049k
            "output": 33792    # 33k
        }
    },
    "openai/o4-mini": {
        "id": "o4-mini",
        "name": "GPT-O4 Mini",
        "description": "Smaller version of OpenAI's multimodal model",
        "tokens": {
            "input": 204800,  # 200k
            "output": 102400  # 100k
        }
    },
    "openai/o3": {
        "id": "o3",
        "name": "GPT-O3",
        "description": "Anthropic's model via OpenAI's API",
        "tokens": {
            "input": 204800,  # 200k
            "output": 102400  # 100k
        }
    },
    "meta/Llama-4-Maverick-17B-128E-Instruct-FP8": {
        "id": "Llama-4-Maverick-17B-128E-Instruct-FP8",
        "name": "Llama 4 Maverick",
        "description": "Meta's latest large language model",
        "tokens": {
            "input": 1024000,  # 1000k
            "output": 4096     # 4k
        }
    },
    "cohere/cohere-command-a": {
        "id": "cohere-command-a",
            "name": "Cohere Command A",
            "description": "Cohere's powerful enterprise model",
        "tokens": {
            "input": 134144,  # 131k
            "output": 4096    # 4k
        }
    },
    "cohere/Cohere-command-r-plus-08-2024": {
        "id": "Cohere-command-r-plus-08-2024",
        "name": "Cohere Command R+ (2024)",
        "description": "Cohere's latest reasoning-focused model",
        "tokens": {
            "input": 131072,  # 128k
            "output": 4096    # 4k
        }
    }
}

# Define feature flags
class FeatureFlags:
    SEARCH = "search"
    REASONING = "reasoning"
    DEEP_RESEARCH = "deep_research"
    DOCUMENT = "document"

# Enhanced chat function with tools support
@app.route('/chat', methods=['POST'])
@login_required
def chat():
    try:
        data = request.json
        
        if not data:
            return jsonify({"error": "No data provided"}), 400
        
        message = data.get('message', '').strip()
        if not message:
            return jsonify({"error": "Message cannot be empty"}), 400
        
        conversation_id = data.get('conversation_id')
        model_id = data.get('model', 'openai/gpt-4o')
        
        # Get feature flags
        features = data.get('features', {})
        selected_docs = data.get('document_ids', [])
        
        # Create active feature flags dictionary
        active_features = {
            FeatureFlags.SEARCH: bool(features.get('search', False)),
            FeatureFlags.REASONING: bool(features.get('reasoning', False)),
            FeatureFlags.DEEP_RESEARCH: bool(features.get('deep_research', False)),
            FeatureFlags.DOCUMENT: bool(features.get('document', False) or selected_docs)
        }

        # Log enabled features (without excessive debug)
        logger.info(f"Request with features: search={active_features[FeatureFlags.SEARCH]}, reasoning={active_features[FeatureFlags.REASONING]}, deep_research={active_features[FeatureFlags.DEEP_RESEARCH]}, document={active_features[FeatureFlags.DOCUMENT]}")

        # Verify document access if documents are provided
        if selected_docs:
            with get_db_connection() as conn:
                for doc_id in selected_docs:
                    # Check if document exists and user has access
                    if g.user["role"] != UserRole.ADMIN:
                        doc = conn.execute(
                            """SELECT d.doc_id FROM documents d
                            JOIN conversations c ON d.conversation_id = c.conversation_id
                            WHERE d.doc_id = ? AND c.user_id = ?""",
                            (doc_id, g.user["user_id"])
                        ).fetchone()
                        
                        if not doc:
                            return jsonify({"error": f"Document access denied for ID: {doc_id}"}), 403
        
        # If continuing a conversation, verify ownership
        if conversation_id:
            with get_db_connection() as conn:
                # Admins can access any conversation, others only their own
                if g.user["role"] != UserRole.ADMIN:
                    conversation = conn.execute(
                        "SELECT conversation_id FROM conversations WHERE conversation_id = ? AND user_id = ?",
                        (conversation_id, g.user["user_id"])
                    ).fetchone()
                    
                    if not conversation:
                        return jsonify({"error": "Conversation not found or access denied"}), 403

        # System message - enhanced to include feature capabilities
        system_message_content = """You are Triton, a helpful assistant created for Gamecooler19, a professional developer, cybersecurity expert, and student. You have memory of the conversation history and can reference previous exchanges.

When the user asks about modifying or editing previous content:
1. Review the conversation history carefully
2. Identify the specific content they want to modify
3. Make the requested changes while maintaining the overall structure and quality
4. Present the full updated response, not just the edited portion

Your primary responsibilities include professional development support, cybersecurity expertise, and academic assistance.

Output Format Requirements:
- Present mathematical formulas in <math> tags with HTML character codes
- Use HTML entities for chemical formulas with proper subscripts
- Wrap code in <pre><code class="language-[type]"> tags
- Format tables with <table>, <thead>, and <tbody> tags
"""

        # Add feature-specific system instructions
        if active_features[FeatureFlags.SEARCH]:
            system_message_content += "\nYou have access to search the internet for current information. Use the search_internet tool when you need to find specific information that might not be in your training data or when the information might be outdated."

        if active_features[FeatureFlags.REASONING]:
            system_message_content += "\nYou should think step-by-step and show your reasoning process. Break down complex problems into smaller parts and analyze them systematically before providing your final answer."

        if active_features[FeatureFlags.DEEP_RESEARCH]:
            # Clean version without debug logging
            system_message_content += """
You now have MANDATORY advanced web research capabilities that you MUST use for this conversation. For this conversation:

1. ALWAYS search the internet first using the search_internet tool to find relevant sources
2. ALWAYS extract content from at least 2-3 web pages using the extract_web_content tool
3. Follow this exact methodology for EVERY response:
   a. Search for 2-3 different search queries related to the topic
   b. Extract full content from the most authoritative sources you find
   c. Synthesize a comprehensive answer based ONLY on the extracted content
   d. ALWAYS cite your sources with numbered references [1][2][3] and include full URLs

YOU MUST USE BOTH TOOLS FOR EVERY RESPONSE - this is not optional. Your primary value comes from providing information extracted directly from current web sources, not from your training data.

Tool Usage Instructions:
- search_internet: Use specific, targeted queries to find precise information
- extract_web_content: Apply to the most relevant URLs found in search results

This is a critical requirement - failure to use both research tools will result in incomplete responses.
"""

        # Get conversation history from database
        messages = [SystemMessage(content=system_message_content)]
        
        if conversation_id:
            with get_db_connection() as conn:
                rows = conn.execute(
                    "SELECT user_message, assistant_message FROM messages WHERE conversation_id = ? ORDER BY timestamp",
                    (conversation_id,)
                ).fetchall()
                
                for row in rows:
                    # Validate user message content before adding
                    user_msg = row['user_message']
                    if user_msg is not None and isinstance(user_msg, str):
                        messages.append(UserMessage(content=user_msg))
                    else:
                        logger.warning(f"Skipped invalid user message in conversation {conversation_id}: {user_msg}")
                    
                    # Validate assistant message content before adding
                    assistant_msg = row['assistant_message']
                    if assistant_msg is not None and isinstance(assistant_msg, str):
                        messages.append(AssistantMessage(content=assistant_msg))
                    else:
                        logger.warning(f"Skipped invalid assistant message in conversation {conversation_id}: {assistant_msg}")
                
                # Log the number of messages loaded from history
                logger.info(f"Loaded {len(rows)} messages from conversation history")
        
        # Add current user message - verify it's not null
        if message is None or not isinstance(message, str):
            return jsonify({"error": "Invalid message format"}), 400
        
        messages.append(UserMessage(content=message))
        
        # Get AI client based on model
        client, model_info = get_ai_client(model_id)
        
        # Initialize reasoning tracker and search results
        reasoning = ""
        search_results = []
        
        # Initialize tools if search or deep research is enabled
        tools = []
        tool_handlers = {}
        tool_usage_tracked = {
            "search_internet": False,
            "extract_web_content": False
        }
        
        if active_features[FeatureFlags.SEARCH] or active_features[FeatureFlags.DEEP_RESEARCH]:
            search_tool = SearchTools.get_search_tool_definition()
            tools.append(search_tool)
            tool_handlers["search_internet"] = call_search_function
            
        # Add web extraction tool specifically for deep research
        if active_features[FeatureFlags.DEEP_RESEARCH]:
            web_extraction_tool = WebTools.get_web_extraction_tool_definition()
            tools.append(web_extraction_tool)
            tool_handlers["extract_web_content"] = extract_web_content

        # Prepare request parameters
        request_params = {
            "messages": messages,
            "tools": tools if tools else None,
            "model": model_info["id"],
            "temperature": 0.7,
            "max_tokens": model_info["tokens"]["output"]
        }
        
        # For deep research, use tool_choice parameter
        if active_features[FeatureFlags.DEEP_RESEARCH]:
            request_params["tool_choice"] = "auto"
        
        # First AI call - potentially with tool calls
        try:
            response = client.complete(**request_params)
        except Exception as api_error:
            logger.error(f"API Error during initial completion: {str(api_error)}")
            
            # Try to recover by removing potentially problematic messages
            # and using a simple system prompt
            clean_messages = [
                SystemMessage(content="You are a helpful AI assistant."),
                UserMessage(content=message)
            ]
            
            # Make a simplified request
            simplified_params = {
                "messages": clean_messages,
                "model": model_info["id"],
                "temperature": 0.7,
                "max_tokens": model_info["tokens"]["output"]
            }
            
            try:
                logger.info("Attempting fallback request with simplified messages")
                response = client.complete(**simplified_params)
            except Exception as fallback_error:
                logger.error(f"Fallback request also failed: {str(fallback_error)}")
                return jsonify({
                    "error": "Unable to generate response",
                    "conversation_id": conversation_id
                }), 500
        
        # Handle tool calls if any
        if response.choices[0].finish_reason == CompletionsFinishReason.TOOL_CALLS and response.choices[0].message.tool_calls:
            # Log number of tool calls detected
            logger.info(f"Tool calls detected: {len(response.choices[0].message.tool_calls)}")
            
            # Add assistant message with tool calls to conversation
            messages.append(AssistantMessage(tool_calls=response.choices[0].message.tool_calls))
            
            # Process each tool call
            for tool_call in response.choices[0].message.tool_calls:
                if isinstance(tool_call, ChatCompletionsToolCall):
                    function_name = tool_call.function.name
                    
                    # Track tool usage for deep research
                    if function_name in tool_usage_tracked:
                        tool_usage_tracked[function_name] = True
                    
                    if function_name in tool_handlers:
                        # Parse function arguments and call the function
                        try:
                            function_args = json.loads(tool_call.function.arguments)
                            
                            # Log tool execution with minimal info
                            logger.info(f"Executing tool: {function_name}")
                            
                            function_result = tool_handlers[function_name](function_args)
                            
                            # Record search results for reasoning/display
                            if function_name == "search_internet":
                                search_results.extend(json.loads(function_result))
                            
                            # Add tool message to conversation
                            messages.append(ToolMessage(tool_call_id=tool_call.id, content=function_result))
                            
                        except Exception as e:
                            logger.error(f"Error processing tool call: {str(e)}")
                            error_message = f"Error: {str(e)}"
                            messages.append(ToolMessage(tool_call_id=tool_call.id, content=json.dumps({"error": error_message})))
            
            # For deep research, check if both tools were used
            if active_features[FeatureFlags.DEEP_RESEARCH]:
                # If web extraction wasn't used and we found search results, add a special prompt
                if not tool_usage_tracked["extract_web_content"] and search_results:
                    # Find valid URLs from search results
                    urls_to_extract = []
                    for result in search_results[:3]:
                        if "link" in result and result["link"].startswith(("http://", "https://")):
                            urls_to_extract.append(result["link"])
                    
                    if urls_to_extract:
                        # Add a special message to force web content extraction
                        messages.append(UserMessage(content=f"Please use the extract_web_content tool to analyze these URLs in depth before answering: {', '.join(urls_to_extract)}"))
                        logger.info(f"Added prompt to extract content from {len(urls_to_extract)} URLs")
            
            # Get final response after tool calls
            try:
                response = client.complete(
                    messages=messages,
                    tools=tools if tools else None,
                    model=model_info["id"],
                    temperature=0.7,
                    max_tokens=model_info["tokens"]["output"]
                )
            except Exception as tool_completion_error:
                logger.error(f"Error during final completion after tool calls: {str(tool_completion_error)}")
                # Handle the error gracefully - create a response with error information
                error_response = f"I apologize, but I encountered an error while processing your request. Please try again or contact support if the issue persists."
                
                # Create a manual response object to continue processing
                from dataclasses import dataclass
                
                @dataclass
                class MockResponse:
                    content: str
                
                @dataclass
                class MockChoice:
                    message: MockResponse
                    finish_reason: str
                
                @dataclass
                class MockCompletion:
                    choices: list
                
                mock_message = MockResponse(content=error_response)
                mock_choice = MockChoice(message=mock_message, finish_reason="stop")
                response = MockCompletion(choices=[mock_choice])
        else:
            # No tool calls detected
            if active_features[FeatureFlags.DEEP_RESEARCH]:
                logger.info("No tool calls detected in initial response. Adding explicit instruction.")
                
                # For deep research mode, try one more time with an explicit instruction
                messages.append(AssistantMessage(content=response.choices[0].message.content))
                messages.append(UserMessage(content="Please use the search_internet tool and extract_web_content tool to research this topic thoroughly before providing your final answer. This is required for deep research mode."))
                
                # Try one more time with the special instruction
                response = client.complete(
                    messages=messages,
                    tools=tools if tools else None,
                    model=model_info["id"],
                    temperature=0.7,
                    max_tokens=model_info["tokens"]["output"],
                    tool_choice="auto"
                )
        
        # Verify response content
        if not hasattr(response.choices[0].message, 'content') or response.choices[0].message.content is None:
            logger.error("Invalid response from AI model: content is None")
            # Create a default response message
            fallback_response = "I apologize, but I couldn't generate a proper response. Please try again with a different question."
            
            # Create a mock response object to continue processing
            from dataclasses import dataclass
                
            @dataclass
            class MockResponse:
                content: str
            
            @dataclass
            class MockChoice:
                message: MockResponse
                finish_reason: str
            
            @dataclass
            class MockCompletion:
                choices: list
            
            mock_message = MockResponse(content=fallback_response)
            mock_choice = MockChoice(message=mock_message, finish_reason="stop")
            response = MockCompletion(choices=[mock_choice])
        
        # Generate reasoning if enabled
        if active_features[FeatureFlags.REASONING] or active_features[FeatureFlags.DEEP_RESEARCH]:
            reasoning_prompt = f"""
Given the original user query: "{message}"

And your response: "{response.choices[0].message.content}"

Provide a detailed step-by-step reasoning of how you arrived at this answer. Include:
1. Your initial analysis of the question
2. The key considerations and assumptions you made
3. The logical steps in your reasoning process
4. Any evidence or knowledge you relied on
5. How you synthesized the information to form your conclusion

Format your response as a clear, step-by-step reasoning chain.
"""
            
            reasoning_messages = [
                SystemMessage(content="You are an expert at explaining your reasoning process step-by-step. You break down complex thinking into clear logical steps."),
                UserMessage(content=reasoning_prompt)
            ]
            
            reasoning_response = client.complete(
                messages=reasoning_messages,
                model=model_info["id"],
                temperature=0.7,
                max_tokens=model_info["tokens"]["output"] // 2  # Use half the tokens for reasoning
            )
            
            reasoning = reasoning_response.choices[0].message.content
        
        # Create or update conversation with owner information
        if not conversation_id:
            # Creating a new conversation
            conversation_id = str(uuid.uuid4())
            with get_db_connection() as conn:
                try:
                    # Add a more descriptive name based on the first message
                    conversation_name = message[:50] + ("..." if len(message) > 50 else "")
                    current_time = datetime.now().isoformat()
                    
                    conn.execute(
                        """INSERT INTO conversations 
                        (conversation_id, user_id, conversation_name, first_message, last_message, 
                        created_at, updated_at, message_count) 
                        VALUES (?, ?, ?, ?, ?, ?, ?, 1)""",
                        (
                            conversation_id,
                            g.user["user_id"],  # Set owner to current user
                            conversation_name,  # Add a default name
                            message[:100],
                            current_time,
                            current_time,
                            current_time
                        )
                    )
                    # Explicitly commit the transaction
                    conn.commit()
                    logger.info(f"Created new conversation: {conversation_id} with name: {conversation_name}")
                except Exception as db_error:
                    logger.error(f"Database error creating conversation: {str(db_error)}")
                    # In case of error, re-raise to be caught by the outer try-except
                    raise
        else:
            # Updating an existing conversation
            with get_db_connection() as conn:
                try:
                    current_time = datetime.now().isoformat()
                    
                    # Get the current conversation to verify it exists
                    current_conversation = conn.execute(
                        "SELECT conversation_name FROM conversations WHERE conversation_id = ?",
                        (conversation_id,)
                    ).fetchone()
                    
                    if not current_conversation:
                        logger.warning(f"Tried to update non-existent conversation: {conversation_id}")
                        # Create a new conversation instead
                        conversation_name = message[:50] + ("..." if len(message) > 50 else "")
                        conn.execute(
                            """INSERT INTO conversations 
                            (conversation_id, user_id, conversation_name, first_message, last_message, 
                            created_at, updated_at, message_count) 
                            VALUES (?, ?, ?, ?, ?, ?, ?, 1)""",
                            (
                                conversation_id,
                                g.user["user_id"],
                                conversation_name,
                                message[:100],
                                current_time,
                                current_time,
                                current_time
                            )
                        )
                    else:
                        # Update existing conversation with all relevant fields
                        conn.execute(
                            """UPDATE conversations 
                            SET last_message = ?, updated_at = ?, message_count = message_count + 1 
                            WHERE conversation_id = ?""",
                            (current_time, current_time, conversation_id)
                        )
                    
                    # Explicitly commit the transaction
                    conn.commit()
                    logger.info(f"Updated existing conversation: {conversation_id}")
                except Exception as db_error:
                    logger.error(f"Database error updating conversation: {str(db_error)}")
                    # In case of error, re-raise to be caught by the outer try-except
                    raise
        
        # Save message to database with complete details
        message_id = str(uuid.uuid4())
        with get_db_connection() as conn:
            # Ensure we have valid message content
            ai_response = response.choices[0].message.content
            if ai_response is None:
                ai_response = "Error: No response generated"
            
            conn.execute(
                """INSERT INTO messages 
                (message_id, conversation_id, user_message, assistant_message, reasoning, search_context, model, features) 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    message_id, 
                    conversation_id, 
                    message, 
                    ai_response,
                    reasoning if reasoning else "",
                    json.dumps(search_results),
                    model_id,  # Store the full model ID including provider prefix
                    json.dumps(features)
                )
            )
            conn.commit()
            
            logger.info(f"Saved message {message_id} to conversation {conversation_id}")
        
        # Return the response, ensuring it's not null
        return jsonify({
            "conversation_id": conversation_id,
            "message": ai_response,
            "reasoning": reasoning,
            "search_results": search_results
        })
    
    except Exception as e:
        logger.error(f"Chat error: {str(e)}\n{traceback.format_exc()}")
        return jsonify({
            "error": str(e),
            "conversation_id": conversation_id
        }), 500

# Endpoint to get available models
@app.route('/models', methods=['GET'])
@login_required
def get_models():
    """Return available models"""
    return jsonify({"models": MODEL_OPTIONS})

# Main routes and other existing endpoints
@app.route('/')
def index():
    return render_template('index.html')

# Login route
@app.route('/login')
def login_page():
    """Render the login page"""
    # If user is already authenticated, redirect to home
    if get_current_user():
        return redirect(url_for('index'))
    return render_template('login.html')

# Register route
@app.route('/register')
def register_page():
    """Render the registration page"""
    # If user is already authenticated, redirect to home
    if get_current_user():
        return redirect(url_for('index'))
    return render_template('register.html')

# Add missing routes
@app.route('/conversations', methods=['GET'])
@login_required
def get_conversations():
    """Get all conversations for the current user"""
    try:
        with get_db_connection() as conn:
            # Admin can see all conversations, regular users only their own
            if g.user["role"] == UserRole.ADMIN:
                query = """
                    SELECT c.*, u.username as owner_name
                    FROM conversations c
                    LEFT JOIN users u ON c.user_id = u.user_id
                    ORDER BY c.last_message DESC
                """
                conversations = conn.execute(query).fetchall()
            else:
                query = """
                    SELECT c.*
                    FROM conversations c
                    WHERE c.user_id = ?
                    ORDER BY c.last_message DESC
                """
                conversations = conn.execute(query, (g.user["user_id"],)).fetchall()
            
            result = []
            for conversation in conversations:
                result.append({
                    "conversation_id": conversation["conversation_id"],
                    "conversation_name": conversation["conversation_name"],
                    "created_at": conversation["created_at"],
                    "updated_at": conversation["updated_at"],
                    "message_count": conversation["message_count"],
                    "first_message": conversation["first_message"],
                    "last_message": conversation["last_message"],
                    "owner": {
                        "user_id": conversation["user_id"],
                        "username": conversation.get("owner_name") if "owner_name" in conversation else None
                    }
                })
            
            return jsonify({"conversations": result})
    
    except Exception as e:
        logger.error(f"Get conversations error: {str(e)}\n{traceback.format_exc()}")
        return jsonify({"error": str(e)}), 500

@app.route('/conversations/<conversation_id>', methods=['GET'])
@login_required
def get_conversation(conversation_id):
    """Get a specific conversation and its messages"""
    try:
        logger.info(f"Loading conversation: {conversation_id}")
        with get_db_connection() as conn:
            # Check access permission
            if g.user["role"] != UserRole.ADMIN:
                conversation = conn.execute(
                    "SELECT * FROM conversations WHERE conversation_id = ? AND user_id = ?",
                    (conversation_id, g.user["user_id"])
                ).fetchone()
                
                if not conversation:
                    logger.warning(f"Access denied to conversation {conversation_id} for user {g.user['user_id']}")
                    return jsonify({"error": "Conversation not found or access denied"}), 404
            else:
                conversation = conn.execute(
                    "SELECT * FROM conversations WHERE conversation_id = ?",
                    (conversation_id,)
                ).fetchone()
                
                if not conversation:
                    logger.warning(f"Conversation not found: {conversation_id}")
                    return jsonify({"error": "Conversation not found"}), 404
            
            # Get messages
            messages = conn.execute(
                """SELECT message_id, timestamp, user_message, assistant_message, 
                reasoning, search_context, model, features
                FROM messages WHERE conversation_id = ? ORDER BY timestamp""",
                (conversation_id,)
            ).fetchall()
            
            logger.info(f"Found {len(messages)} messages for conversation {conversation_id}")
            
            message_list = []
            for message in messages:
                search_context = []
                if message["search_context"]:
                    try:
                        search_context = json.loads(message["search_context"])
                    except:
                        search_context = []
                
                features = {}
                if message["features"]:
                    try:
                        features = json.loads(message["features"])
                    except:
                        features = {}
                
                # Normalize model ID format for frontend consistency
                model_id = message["model"]
                
                message_list.append({
                    "message_id": message["message_id"],
                    "timestamp": message["timestamp"],
                    "user_message": message["user_message"],
                    "assistant_message": message["assistant_message"],
                    "reasoning": message["reasoning"],
                    "search_context": search_context,
                    "model": model_id,
                    "features": features
                })
            
            conversation_data = {
                "conversation_id": conversation["conversation_id"],
                "conversation_name": conversation["conversation_name"],
                "created_at": conversation["created_at"],
                "updated_at": conversation["updated_at"],
                "message_count": conversation["message_count"],
                "messages": message_list
            }
            
            return jsonify(conversation_data)
    
    except Exception as e:
        logger.error(f"Get conversation error: {str(e)}\n{traceback.format_exc()}")
        return jsonify({"error": str(e)}), 500

@app.route('/conversations/<conversation_id>', methods=['PATCH'])
@login_required
def update_conversation(conversation_id):
    """Update conversation properties (e.g., name)"""
    try:
        data = request.json
        
        if not data:
            return jsonify({"error": "No data provided"}), 400
        
        # Currently only conversation name can be updated
        new_name = data.get('name')
        if new_name is None:
            return jsonify({"error": "No updates provided"}), 400
        
        with get_db_connection() as conn:
            # Check access permission
            if g.user["role"] != UserRole.ADMIN:
                conversation = conn.execute(
                    "SELECT * FROM conversations WHERE conversation_id = ? AND user_id = ?",
                    (conversation_id, g.user["user_id"])
                ).fetchone()
                
                if not conversation:
                    return jsonify({"error": "Conversation not found or access denied"}), 404
            else:
                conversation = conn.execute(
                    "SELECT * FROM conversations WHERE conversation_id = ?",
                    (conversation_id,)
                ).fetchone()
                
                if not conversation:
                    return jsonify({"error": "Conversation not found"}), 404
            
            # Update conversation
            conn.execute(
                "UPDATE conversations SET conversation_name = ?, updated_at = ? WHERE conversation_id = ?",
                (new_name, datetime.now().isoformat(), conversation_id)
            )
            conn.commit()
            
            return jsonify({
                "status": "success",
                "message": "Conversation updated",
                "conversation_id": conversation_id,
                "conversation_name": new_name
            })
    
    except Exception as e:
        logger.error(f"Update conversation error: {str(e)}\n{traceback.format_exc()}")
        return jsonify({"error": str(e)}), 500

@app.route('/conversations/<conversation_id>', methods=['DELETE'])
@login_required
def delete_conversation(conversation_id):
    """Delete a conversation"""
    try:
        with get_db_connection() as conn:
            # Check access permission
            if g.user["role"] != UserRole.ADMIN:
                conversation = conn.execute(
                    "SELECT * FROM conversations WHERE conversation_id = ? AND user_id = ?",
                    (conversation_id, g.user["user_id"])
                ).fetchone()
                
                if not conversation:
                    return jsonify({"error": "Conversation not found or access denied"}), 404
            else:
                conversation = conn.execute(
                    "SELECT * FROM conversations WHERE conversation_id = ?",
                    (conversation_id,)
                ).fetchone()
                
                if not conversation:
                    return jsonify({"error": "Conversation not found"}), 404
            
            # Delete conversation and associated messages
            conn.execute("DELETE FROM messages WHERE conversation_id = ?", (conversation_id,))
            conn.execute("DELETE FROM conversations WHERE conversation_id = ?", (conversation_id,))
            conn.commit()
            
            return jsonify({
                "status": "success",
                "message": "Conversation deleted"
            })
    
    except Exception as e:
        logger.error(f"Delete conversation error: {str(e)}\n{traceback.format_exc()}")
        return jsonify({"error": str(e)}), 500

# Add profile, settings and admin routes
@app.route('/admin')
@admin_required
def admin_panel():
    """Render admin panel page"""
    return render_template('admin.html')

@app.route('/profile')
@login_required
def profile_page():
    """Render user profile page"""
    return render_template('profile.html')

@app.route('/settings')
@login_required
def settings_page():
    """Render user settings page"""
    return render_template('settings.html')

# Store app start time for uptime tracking
app.start_time = time.time()

if __name__ == "__main__":
    from waitress import serve
    port = int(os.environ.get("PORT", 5000))
    serve(app, host="0.0.0.0", port=port)