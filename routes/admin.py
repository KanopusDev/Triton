import os
import uuid
import json
import logging
from typing import Dict, List, Any, Optional, Union
from datetime import datetime, timedelta
import secrets
from functools import wraps
from flask import Blueprint, request, jsonify, g, current_app
import bcrypt

# Import database service
from services.database import DatabaseService
from services.monitor import MonitoringService

# Configure logging
logger = logging.getLogger("triton.admin")

# Create blueprint
admin_bp = Blueprint('admin', __name__, url_prefix='/api/admin')

# Get database service instance
def get_db():
    """Get database service instance"""
    if not hasattr(g, 'db_service'):
        db_path = current_app.config.get("DATABASE_PATH", "triton.db")
        g.db_service = DatabaseService(db_path, current_app.config)
    return g.db_service

# Get monitoring service instance
def get_monitor():
    """Get monitoring service instance"""
    if not hasattr(g, 'monitor_service'):
        g.monitor_service = MonitoringService(
            app_name="Triton Admin",
            config=current_app.config
        )
    return g.monitor_service

# Verify admin access for all routes
@admin_bp.before_request
def verify_admin_access():
    """Verify that the current user has admin privileges"""
    if not g.user or g.user.get("role") != "admin":
        return jsonify({"error": "Administrator privileges required"}), 403

# User management endpoints
@admin_bp.route('/users', methods=['GET'])
def get_users():
    """Get all users"""
    try:
        db = get_db()
        
        # Support pagination
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 20, type=int)
        
        # Calculate offset
        offset = (page - 1) * per_page
        
        # Get total count
        total_count = db.execute_query(
            "SELECT COUNT(*) as count FROM users", 
            fetch_mode="one"
        )["count"]
        
        # Get users with pagination
        users = db.execute_query(
            """SELECT user_id, username, email, role, created_at, last_login, active 
            FROM users ORDER BY created_at DESC LIMIT ? OFFSET ?""",
            (per_page, offset),
            fetch_mode="all"
        )
        
        # Format the response
        user_list = []
        for user in users:
            user_list.append({
                "user_id": user["user_id"],
                "username": user["username"],
                "email": user["email"],
                "role": user["role"],
                "created_at": user["created_at"],
                "last_login": user["last_login"],
                "active": bool(user["active"])
            })
        
        return jsonify({
            "users": user_list,
            "pagination": {
                "page": page,
                "per_page": per_page,
                "total": total_count,
                "pages": (total_count + per_page - 1) // per_page
            }
        })
    except Exception as e:
        logger.error(f"Error getting users: {str(e)}")
        return jsonify({"error": str(e)}), 500

@admin_bp.route('/users/<user_id>', methods=['GET'])
def get_user(user_id):
    """Get user details by ID"""
    try:
        db = get_db()
        user = db.get_user_by_id(user_id)
        
        if not user:
            return jsonify({"error": "User not found"}), 404
            
        # Get user activity stats
        stats = db.execute_query(
            """SELECT COUNT(*) as conversation_count 
            FROM conversations WHERE user_id = ?""",
            (user_id,),
            fetch_mode="one",
            cache=True
        )
        
        # Get last login from sessions
        last_session = db.execute_query(
            """SELECT created_at FROM sessions 
            WHERE user_id = ? ORDER BY created_at DESC LIMIT 1""",
            (user_id,),
            fetch_mode="one"
        )
        
        # Enhance user object with stats
        user["conversation_count"] = stats["conversation_count"] if stats else 0
        user["last_session"] = last_session["created_at"] if last_session else None
        
        return jsonify({"user": user})
    except Exception as e:
        logger.error(f"Error getting user {user_id}: {str(e)}")
        return jsonify({"error": str(e)}), 500

@admin_bp.route('/users', methods=['POST'])
def create_user():
    """Create a new user"""
    try:
        data = request.json
        
        if not data:
            return jsonify({"error": "No data provided"}), 400
            
        # Validate required fields
        required_fields = ['username', 'email', 'password']
        for field in required_fields:
            if field not in data or not data[field]:
                return jsonify({"error": f"Missing required field: {field}"}), 400
        
        db = get_db()
        
        # Check if email already exists
        existing_user = db.get_user_by_email(data['email'])
        if existing_user:
            return jsonify({"error": "Email already in use"}), 409
        
        # Generate user ID
        user_id = str(uuid.uuid4())
        
        # Hash password
        password_hash = bcrypt.hashpw(
            data['password'].encode('utf-8'), 
            bcrypt.gensalt()
        ).decode('utf-8')
        
        # Create user object
        user_data = {
            "user_id": user_id,
            "username": data['username'],
            "email": data['email'].lower(),
            "password_hash": password_hash,
            "role": data.get('role', 'user')  # Default to regular user
        }
        
        # Create user in database
        db.create_user(user_data)
        
        # Log the action
        logger.info(f"Admin {g.user['username']} created new user: {data['email']}")
        
        # Get the created user without password
        created_user = db.get_user_by_id(user_id)
        
        return jsonify({
            "message": "User created successfully",
            "user": created_user
        }), 201
    except Exception as e:
        logger.error(f"Error creating user: {str(e)}")
        return jsonify({"error": str(e)}), 500

@admin_bp.route('/users/<user_id>', methods=['PUT', 'PATCH'])
def update_user(user_id):
    """Update user details"""
    try:
        data = request.json
        
        if not data:
            return jsonify({"error": "No data provided"}), 400
            
        db = get_db()
        
        # Check if user exists
        existing_user = db.get_user_by_id(user_id)
        if not existing_user:
            return jsonify({"error": "User not found"}), 404
        
        # Prepare update data
        updates = {}
        
        # Update allowed fields
        if 'username' in data and data['username']:
            updates['username'] = data['username']
            
        if 'email' in data and data['email']:
            # Check if email is being changed and is unique
            if data['email'].lower() != existing_user['email'].lower():
                email_check = db.get_user_by_email(data['email'])
                if email_check:
                    return jsonify({"error": "Email already in use"}), 409
            updates['email'] = data['email'].lower()
            
        if 'role' in data and data['role']:
            # Validate role
            if data['role'] not in ['admin', 'user']:
                return jsonify({"error": "Invalid role"}), 400
            updates['role'] = data['role']
            
        if 'active' in data:
            updates['active'] = 1 if data['active'] else 0
            
        if 'password' in data and data['password']:
            # Hash new password
            updates['password_hash'] = bcrypt.hashpw(
                data['password'].encode('utf-8'), 
                bcrypt.gensalt()
            ).decode('utf-8')
        
        if not updates:
            return jsonify({"message": "No changes to apply"}), 200
        
        # Update user in database
        result = db.execute_transaction([{
            "query": f"""UPDATE users SET {', '.join([f'{k} = ?' for k in updates.keys()])} 
            WHERE user_id = ?""",
            "params": tuple(list(updates.values()) + [user_id])
        }])
        
        # Log the action
        logger.info(f"Admin {g.user['username']} updated user {user_id}")
        
        # Get updated user
        updated_user = db.get_user_by_id(user_id)
        
        return jsonify({
            "message": "User updated successfully",
            "user": updated_user
        })
    except Exception as e:
        logger.error(f"Error updating user {user_id}: {str(e)}")
        return jsonify({"error": str(e)}), 500

@admin_bp.route('/users/<user_id>', methods=['DELETE'])
def delete_user(user_id):
    """Delete a user"""
    try:
        db = get_db()
        
        # Check if user exists
        existing_user = db.get_user_by_id(user_id)
        if not existing_user:
            return jsonify({"error": "User not found"}), 404
            
        # Prevent deleting yourself
        if user_id == g.user['user_id']:
            return jsonify({"error": "Cannot delete your own account"}), 400
            
        # Soft delete by deactivating instead of actual deletion
        db.execute_transaction([{
            "query": "UPDATE users SET active = 0 WHERE user_id = ?",
            "params": (user_id,)
        }])
        
        # Log the action
        logger.info(f"Admin {g.user['username']} deleted user {user_id}")
        
        return jsonify({"message": "User deleted successfully"})
    except Exception as e:
        logger.error(f"Error deleting user {user_id}: {str(e)}")
        return jsonify({"error": str(e)}), 500

# System monitoring endpoints
@admin_bp.route('/system/stats', methods=['GET'])
def get_system_stats():
    """Get system statistics"""
    try:
        db = get_db()
        monitor = get_monitor()
        
        # Get database stats
        db_stats = db.get_database_stats()
        
        # Get monitoring metrics
        monitoring_metrics = monitor.get_metrics()
        
        # Combine stats
        stats = {
            "database": db_stats,
            "monitoring": monitoring_metrics,
            "timestamp": datetime.utcnow().isoformat()
        }
        
        return jsonify(stats)
    except Exception as e:
        logger.error(f"Error getting system stats: {str(e)}")
        return jsonify({"error": str(e)}), 500

@admin_bp.route('/system/logs', methods=['GET'])
def get_error_logs():
    """Get system error logs"""
    try:
        db = get_db()
        
        # Support pagination
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 20, type=int)
        resolved = request.args.get('resolved', None)
        
        # Build query
        query_parts = ["SELECT * FROM error_logs"]
        params = []
        
        # Add filter for resolved status if specified
        if resolved is not None:
            resolved_value = 1 if resolved in ['true', '1', 'yes'] else 0
            query_parts.append("WHERE resolved = ?")
            params.append(resolved_value)
        
        # Add ordering
        query_parts.append("ORDER BY timestamp DESC")
        
        # Add pagination
        query_parts.append("LIMIT ? OFFSET ?")
        params.extend([per_page, (page - 1) * per_page])
        
        # Get logs
        logs = db.execute_query(" ".join(query_parts), tuple(params), fetch_mode="all")
        
        # Get total count
        count_query = "SELECT COUNT(*) as count FROM error_logs"
        count_params = []
        if resolved is not None:
            count_query += " WHERE resolved = ?"
            count_params.append(resolved_value)
        
        total_count = db.execute_query(count_query, tuple(count_params), fetch_mode="one")["count"]
        
        # Format logs
        log_list = []
        for log in logs:
            # Parse request data if present
            request_data = {}
            if log["request_data"]:
                try:
                    request_data = json.loads(log["request_data"])
                except:
                    request_data = {"raw": log["request_data"]}
            
            log_list.append({
                "error_id": log["error_id"],
                "error_type": log["error_type"],
                "error_message": log["error_message"],
                "stack_trace": log["stack_trace"],
                "request": {
                    "path": log["request_path"],
                    "method": log["request_method"],
                    "data": request_data
                },
                "user_id": log["user_id"],
                "timestamp": log["timestamp"],
                "resolved": bool(log["resolved"])
            })
        
        return jsonify({
            "logs": log_list,
            "pagination": {
                "page": page,
                "per_page": per_page,
                "total": total_count,
                "pages": (total_count + per_page - 1) // per_page
            }
        })
    except Exception as e:
        logger.error(f"Error getting error logs: {str(e)}")
        return jsonify({"error": str(e)}), 500

@admin_bp.route('/system/logs/<error_id>', methods=['PATCH'])
def update_error_log(error_id):
    """Update error log (mark as resolved)"""
    try:
        data = request.json
        if not data:
            return jsonify({"error": "No data provided"}), 400
            
        db = get_db()
        
        # Check if log exists
        log = db.execute_query(
            "SELECT error_id FROM error_logs WHERE error_id = ?",
            (error_id,),
            fetch_mode="one"
        )
        
        if not log:
            return jsonify({"error": "Error log not found"}), 404
            
        # Update resolved status
        resolved = 1 if data.get('resolved', False) else 0
        
        db.execute_query(
            "UPDATE error_logs SET resolved = ? WHERE error_id = ?",
            (resolved, error_id),
            fetch_mode="none"
        )
        
        return jsonify({
            "message": f"Error log marked as {'resolved' if resolved else 'unresolved'}",
            "error_id": error_id
        })
    except Exception as e:
        logger.error(f"Error updating error log {error_id}: {str(e)}")
        return jsonify({"error": str(e)}), 500

# Invitation management endpoints
@admin_bp.route('/invitations', methods=['GET'])
def get_invitations():
    """Get all invitation codes"""
    try:
        db = get_db()
        
        # Support pagination
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 20, type=int)
        status = request.args.get('status', None)  # active, used, all
        
        # Build query
        query_parts = ["""
            SELECT i.*, u.username as created_by_username 
            FROM invitations i
            LEFT JOIN users u ON i.created_by = u.user_id
        """]
        params = []
        
        # Add filter for invitation status
        if status == 'active':
            query_parts.append("WHERE i.used = 0 AND i.expires_at > ?")
            params.append(datetime.utcnow().isoformat())
        elif status == 'used':
            query_parts.append("WHERE i.used = 1")
        elif status == 'expired':
            query_parts.append("WHERE i.used = 0 AND i.expires_at <= ?")
            params.append(datetime.utcnow().isoformat())
        
        # Add sorting
        query_parts.append("ORDER BY i.created_at DESC")
        
        # Add pagination
        query_parts.append("LIMIT ? OFFSET ?")
        params.extend([per_page, (page - 1) * per_page])
        
        # Get invitations
        invitations = db.execute_query(" ".join(query_parts), tuple(params), fetch_mode="all")
        
        # Build count query
        count_query_parts = ["SELECT COUNT(*) as count FROM invitations"]
        count_params = []
        
        if status == 'active':
            count_query_parts.append("WHERE used = 0 AND expires_at > ?")
            count_params.append(datetime.utcnow().isoformat())
        elif status == 'used':
            count_query_parts.append("WHERE used = 1")
        elif status == 'expired':
            count_query_parts.append("WHERE used = 0 AND expires_at <= ?")
            count_params.append(datetime.utcnow().isoformat())
            
        # Get total count
        total_count = db.execute_query(
            " ".join(count_query_parts), 
            tuple(count_params), 
            fetch_mode="one"
        )["count"]
        
        # Format invitations
        invitation_list = []
        for invitation in invitations:
            invitation_list.append({
                "invitation_id": invitation["invitation_id"],
                "email": invitation["email"],
                "token": invitation["token"],
                "created_by": {
                    "user_id": invitation["created_by"],
                    "username": invitation["created_by_username"]
                },
                "created_at": invitation["created_at"],
                "expires_at": invitation["expires_at"],
                "used": bool(invitation["used"]),
                "status": "used" if invitation["used"] else 
                         ("expired" if invitation["expires_at"] < datetime.utcnow().isoformat() else "active")
            })
        
        return jsonify({
            "invitations": invitation_list,
            "pagination": {
                "page": page,
                "per_page": per_page,
                "total": total_count,
                "pages": (total_count + per_page - 1) // per_page
            }
        })
    except Exception as e:
        logger.error(f"Error getting invitations: {str(e)}")
        return jsonify({"error": str(e)}), 500

@admin_bp.route('/invitations', methods=['POST'])
def create_invitation():
    """Create a new invitation code"""
    try:
        data = request.json
        
        if not data:
            return jsonify({"error": "No data provided"}), 400
            
        # Validate email
        email = data.get('email')
        if not email:
            return jsonify({"error": "Email is required"}), 400
            
        db = get_db()
        
        # Check if user already exists with this email
        existing_user = db.get_user_by_email(email)
        if existing_user:
            return jsonify({"error": "User with this email already exists"}), 409
            
        # Generate invitation data
        invitation_id = str(uuid.uuid4())
        token = secrets.token_urlsafe(32)
        expires_at = datetime.utcnow() + timedelta(days=data.get('expires_days', 7))
        
        invitation_data = {
            "invitation_id": invitation_id,
            "email": email,
            "token": token,
            "created_by": g.user["user_id"],
            "expires_at": expires_at.isoformat()
        }
        
        # Create invitation
        db.create_invitation(invitation_data)
        
        # Format response
        invitation = {
            "invitation_id": invitation_id,
            "email": email,
            "token": token,
            "created_by": {
                "user_id": g.user["user_id"],
                "username": g.user["username"]
            },
            "created_at": datetime.utcnow().isoformat(),
            "expires_at": expires_at.isoformat(),
            "used": False,
            "status": "active",
            "invitation_url": f"/register?token={token}&email={email}"
        }
        
        # Log the action
        logger.info(f"Admin {g.user['username']} created invitation for {email}")
        
        return jsonify({
            "message": "Invitation created successfully",
            "invitation": invitation
        }), 201
    except Exception as e:
        logger.error(f"Error creating invitation: {str(e)}")
        return jsonify({"error": str(e)}), 500

@admin_bp.route('/invitations/<invitation_id>', methods=['DELETE'])
def revoke_invitation(invitation_id):
    """Revoke an unused invitation"""
    try:
        db = get_db()
        
        # Check if invitation exists and is unused
        invitation = db.execute_query(
            "SELECT invitation_id, used FROM invitations WHERE invitation_id = ?",
            (invitation_id,),
            fetch_mode="one"
        )
        
        if not invitation:
            return jsonify({"error": "Invitation not found"}), 404
            
        if invitation["used"]:
            return jsonify({"error": "Cannot revoke an invitation that has been used"}), 400
            
        # Delete the invitation
        db.execute_query(
            "DELETE FROM invitations WHERE invitation_id = ?",
            (invitation_id,),
            fetch_mode="none"
        )
        
        # Log the action
        logger.info(f"Admin {g.user['username']} revoked invitation {invitation_id}")
        
        return jsonify({
            "message": "Invitation revoked successfully"
        })
    except Exception as e:
        logger.error(f"Error revoking invitation {invitation_id}: {str(e)}")
        return jsonify({"error": str(e)}), 500

# Database maintenance endpoints
@admin_bp.route('/system/database/optimize', methods=['POST'])
def optimize_database():
    """Optimize the database (vacuum, reindex)"""
    try:
        db = get_db()
        
        # Run optimization
        success = db.optimize_database()
        
        if success:
            # Log the action
            logger.info(f"Admin {g.user['username']} optimized the database")
            
            return jsonify({
                "message": "Database optimized successfully"
            })
        else:
            return jsonify({"error": "Database optimization failed"}), 500
    except Exception as e:
        logger.error(f"Error optimizing database: {str(e)}")
        return jsonify({"error": str(e)}), 500

@admin_bp.route('/system/database/backup', methods=['POST'])
def backup_database():
    """Create a database backup"""
    try:
        db = get_db()
        
        # Create backup
        backup_path = db.create_backup()
        
        # Log the action
        logger.info(f"Admin {g.user['username']} created database backup at {backup_path}")
        
        return jsonify({
            "message": "Database backup created successfully",
            "backup_path": backup_path,
            "timestamp": datetime.utcnow().isoformat()
        })
    except Exception as e:
        logger.error(f"Error creating database backup: {str(e)}")
        return jsonify({"error": str(e)}), 500

# Register the blueprint with the Flask app
def register_blueprint(app):
    """Register the admin blueprint with the Flask app"""
    app.register_blueprint(admin_bp)
    logger.info("Admin routes registered")
