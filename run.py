import os
import sys
import logging
import logging.config
import click
import uuid
import json
import secrets
import atexit
import signal
import threading
from datetime import datetime, timedelta
from typing import Dict, Any, Optional
from pathlib import Path
from functools import wraps
from flask import Flask, g, request, jsonify, current_app, Response, render_template, redirect, has_request_context, has_app_context
from flask.cli import FlaskGroup, with_appcontext
from werkzeug.middleware.proxy_fix import ProxyFix
from dotenv import load_dotenv
import time

# Import route blueprints
from routes.admin import register_blueprint as register_admin
from routes.auth import register_blueprint as register_auth
from routes.chat import register_blueprint as register_chat
from routes.images import register_blueprint as register_images

# Import services
from services.database import DatabaseService
from services.monitor import MonitoringService
from services.cors import CorsService

# Configure logger first (will be reconfigured with app config later)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler()]
)

logger = logging.getLogger("triton")

# Load environment variables
load_dotenv()

def create_app(env=None) -> Flask:
    """
    Application factory function that creates and configures the Flask app
    
    Args:
        env: Environment name ('development', 'production', 'testing')
        
    Returns:
        Flask: Configured Flask application
    """
    # Create the Flask app
    app = Flask(
        __name__,
        static_folder='static',
        template_folder='templates'
    )
    
    # Get environment
    env = env or os.getenv('FLASK_ENV', 'production')
    
    # Load configuration
    config = load_configuration(env)
    app.config.update(config)
    
    # Enable proxy fix for proper IP handling behind a reverse proxy
    if config.get("BEHIND_PROXY", False):
        app.wsgi_app = ProxyFix(
            app.wsgi_app, 
            x_for=config.get("PROXY_X_FOR", 1), 
            x_proto=config.get("PROXY_X_PROTO", 1),
            x_host=config.get("PROXY_X_HOST", 1),
            x_port=config.get("PROXY_X_PORT", 1)
        )
    
    # Configure logging
    configure_logging(app)
    
    # Set up CORS
    CorsService.initialize(app)
    
    # Initialize database
    with app.app_context():
        db_service = init_database(app)
        app.db_service = db_service
        
        # Initialize monitoring
        app.monitor = MonitoringService(
            app_name="Triton",
            config=config
        )
    
    # Register error handlers
    register_error_handlers(app)
    
    # Register middleware
    register_middleware(app)
    
    # Register routes
    register_routes(app)
    
    # Register health check endpoint
    register_health_check(app)
    
    # Register shutdown handlers
    register_shutdown_handlers(app)
    
    # Register CLI commands
    register_commands(app)
    
    # Log application startup
    logger.info(f"Triton application initialized in {env} environment")
    
    return app

def load_configuration(env: str) -> Dict[str, Any]:
    """
    Load configuration from files and environment variables
    
    Args:
        env: Environment name ('development', 'production', 'testing')
        
    Returns:
        Dict: Configuration dictionary
    """
    # Base configuration
    config = {
        "SECRET_KEY": os.getenv("SECRET_KEY", secrets.token_hex(32)),
        "DEBUG": env == "development",
        "TESTING": env == "testing",
        "ENV": env,
        "DATABASE_PATH": os.getenv("DATABASE_PATH", "data/triton.db"),
        "CORS_ORIGINS": os.getenv("CORS_ORIGINS", "*").split(","),
        "BEHIND_PROXY": os.getenv("BEHIND_PROXY", "false").lower() == "true",
        "PROXY_X_FOR": int(os.getenv("PROXY_X_FOR", "1")),
        "PROXY_X_PROTO": int(os.getenv("PROXY_X_PROTO", "1")),
        "PROXY_X_HOST": int(os.getenv("PROXY_X_HOST", "1")),
        "PROXY_X_PORT": int(os.getenv("PROXY_X_PORT", "1")),
        "MAX_CONTENT_LENGTH": int(os.getenv("MAX_CONTENT_LENGTH", str(16 * 1024 * 1024))),  # 16MB
        "SESSION_COOKIE_SECURE": env != "development",
        "SESSION_COOKIE_HTTPONLY": True,
        "SESSION_COOKIE_SAMESITE": "Lax",
        "PERMANENT_SESSION_LIFETIME": int(os.getenv("SESSION_LIFETIME_DAYS", "30")) * 86400,
        "DISCORD_WEBHOOK_URL": os.getenv("DISCORD_WEBHOOK_URL", ""),
        "MONITORING_ENABLED": os.getenv("MONITORING_ENABLED", "true").lower() == "true",
        "GOOGLE_API_KEY": os.getenv("GOOGLE_API_KEY", ""),
        "GOOGLE_SEARCH_ENGINE_ID": os.getenv("GOOGLE_SEARCH_ENGINE_ID", ""),
        "AZURE_API_KEY": os.getenv("AZURE_API_KEY", ""),
        "GEMINI_API_KEY": os.getenv("GEMINI_API_KEY", ""),
        
        # Production server settings
        "SERVER_NAME": os.getenv("SERVER_NAME"),
        "APPLICATION_ROOT": os.getenv("APPLICATION_ROOT", "/"),
        "PREFERRED_URL_SCHEME": os.getenv("PREFERRED_URL_SCHEME", "https"),
        "WORKERS": int(os.getenv("WORKERS", "4")),
        "TIMEOUT": int(os.getenv("TIMEOUT", "120")),
        "THREADS": int(os.getenv("THREADS", "2")),
        "WORKER_CONNECTIONS": int(os.getenv("WORKER_CONNECTIONS", "1000")),
        "BIND_HOST": os.getenv("BIND_HOST", "127.0.0.1"),
        "BIND_PORT": int(os.getenv("BIND_PORT", "8000")),
        "LOG_LEVEL": os.getenv("LOG_LEVEL", "INFO").upper(),
        
        # Database settings
        "DB_POOL_SIZE": int(os.getenv("DB_POOL_SIZE", "5")),
        "VACUUM_INTERVAL": int(os.getenv("VACUUM_INTERVAL", "86400")),  # 24 hours
        "QUERY_CACHE_TTL": int(os.getenv("QUERY_CACHE_TTL", "30")),  # 30 seconds
        "MAX_QUERY_CACHE_SIZE": int(os.getenv("MAX_QUERY_CACHE_SIZE", "100")),
        
        # Security settings
        "SECURE_DELETE": env == "production",
        
        # AI Model options
        "MODEL_OPTIONS": {
            "openai/gpt-4o": {
                "id": "openai/gpt-4o",
                "name": "GPT-4o",
                "description": "OpenAI's most capable multimodal model",
                "tokens": {
                    "input": 128000,
                    "output": 4096
                }
            },
            "openai/gpt-4-turbo": {
                "id": "openai/gpt-4-turbo",
                "name": "GPT-4 Turbo",
                "description": "OpenAI's fastest GPT-4 model",
                "tokens": {
                    "input": 128000,
                    "output": 4096
                }
            },
            "anthropic/claude-3-opus": {
                "id": "anthropic/claude-3-opus",
                "name": "Claude 3 Opus",
                "description": "Anthropic's most capable model",
                "tokens": {
                    "input": 200000,
                    "output": 4096
                }
            },
            "anthropic/claude-3-sonnet": {
                "id": "anthropic/claude-3-sonnet",
                "name": "Claude 3 Sonnet",
                "description": "Balanced performance and speed",
                "tokens": {
                    "input": 200000,
                    "output": 4096
                }
            },
            "meta/llama-3-70b": {
                "id": "meta/llama-3-70b",
                "name": "Llama 3 70B",
                "description": "Meta's most capable open model",
                "tokens": {
                    "input": 8192,
                    "output": 4096
                }
            }
        }
    }
    
    # Load additional environment-specific configuration
    env_file = Path(f"config/{env}.py")
    if env_file.exists():
        with open(env_file, 'r') as f:
            exec(f.read(), globals(), config)
    
    # Ensure data directories exist
    for dir_path in ["data", "data/backups", "logs", "instance/images", "instance/thumbnails"]:
        os.makedirs(dir_path, exist_ok=True)
    
    return config

def configure_logging(app: Flask):
    """Configure logging for the application
    
    Args:
        app: Flask application
    """
    log_level = app.config.get("LOG_LEVEL", "INFO")
    log_dir = "logs"
    os.makedirs(log_dir, exist_ok=True)
    
    # Configure basic logging
    logging_config = {
        'version': 1,
        'disable_existing_loggers': False,
        'formatters': {
            'standard': {
                'format': '%(asctime)s [%(levelname)s] %(name)s: %(message)s'
            },
            'detailed': {
                'format': '%(asctime)s [%(levelname)s] %(name)s (%(filename)s:%(lineno)d): %(message)s'
            },
            'request_id': {
                'format': '%(asctime)s [%(levelname)s] [%(request_id)s] %(name)s: %(message)s'
            }
        },
        'handlers': {
            'console': {
                'class': 'logging.StreamHandler',
                'level': 'DEBUG',
                'formatter': 'standard',
                'stream': 'ext://sys.stdout'
            },
            'file': {
                'class': 'logging.handlers.TimedRotatingFileHandler',
                'level': 'INFO',
                'formatter': 'detailed',
                'filename': os.path.join(log_dir, 'triton.log'),
                'when': 'midnight',
                'interval': 1,
                'backupCount': 30
            },
            'error_file': {
                'class': 'logging.handlers.TimedRotatingFileHandler',
                'level': 'ERROR',
                'formatter': 'detailed',
                'filename': os.path.join(log_dir, 'error.log'),
                'when': 'midnight',
                'interval': 1,
                'backupCount': 90
            }
        },
        'loggers': {
            'triton': {
                'level': log_level,
                'handlers': ['console', 'file', 'error_file'],
                'propagate': False
            },
            'flask.app': {
                'level': log_level,
                'handlers': ['console', 'file', 'error_file'],
                'propagate': False
            },
            'werkzeug': {
                'level': 'INFO',
                'handlers': ['console', 'file']
            }
        },
        'root': {
            'level': log_level,
            'handlers': ['console', 'file', 'error_file']
        }
    }
    
    # Apply configuration
    logging.config.dictConfig(logging_config)
    
    # Add request info to logs - only during request handling
    class SafeRequestIdFilter(logging.Filter):
        """Filter that safely adds request_id to log records, handling cases with no request context"""
        def filter(self, record):
            if has_request_context():
                # We're in a request context, can safely access g
                record.request_id = g.get('request_id', '-')
            else:
                # Not in a request context, use a default value
                record.request_id = '-'
            return True
    
    # Register the filter only for use in request handling
    @app.before_request
    def before_request_logging():
        """Add request ID to context for logging"""
        g.request_id = request.headers.get('X-Request-ID', uuid.uuid4().hex)
        
        # Apply the filter to loggers dynamically during request processing
        request_filter = SafeRequestIdFilter()
        for logger_name in ['triton', 'flask.app']:
            logging.getLogger(logger_name).addFilter(request_filter)
    
    # Log basic startup information without request context
    app.logger.info(f"Logging configured with level {log_level}")

def init_database(app):
    """Initialize the database with better error handling
    
    Args:
        app: Flask application
        
    Returns:
        DatabaseService: Initialized database service
    """
    from services.database import DatabaseService
    
    db_path = app.config.get("DATABASE_PATH", "data/triton.db")
    # Ensure database directory exists
    os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)
    
    db_service = DatabaseService(db_path, app.config)
    
    max_attempts = 3
    for attempt in range(max_attempts):
        try:
            # Call the initialize_database method we just added
            db_service.initialize_database()
            app.logger.info(f"Database initialized successfully")
            return db_service
        except Exception as e:
            app.logger.error(f"Database initialization error (attempt {attempt+1}/{max_attempts}): {str(e)}")
            if attempt == max_attempts - 1:
                app.logger.error("Failed to initialize database after multiple attempts")
                raise
            time.sleep(1)  # Wait before retrying
    
    return db_service

def register_error_handlers(app: Flask):
    """Register error handlers for the application
    
    Args:
        app: Flask application
    """
    @app.errorhandler(400)
    def bad_request(error):
        return jsonify({"error": "Bad request", "message": str(error)}), 400
    
    @app.errorhandler(401)
    def unauthorized(error):
        return jsonify({"error": "Unauthorized", "message": "Authentication required"}), 401
    
    @app.errorhandler(403)
    def forbidden(error):
        return jsonify({"error": "Forbidden", "message": "You don't have permission to access this resource"}), 403
    
    @app.errorhandler(404)
    def not_found(error):
        return jsonify({"error": "Not found", "message": "The requested resource was not found"}), 404
    
    @app.errorhandler(405)
    def method_not_allowed(error):
        return jsonify({"error": "Method not allowed", "message": "The method is not allowed for this resource"}), 405
    
    @app.errorhandler(429)
    def too_many_requests(error):
        return jsonify({"error": "Too many requests", "message": "Rate limit exceeded"}), 429
    
    @app.errorhandler(500)
    def server_error(error):
        # Log the error
        app.logger.error(f"500 error: {str(error)}")
        error_id = str(uuid.uuid4())
        
        # Log to monitoring service if available
        if hasattr(app, 'monitor'):
            app.monitor.log_error(
                error=error,
                request_info={
                    "path": request.path,
                    "method": request.method,
                    "data": request.get_json(silent=True)
                },
                user_info=g.user if hasattr(g, 'user') else None,
                send_alert=True
            )
        
        return jsonify({
            "error": "Internal server error", 
            "message": "An unexpected error occurred", 
            "error_id": error_id
        }), 500

def register_middleware(app: Flask):
    """Register middleware for the application
    
    Args:
        app: Flask application
    """
    @app.before_request
    def before_request():
        # Start timer for request duration
        g.start_time = time.time()
        
        # Add request ID for tracking
        g.request_id = request.headers.get('X-Request-ID', str(uuid.uuid4()))
        
        # Security checks for production
        if app.config['ENV'] == 'production':
            # Force HTTPS in production
            if app.config.get('FORCE_HTTPS', True) and request.headers.get('X-Forwarded-Proto') == 'http':
                url = request.url.replace('http://', 'https://', 1)
                return redirect(url, code=301)
            
            # Check for basic security headers
            if not request.headers.get('User-Agent'):
                return jsonify({"error": "Missing User-Agent header"}), 400
        
    @app.after_request
    def after_request(response):
        # Add security headers
        response.headers.add('X-Content-Type-Options', 'nosniff')
        response.headers.add('X-Frame-Options', 'DENY')
        response.headers.add('X-XSS-Protection', '1; mode=block')
        response.headers.add('Referrer-Policy', 'strict-origin-when-cross-origin')
        
        # Add Content-Security-Policy in production
        if app.config['ENV'] == 'production':
            response.headers.add('Content-Security-Policy', 
                                "default-src 'self'; " +
                                "script-src 'self' 'unsafe-inline'; " +
                                "style-src 'self' 'unsafe-inline'; " +
                                "img-src 'self' data:; " +
                                "font-src 'self'; " +
                                "connect-src 'self'")
        
        # Add request ID to response
        response.headers.add('X-Request-ID', g.get('request_id', ''))
        
        # Calculate request duration
        if hasattr(g, 'start_time'):
            duration = time.time() - g.start_time
            
            # Log request details
            app.logger.info(
                f"Request: {request.method} {request.path} - "
                f"Status: {response.status_code} - "
                f"Duration: {duration:.4f}s"
            )
            
            # Record metrics
            if hasattr(app, 'monitor'):
                app.monitor.log_request(
                    path=request.path,
                    method=request.method,
                    status_code=response.status_code,
                    response_time=duration,
                    user_id=g.user["user_id"] if hasattr(g, 'user') and g.user else None
                )
        
        return response

def register_routes(app: Flask):
    """Register all route blueprints
    
    Args:
        app: Flask application
    """
    # Register blueprints
    register_auth(app)
    register_admin(app)
    register_chat(app)
    register_images(app)
    
    # Root route for health check
    @app.route('/')
    def index():
        return jsonify({
            "status": "ok",
            "application": "Triton",
            "version": "1.0.0",
            "environment": app.config.get('ENV')
        })
    
    # Add static file route for SPA frontend
    @app.route('/<path:path>')
    def catch_all(path):
        # Serve static files from the static folder if they exist
        static_file = os.path.join(app.static_folder, path)
        if os.path.isfile(static_file):
            return app.send_static_file(path)
        
        # Otherwise, serve the index.html for SPA
        return app.send_static_file('index.html')

def register_health_check(app: Flask):
    """Register health check endpoints
    
    Args:
        app: Flask application
    """
    @app.route('/health')
    def health_check():
        """Basic health check endpoint"""
        return jsonify({
            "status": "ok",
            "timestamp": datetime.utcnow().isoformat()
        })
    
    @app.route('/health/detailed')
    def detailed_health_check():
        """Detailed health check with system metrics"""
        import psutil
        
        health_data = {
            "status": "ok",
            "timestamp": datetime.utcnow().isoformat(),
            "app": {
                "version": "1.0.0",
                "environment": app.config.get("ENV", "production"),
                "uptime": str(datetime.utcnow() - app.start_time).split('.')[0] if hasattr(app, 'start_time') else "unknown"
            },
            "system": {
                "cpu_percent": psutil.cpu_percent(),
                "memory_percent": psutil.virtual_memory().percent,
                "disk_percent": psutil.disk_usage('/').percent
            }
        }
        
        # Add database check
        try:
            db_service = app.db_service
            db_stats = db_service.get_connection_stats()
            
            with db_service.get_connection() as conn:
                conn.execute("SELECT 1").fetchone()
            
            health_data["database"] = {
                "status": "ok",
                "connection_stats": db_stats
            }
        except Exception as e:
            health_data["database"] = {"status": "error", "message": str(e)}
            health_data["status"] = "degraded"
        
        # Add Azure API check if key is configured
        if app.config.get("AZURE_API_KEY"):
            try:
                # Perform a simple check
                health_data["azure_api"] = {"status": "ok"}
            except Exception as e:
                health_data["azure_api"] = {"status": "error", "message": str(e)}
                health_data["status"] = "degraded"
        
        # Add monitoring metrics if available
        if hasattr(app, 'monitor'):
            health_data["metrics"] = app.monitor.get_metrics()
        
        return jsonify(health_data)

def register_shutdown_handlers(app: Flask):
    """Register handlers for graceful shutdown
    
    Args:
        app: Flask application
    """
    def shutdown_handler(signal_num, frame):
        app.logger.info(f"Received signal {signal_num}, shutting down gracefully...")
        
        # Set application state to shutting down
        app.shutting_down = True
        
        # Log shutdown to monitoring if available
        if hasattr(app, 'monitor'):
            app.monitor.send_alert(
                title="Application Shutdown",
                message=f"Triton is shutting down on {socket.gethostname()}",
                level="info"
            )
        
        # Close database connections
        if hasattr(app, 'db_service'):
            app.logger.info("Closing database connections...")
            app.db_service._cleanup()
        
        # Exit with success status
        sys.exit(0)
    
    # Store application start time
    app.start_time = datetime.utcnow()
    app.shutting_down = False
    
    # Register for SIGTERM and SIGINT
    signal.signal(signal.SIGTERM, shutdown_handler)
    signal.signal(signal.SIGINT, shutdown_handler)

@click.command('db-status')
@with_appcontext
def db_status_command():
    """Display database connection status"""
    from services.database import DatabaseService
    import os
    
    db_path = current_app.config.get("DATABASE_PATH", "data/triton.db")
    db_service = DatabaseService(db_path, current_app.config)
    
    # Get connection stats
    stats = db_service.get_connection_stats()
    
    # Get database info
    try:
        with db_service.get_connection() as conn:
            db_size = os.path.getsize(db_path) / (1024 * 1024)  # Convert to MB
            journal_size = 0
            wal_path = f"{db_path}-wal"
            if os.path.exists(wal_path):
                journal_size = os.path.getsize(wal_path) / (1024 * 1024)  # Convert to MB
                
            # Get page and schema info
            page_size = conn.execute("PRAGMA page_size").fetchone()[0]
            page_count = conn.execute("PRAGMA page_count").fetchone()[0]
            journal_mode = conn.execute("PRAGMA journal_mode").fetchone()[0]
            
            # Get table counts
            tables = {}
            for table in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall():
                table_name = table[0]
                count = conn.execute(f"SELECT COUNT(*) FROM {table_name}").fetchone()[0]
                tables[table_name] = count
    except Exception as e:
        click.echo(f"Error getting database info: {e}")
        tables = {}
        db_size = journal_size = page_size = page_count = journal_mode = "Unknown"
    
    # Display results
    click.echo("\nDatabase Connection Status:")
    click.echo(f"  Active connections: {stats['active_connections']}")
    click.echo(f"  Pool connections: {stats['pool_connections']}")
    click.echo(f"  Max pool size: {stats['max_pool_size']}")
    
    click.echo("\nDatabase Information:")
    click.echo(f"  Database path: {db_path}")
    click.echo(f"  Database size: {db_size:.2f} MB")
    click.echo(f"  Journal size: {journal_size:.2f} MB")
    click.echo(f"  Page size: {page_size}")
    click.echo(f"  Page count: {page_count}")
    click.echo(f"  Journal mode: {journal_mode}")
    
    if tables:
        click.echo("\nTable Row Counts:")
        for table, count in tables.items():
            click.echo(f"  {table}: {count}")

def register_commands(app):
    """Register Flask CLI commands
    
    Args:
        app: Flask application
    """
    # Database status command
    app.cli.add_command(db_status_command)
    
    # Add vacuum command
    @app.cli.command("db-vacuum")
    def db_vacuum_command():
        """Optimize database by running VACUUM"""
        if hasattr(app, 'db_service'):
            click.echo("Optimizing database...")
            success = app.db_service.optimize_database()
            if success:
                click.echo("Database optimized successfully")
            else:
                click.echo("Database optimization failed")
    
    # Add stats command
    @app.cli.command("stats")
    def app_stats_command():
        """Show application statistics"""
        if hasattr(app, 'monitor'):
            stats = app.monitor.get_metrics()
            click.echo(json.dumps(stats, indent=2))
        else:
            click.echo("Monitoring service not available")
    
    # Add production deployment command
    @app.cli.command("deploy")
    @click.option("--workers", default=4, help="Number of worker processes")
    @click.option("--bind", default="127.0.0.1:8000", help="Bind address (host:port)")
    def deploy_command(workers, bind):
        """Deploy the application with production WSGI server"""
        if not bind or ":" not in bind:
            click.echo("Invalid bind address. Use format host:port")
            return
            
        host, port = bind.split(":")
        try:
            port = int(port)
        except ValueError:
            click.echo("Invalid port number")
            return
            
        # Check if gunicorn is installed
        try:
            import gunicorn
            has_gunicorn = True
        except ImportError:
            has_gunicorn = False
            
        # Check if waitress is installed
        try:
            import waitress
            has_waitress = True
        except ImportError:
            has_waitress = False
            
        if not has_gunicorn and not has_waitress:
            click.echo("Neither Gunicorn nor Waitress is installed. Install one of them to run in production mode.")
            click.echo("  pip install gunicorn  # For Linux/macOS")
            click.echo("  pip install waitress  # For Windows")
            return
            
        # On Linux/macOS, prefer gunicorn
        if has_gunicorn and os.name != 'nt':
            click.echo(f"Starting Gunicorn server with {workers} workers on {bind}...")
            os.execvp("gunicorn", [
                "gunicorn",
                f"--workers={workers}",
                f"--bind={bind}",
                "--access-logfile=-",
                "--error-logfile=-",
                "--timeout=120",
                "--worker-class=gthread",
                "--threads=2",
                "--preload",
                "run:create_app()"
            ])
        # On Windows, use waitress
        elif has_waitress:
            click.echo(f"Starting Waitress server on {host}:{port}...")
            from waitress import serve
            serve(create_app(), host=host, port=port, threads=workers*2)
        else:
            click.echo("No suitable production server available for your platform.")

# CLI commands
@click.group(cls=FlaskGroup, create_app=lambda: create_app())
def cli():
    """Management script for the Triton application."""
    pass

@cli.command("create-admin")
@click.option("--username", required=True, help="Admin username")
@click.option("--email", required=True, help="Admin email")
@click.option("--password", required=True, help="Admin password")
def create_admin(username, email, password):
    """Create an administrator user"""
    import bcrypt
    
    app = create_app()
    with app.app_context():
        db = app.db_service
        
        # Check if user already exists
        existing = db.get_user_by_email(email)
        if existing:
            click.echo(f"User with email {email} already exists")
            return
        
        # Create user
        user_id = str(uuid.uuid4())
        password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        
        db.create_user({
            "user_id": user_id,
            "username": username,
            "email": email,
            "password_hash": password_hash,
            "role": "admin"  # Set role to admin
        })
        
        click.echo(f"Admin user {username} created successfully")

@cli.command("create-invitation")
@click.option("--email", required=True, help="Email to invite")
@click.option("--admin-id", required=True, help="Admin user ID")
@click.option("--expires-days", default=7, help="Expiration days")
def create_invitation(email, admin_id, expires_days):
    """Create a user invitation"""
    app = create_app()
    with app.app_context():
        db = app.db_service
        
        # Check if admin exists
        admin = db.get_user_by_id(admin_id)
        if not admin or admin['role'] != 'admin':
            click.echo("Invalid admin user ID")
            return
        
        # Generate invitation
        invitation_id = str(uuid.uuid4())
        token = secrets.token_urlsafe(32)
        expires_at = datetime.utcnow() + timedelta(days=expires_days)
        
        db.create_invitation({
            "invitation_id": invitation_id,
            "email": email,
            "token": token,
            "created_by": admin_id,
            "expires_at": expires_at.isoformat()
        })
        
        click.echo(f"Invitation created for {email}")
        click.echo(f"Token: {token}")
        click.echo(f"Expires: {expires_at.isoformat()}")

@cli.command("db-backup")
@click.option("--output", help="Output file path")
def db_backup(output):
    """Create a database backup"""
    app = create_app()
    with app.app_context():
        db = app.db_service
        backup_path = db.create_backup(output)
        click.echo(f"Database backup created at: {backup_path}")

# Production server entry point
def run_production_server():
    """Run the application with a production WSGI server"""
    app = create_app()
    config = app.config
    
    # Determine which server to use based on platform
    is_windows = os.name == 'nt'
    
    # Check for server availability
    try:
        import gunicorn
        has_gunicorn = True and not is_windows  # Gunicorn doesn't work on Windows
    except ImportError:
        has_gunicorn = False
    
    try:
        import waitress
        has_waitress = True
    except ImportError:
        has_waitress = False
    
    # Get server config
    bind_host = config.get('BIND_HOST', '127.0.0.1')
    bind_port = config.get('BIND_PORT', 8000)
    workers = config.get('WORKERS', 4)
    threads = config.get('THREADS', 2)
    
    # Log startup
    logger.info(f"Starting production server on {bind_host}:{bind_port}")
    
    # Use appropriate server
    if has_gunicorn:
        import multiprocessing
        if workers == 0:
            workers = (multiprocessing.cpu_count() * 2) + 1
        
        logger.info(f"Using Gunicorn with {workers} workers")
        from gunicorn.app.base import BaseApplication
        
        class GunicornApp(BaseApplication):
            def __init__(self, app, options=None):
                self.options = options or {}
                self.application = app
                super().__init__()
                
            def load_config(self):
                for key, value in self.options.items():
                    self.cfg.set(key.lower(), value)
                    
            def load(self):
                return self.application
        
        # Configure Gunicorn
        options = {
            'bind': f"{bind_host}:{bind_port}",
            'workers': workers,
            'threads': threads,
            'worker_class': 'gthread',
            'timeout': config.get('TIMEOUT', 120),
            'worker_connections': config.get('WORKER_CONNECTIONS', 1000),
            'preload_app': True,
            'accesslog': '-',
            'errorlog': '-',
            'loglevel': config.get('LOG_LEVEL', 'info').lower(),
            'capture_output': True,
            'proc_name': 'triton'
        }
        
        # Run Gunicorn
        GunicornApp(app, options).run()
        
    elif has_waitress:
        logger.info(f"Using Waitress with {threads} threads per worker")
        from waitress import serve
        
        # Run Waitress
        serve(app, host=bind_host, port=bind_port, threads=workers*threads)
        
    else:
        logger.warning("No production WSGI server found. Install Gunicorn (Linux/macOS) or Waitress (Windows).")
        logger.info("Falling back to Flask development server (NOT RECOMMENDED FOR PRODUCTION)")
        
        # Fallback to Flask server with warning
        import warnings
        warnings.warn("Using Flask development server in production environment is not recommended")
        app.run(host=bind_host, port=bind_port, threaded=True)

# Main entry point
if __name__ == "__main__":
    # Check if we should run the production server directly
    if os.getenv('FLASK_ENV', 'production') == 'production' and '--production' in sys.argv:
        sys.argv.remove('--production')
        run_production_server()
    else:
        cli()
