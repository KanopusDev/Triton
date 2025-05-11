import sqlite3
import logging
import time
import random
import threading
import json
import hashlib
import queue
import functools
from typing import Dict, List, Any, Optional, Tuple, Union, Callable, Generator
from contextlib import contextmanager
from datetime import datetime, timedelta
import os
import shutil
import traceback

# Configure logging
logger = logging.getLogger("triton.database")

class DatabaseService:
    """Enterprise-grade service for managing database connections and operations"""
    
    def __init__(self, db_path: str, app_config: Optional[Dict[str, Any]] = None):
        """
        Initialize the database service
        
        Args:
            db_path: Path to SQLite database file
            app_config: Optional application configuration dictionary
        """
        self.db_path = db_path
        self.app_config = app_config or {}
        
        # Enhanced connection pool with queue-based management
        self._pool_size = self.app_config.get("DB_POOL_SIZE", 5)
        self._connection_pool = queue.Queue(maxsize=self._pool_size)
        self._active_connections_count = 0
        self._pool_lock = threading.RLock()
        
        # Track if initialized
        self._initialized = False
        self._initialization_lock = threading.RLock()
        
        # Create database directory if it doesn't exist
        os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)
        
        # Initialize stats tracking
        self.stats = {
            "connections_created": 0,
            "connections_reused": 0,
            "transactions_committed": 0,
            "transactions_rolled_back": 0,
            "lock_wait_time": 0,
            "query_count": 0,
            "slow_queries": 0,
            "query_cache_hits": 0,
            "deadlocks_detected": 0,
            "version": "0.0.0"
        }
        
        # Query cache (for read-only queries)
        self._query_cache = {}
        self._query_cache_ttl = self.app_config.get("QUERY_CACHE_TTL", 30)  # seconds
        self._max_cache_size = self.app_config.get("MAX_QUERY_CACHE_SIZE", 100)
        
        # Database schema version
        self._current_schema_version = "1.0.0"
        
        # Last vacuum time
        self._last_vacuum_time = time.time()
        self._vacuum_interval = self.app_config.get("VACUUM_INTERVAL", 86400)  # 24 hours
        
        # Register cleanup on interpreter shutdown
        self._register_cleanup()
    
    def _register_cleanup(self):
        """Register cleanup function to run on interpreter shutdown"""
        import atexit
        atexit.register(self._cleanup)
    
    def _cleanup(self):
        """Clean up resources when service is destroyed"""
        logger.info("Cleaning up database connections")
        with self._pool_lock:
            # Close all connections in the pool
            while not self._connection_pool.empty():
                try:
                    conn = self._connection_pool.get_nowait()
                    if conn and hasattr(conn, 'close'):
                        try:
                            conn.close()
                        except Exception as e:
                            logger.warning(f"Error closing connection during cleanup: {str(e)}")
                except queue.Empty:
                    break
    
    def _create_connection(self, timeout: int = 20) -> sqlite3.Connection:
        """
        Create a new database connection
        
        Args:
            timeout: Number of seconds to wait for database locks
            
        Returns:
            sqlite3.Connection: A new database connection
        
        Raises:
            RuntimeError: If connection cannot be established
        """
        retry_count = 0
        max_retries = 3
        
        while retry_count < max_retries:
            try:
                conn = sqlite3.connect(self.db_path, timeout=timeout)
                conn.row_factory = sqlite3.Row
                
                # Enable foreign keys
                conn.execute("PRAGMA foreign_keys = ON")
                
                # Set busy timeout (milliseconds)
                conn.execute(f"PRAGMA busy_timeout = {timeout * 1000}")
                
                # Set optimal journal mode for performance and concurrency
                conn.execute("PRAGMA journal_mode = WAL")
                
                # Set synchronous mode for durability vs. performance tradeoff
                # NORMAL offers good performance with reasonable durability
                conn.execute("PRAGMA synchronous = NORMAL")
                
                # Set temp store to memory for better performance
                conn.execute("PRAGMA temp_store = MEMORY")
                
                # Set secure delete off for better performance
                # Note: Only turn off in environments where security of deleted data isn't a concern
                if not self.app_config.get("SECURE_DELETE", False):
                    conn.execute("PRAGMA secure_delete = OFF")
                
                # Configure memory-mapped I/O for better performance
                # Default to 64MB
                mmap_size = self.app_config.get("MMAP_SIZE", 67108864)
                conn.execute(f"PRAGMA mmap_size = {mmap_size}")
                
                # Update stats
                self.stats["connections_created"] += 1
                
                # Track connection count (thread-safe)
                with self._pool_lock:
                    self._active_connections_count += 1
                
                return conn
            except sqlite3.OperationalError as e:
                if "database is locked" in str(e) and retry_count < max_retries - 1:
                    retry_count += 1
                    # Exponential backoff with jitter for retries
                    sleep_time = (2 ** retry_count) * 0.1 + random.uniform(0, 0.1)
                    logger.warning(f"Database locked while creating connection, retrying in {sleep_time:.2f}s (attempt {retry_count}/{max_retries})")
                    self.stats["lock_wait_time"] += sleep_time
                    time.sleep(sleep_time)
                else:
                    raise RuntimeError(f"Failed to create database connection: {str(e)}") from e
        
        raise RuntimeError(f"Failed to create database connection after {max_retries} attempts")
    
    def _get_connection_from_pool(self, timeout: int = 20) -> sqlite3.Connection:
        """
        Get a connection from the pool or create a new one
        
        Args:
            timeout: Number of seconds to wait for database locks
            
        Returns:
            sqlite3.Connection: A database connection
        """
        try:
            # Try to get a connection from the pool
            conn = self._connection_pool.get_nowait()
            
            # Verify connection is still usable
            try:
                conn.execute("SELECT 1").fetchone()
                self.stats["connections_reused"] += 1
                return conn
            except sqlite3.Error:
                # Connection is stale, create a new one
                logger.debug("Found stale connection in pool, creating new connection")
                # Close the stale connection
                try:
                    conn.close()
                except Exception:
                    pass
                    
                # Update connection count (thread-safe)
                with self._pool_lock:
                    self._active_connections_count -= 1
                    
                return self._create_connection(timeout)
                
        except queue.Empty:
            # No connections in pool, create new one
            return self._create_connection(timeout)
    
    def _return_connection_to_pool(self, conn: sqlite3.Connection):
        """
        Return a connection to the pool
        
        Args:
            conn: The database connection to return
        """
        try:
            # Only return the connection if it's still operational
            if conn:
                try:
                    # Execute a simple query to make sure connection is still good
                    conn.execute("SELECT 1").fetchone()
                    
                    try:
                        # Try to put the connection back in the pool
                        self._connection_pool.put_nowait(conn)
                        return  # Connection returned successfully
                    except queue.Full:
                        # Pool is full, close the connection
                        conn.close()
                        # Update connection count (thread-safe)
                        with self._pool_lock:
                            self._active_connections_count -= 1
                except sqlite3.Error:
                    # Connection is bad, close it
                    conn.close()
                    # Update connection count (thread-safe)
                    with self._pool_lock:
                        self._active_connections_count -= 1
        except Exception as e:
            logger.warning(f"Error returning connection to pool: {str(e)}")
            if conn:
                try:
                    conn.close()
                except Exception:
                    pass
                
                # Ensure we decrement the counter even if errors occur
                with self._pool_lock:
                    self._active_connections_count -= 1
    
    @contextmanager
    def get_connection(self, timeout: int = 20, isolation_level: Optional[str] = None) -> Generator[sqlite3.Connection, None, None]:
        """
        Improved context manager for database connections with proper pool management
        
        Args:
            timeout: Number of seconds to wait for database locks
            isolation_level: SQLite isolation level (None = autocommit mode)
            
        Yields:
            sqlite3.Connection: Database connection
        """
        conn = None
        
        try:
            conn = self._get_connection_from_pool(timeout)
            
            # Set isolation level if specified
            if isolation_level is not None:
                conn.isolation_level = isolation_level
            
            yield conn
        except sqlite3.OperationalError as e:
            if conn:
                # Always rollback on error to release locks
                conn.rollback()
                self.stats["transactions_rolled_back"] += 1
                
            if "database is locked" in str(e):
                logger.error(f"Database lock encountered during operation: {str(e)}")
                raise RuntimeError("Database is temporarily busy. Please try again.") from e
            
            # Check for deadlock
            if "deadlock detected" in str(e).lower() or "database is locked" in str(e).lower():
                self.stats["deadlocks_detected"] += 1
                logger.error(f"Deadlock detected: {str(e)}")
            
            raise
        except Exception as e:
            if conn:
                # Always rollback on any exception
                conn.rollback()
                self.stats["transactions_rolled_back"] += 1
            
            logger.error(f"Database error: {str(e)}\n{traceback.format_exc()}")
            raise
        else:
            # If no exception and not in autocommit mode, commit the transaction
            if conn and isolation_level is not None:
                conn.commit()
                self.stats["transactions_committed"] += 1
        finally:
            # If vacuum interval has passed, perform maintenance
            if conn:
                self._perform_maintenance_if_needed(conn)
                
                # Return connection to pool if still available
                if isolation_level is not None:
                    # Reset to autocommit mode before returning
                    conn.isolation_level = None
                self._return_connection_to_pool(conn)

    def _perform_maintenance_if_needed(self, conn: sqlite3.Connection) -> None:
        """
        Perform database maintenance if the maintenance interval has elapsed
        
        Args:
            conn: Active database connection
        """
        # Only perform maintenance if vacuum interval has passed
        current_time = time.time()
        if current_time - self._last_vacuum_time < self._vacuum_interval:
            return
            
        try:
            # Use a random probability (5%) to avoid all processes trying to vacuum at once
            if random.random() < 0.05:
                # Check database size to determine if vacuum is needed
                page_size = conn.execute("PRAGMA page_size").fetchone()[0]
                page_count = conn.execute("PRAGMA page_count").fetchone()[0]
                db_size_mb = (page_size * page_count) / (1024 * 1024)
                
                # Only vacuum if database is over 5MB
                if db_size_mb > 5:
                    logger.info(f"Performing scheduled database maintenance (size: {db_size_mb:.2f}MB)")
                    
                    # Check for free pages that could be reclaimed
                    free_pages = conn.execute("PRAGMA freelist_count").fetchone()[0]
                    free_space_mb = (page_size * free_pages) / (1024 * 1024)
                    
                    # Only vacuum if there's significant space to reclaim (>0.5MB)
                    if free_space_mb > 0.5:
                        logger.info(f"Running VACUUM (potential space savings: {free_space_mb:.2f}MB)")
                        conn.execute("VACUUM")
                    
                    # Run optimization regardless
                    conn.execute("PRAGMA optimize")
                    
                # Update the last vacuum time regardless of whether we actually vacuumed
                self._last_vacuum_time = current_time
                logger.debug("Database maintenance completed")
        except Exception as e:
            # Non-critical error, just log it
            logger.warning(f"Error during database maintenance: {str(e)}")
            # Still update the last vacuum time to prevent repeated failures
            self._last_vacuum_time = current_time

    def get_connection_stats(self) -> Dict[str, int]:
        """Get current connection statistics
        
        Returns:
            Dict: Connection statistics
        """
        with self._pool_lock:
            pool_size = self._connection_pool.qsize()
            return {
                "active_connections": self._active_connections_count,
                "pool_connections": pool_size,
                "max_pool_size": self._pool_size
            }
    
    def initialize_database(self) -> None:
        """Initialize the database schema and create required tables if they don't exist"""
        logger.info(f"Initializing database at {self.db_path}")
        
        # Create required tables
        with self.get_connection(isolation_level="IMMEDIATE") as conn:
            # Check for schema version table first
            conn.execute('''
            CREATE TABLE IF NOT EXISTS schema_version (
                version TEXT PRIMARY KEY,
                applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            ''')
            
            # Check current schema version
            current_version = conn.execute("SELECT version FROM schema_version ORDER BY applied_at DESC LIMIT 1").fetchone()
            
            if not current_version:
                # First time initialization - create all tables
                logger.info("First-time database initialization")
                
                # Users table
                conn.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    user_id TEXT PRIMARY KEY,
                    username TEXT NOT NULL,
                    email TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    role TEXT DEFAULT 'user',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_login TIMESTAMP,
                    active INTEGER DEFAULT 1
                )
                ''')
                
                # Sessions table
                conn.execute('''
                CREATE TABLE IF NOT EXISTS sessions (
                    session_id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    token TEXT UNIQUE NOT NULL,
                    ip_address TEXT,
                    user_agent TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    expires_at TIMESTAMP NOT NULL,
                    FOREIGN KEY (user_id) REFERENCES users (user_id) ON DELETE CASCADE
                )
                ''')
                
                # Invitations table
                conn.execute('''
                CREATE TABLE IF NOT EXISTS invitations (
                    invitation_id TEXT PRIMARY KEY,
                    email TEXT NOT NULL,
                    token TEXT UNIQUE NOT NULL,
                    created_by TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    expires_at TIMESTAMP NOT NULL,
                    used INTEGER DEFAULT 0,
                    FOREIGN KEY (created_by) REFERENCES users (user_id)
                )
                ''')
                
                # Conversations table
                conn.execute('''
                CREATE TABLE IF NOT EXISTS conversations (
                    conversation_id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    conversation_name TEXT NOT NULL,
                    first_message TEXT,
                    last_message TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    message_count INTEGER DEFAULT 0,
                    FOREIGN KEY (user_id) REFERENCES users (user_id)
                )
                ''')
                
                # Messages table
                conn.execute('''
                CREATE TABLE IF NOT EXISTS messages (
                    message_id TEXT PRIMARY KEY,
                    conversation_id TEXT NOT NULL,
                    user_message TEXT,
                    assistant_message TEXT,
                    reasoning TEXT,
                    search_context TEXT,
                    model TEXT,
                    features TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    token_count INTEGER,
                    FOREIGN KEY (conversation_id) REFERENCES conversations (conversation_id) ON DELETE CASCADE
                )
                ''')
                
                # Images table
                conn.execute('''
                CREATE TABLE IF NOT EXISTS images (
                    image_id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    prompt TEXT NOT NULL,
                    conversation_id TEXT,
                    model TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users (user_id),
                    FOREIGN KEY (conversation_id) REFERENCES conversations (conversation_id) ON DELETE SET NULL
                )
                ''')
                
                # Error logs table
                conn.execute('''
                CREATE TABLE IF NOT EXISTS error_logs (
                    error_id TEXT PRIMARY KEY,
                    error_type TEXT NOT NULL,
                    error_message TEXT NOT NULL,
                    stack_trace TEXT,
                    request_path TEXT,
                    request_method TEXT,
                    request_data TEXT,
                    user_id TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    resolved INTEGER DEFAULT 0,
                    FOREIGN KEY (user_id) REFERENCES users (user_id) ON DELETE SET NULL
                )
                ''')
                
                # Create indexes for faster lookups
                conn.execute("CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions (token)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions (user_id)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_conversations_user_id ON conversations (user_id, updated_at)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_messages_conversation_id ON messages (conversation_id, created_at)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_invitations_email ON invitations (email)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_invitations_token ON invitations (token)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_images_user_id ON images (user_id, created_at)")
                
                # Record the schema version
                conn.execute("INSERT INTO schema_version (version) VALUES (?)", (self._current_schema_version,))
                
                logger.info(f"Database initialized with schema version {self._current_schema_version}")
            else:
                # Already initialized - check for migrations
                current_version = current_version[0]
                logger.info(f"Database already initialized with schema version {current_version}")
                
                # Run migrations if needed
                if current_version != self._current_schema_version:
                    self._run_migrations(conn, current_version)
    
    # ... rest of the existing code ...
