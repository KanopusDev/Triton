import logging
import json
import time
import threading
import requests
import traceback
import uuid
import os
from typing import Dict, List, Any, Optional, Tuple, Union, Callable
from datetime import datetime, timedelta
from functools import wraps
import socket
import platform
import psutil

# Configure logging
logger = logging.getLogger("triton.monitor")

class MonitoringService:
    """Service for monitoring application activity and sending alerts"""
    
    def __init__(self, app_name: str = "Triton", config: Optional[Dict[str, Any]] = None):
        """
        Initialize the monitoring service
        
        Args:
            app_name: Name of the application
            config: Configuration dictionary
        """
        self.app_name = app_name
        self.config = config or {}
        self.discord_webhook_url = self.config.get("DISCORD_WEBHOOK_URL", os.getenv("DISCORD_WEBHOOK_URL", ""))
        self.started_at = datetime.utcnow()
        self.host = socket.gethostname()
        self.metrics = {
            "requests": 0,
            "errors": 0,
            "warnings": 0,
            "response_times": [],
            "memory_usage": []
        }
        
        # Configure event handlers
        self.event_handlers = {}
        
        # Check if monitoring is enabled
        self.enabled = bool(self.discord_webhook_url) and self.config.get("MONITORING_ENABLED", True)
        
        if self.enabled:
            logger.info(f"Monitoring service initialized for {app_name} on {self.host}")
            # Send startup notification
            self.send_startup_notification()
            # Start background monitoring thread
            self._start_background_monitor()
        else:
            logger.warning("Monitoring service is disabled - no webhook URL provided")
    
    def _start_background_monitor(self):
        """Start a background thread for monitoring system metrics"""
        def monitor_loop():
            while True:
                try:
                    # Record memory usage
                    process = psutil.Process(os.getpid())
                    memory_mb = process.memory_info().rss / 1024 / 1024
                    self.metrics["memory_usage"].append((datetime.utcnow(), memory_mb))
                    
                    # Keep only last 100 measurements
                    if len(self.metrics["memory_usage"]) > 100:
                        self.metrics["memory_usage"] = self.metrics["memory_usage"][-100:]
                    
                    # Check if memory usage is too high (> 1GB)
                    if memory_mb > 1024:
                        self.send_alert(
                            title="High Memory Usage",
                            message=f"Process is using {memory_mb:.2f}MB of memory",
                            level="warning"
                        )
                        
                except Exception as e:
                    logger.error(f"Error in monitoring thread: {str(e)}")
                
                # Sleep for 5 minutes
                time.sleep(300)
        
        # Start the thread
        thread = threading.Thread(target=monitor_loop, daemon=True)
        thread.start()
        logger.info("Background monitoring thread started")
    
    def send_startup_notification(self):
        """Send a notification that the application has started"""
        if not self.enabled:
            return
            
        # Get system information
        python_version = platform.python_version()
        system_info = f"{platform.system()} {platform.release()}"
        
        message = {
            "embeds": [{
                "title": f"🟢 {self.app_name} Started",
                "description": f"Application started on {self.host}",
                "color": 3066993,  # Green
                "fields": [
                    {
                        "name": "Environment",
                        "value": os.getenv("FLASK_ENV", "production"),
                        "inline": True
                    },
                    {
                        "name": "Python Version",
                        "value": python_version,
                        "inline": True
                    },
                    {
                        "name": "System",
                        "value": system_info,
                        "inline": True
                    },
                    {
                        "name": "Timestamp",
                        "value": self.started_at.strftime("%Y-%m-%d %H:%M:%S UTC"),
                        "inline": False
                    }
                ],
                "footer": {
                    "text": f"{self.app_name} Monitoring Service"
                },
                "timestamp": datetime.utcnow().isoformat()
            }]
        }
        
        self._send_to_discord(message)
    
    def send_alert(self, title: str, message: str, level: str = "info", 
                   data: Optional[Dict[str, Any]] = None, notify: bool = False):
        """Send an alert notification
        
        Args:
            title: Alert title
            message: Alert message
            level: Alert level (info, warning, error, critical)
            data: Additional data to include
            notify: Whether to use @here mention for critical alerts
        """
        if not self.enabled:
            return
            
        # Map level to color
        colors = {
            "info": 3447003,      # Blue
            "success": 3066993,   # Green
            "warning": 16776960,  # Yellow
            "error": 15158332,    # Red
            "critical": 10038562  # Purple
        }
        color = colors.get(level, colors["info"])
        
        # Create embed
        embed = {
            "title": title,
            "description": message,
            "color": color,
            "fields": [
                {
                    "name": "Level",
                    "value": level.upper(),
                    "inline": True
                },
                {
                    "name": "Host",
                    "value": self.host,
                    "inline": True
                },
                {
                    "name": "Timestamp",
                    "value": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
                    "inline": True
                }
            ],
            "footer": {
                "text": f"{self.app_name} Monitoring Service"
            },
            "timestamp": datetime.utcnow().isoformat()
        }
        
        # Add data field if provided
        if data:
            try:
                formatted_data = json.dumps(data, indent=2, sort_keys=True)
                if len(formatted_data) > 1024:
                    formatted_data = formatted_data[:1000] + "...[truncated]"
                
                embed["fields"].append({
                    "name": "Additional Data",
                    "value": f"```json\n{formatted_data}\n```",
                    "inline": False
                })
            except Exception as e:
                logger.error(f"Error formatting alert data: {str(e)}")
        
        # Prepare message
        discord_message = {"embeds": [embed]}
        
        # Add @here mention for critical alerts
        if level == "critical" and notify:
            discord_message["content"] = "@here Critical alert!"
            
        self._send_to_discord(discord_message)
    
    def log_error(self, error: Exception, request_info: Optional[Dict[str, Any]] = None, 
                  user_info: Optional[Dict[str, Any]] = None, send_alert: bool = True):
        """Log an error and optionally send an alert
        
        Args:
            error: The exception object
            request_info: Information about the request
            user_info: Information about the user
            send_alert: Whether to send an alert
        
        Returns:
            str: The error ID
        """
        error_id = str(uuid.uuid4())
        error_type = type(error).__name__
        error_message = str(error)
        stack_trace = traceback.format_exc()
        
        # Log the error
        logger.error(f"Error ID {error_id}: {error_type}: {error_message}\n{stack_trace}")
        
        # Track error count
        self.metrics["errors"] += 1
        
        # Prepare data for alert
        alert_data = {
            "error_id": error_id,
            "error_type": error_type,
            "error_message": error_message,
            "timestamp": datetime.utcnow().isoformat()
        }
        
        if request_info:
            alert_data["request"] = {
                "path": request_info.get("path", ""),
                "method": request_info.get("method", ""),
                "ip": request_info.get("ip", "")
            }
            
        if user_info:
            alert_data["user"] = {
                "user_id": user_info.get("user_id", ""),
                "username": user_info.get("username", ""),
                "email": user_info.get("email", "")
            }
        
        # Send alert if enabled
        if send_alert and self.enabled:
            self.send_alert(
                title=f"Error: {error_type}",
                message=error_message,
                level="error" if not "critical" in error_type.lower() else "critical",
                data=alert_data,
                notify="critical" in error_type.lower()
            )
        
        return error_id
    
    def log_request(self, path: str, method: str, status_code: int, 
                   response_time: float, user_id: Optional[str] = None):
        """Log an API request
        
        Args:
            path: Request path
            method: HTTP method
            status_code: Response status code
            response_time: Response time in seconds
            user_id: User ID if authenticated
        """
        # Track request count
        self.metrics["requests"] += 1
        
        # Track response time
        self.metrics["response_times"].append((datetime.utcnow(), response_time))
        
        # Keep only last 1000 response times
        if len(self.metrics["response_times"]) > 1000:
            self.metrics["response_times"] = self.metrics["response_times"][-1000:]
        
        # Log slow requests (>2 seconds)
        if response_time > 2:
            logger.warning(f"Slow request: {method} {path} - {response_time:.2f}s")
            
            # Alert on very slow requests (>5 seconds)
            if response_time > 5 and self.enabled:
                self.send_alert(
                    title="Slow Request",
                    message=f"{method} {path} took {response_time:.2f} seconds",
                    level="warning",
                    data={
                        "method": method,
                        "path": path,
                        "status_code": status_code,
                        "response_time": response_time,
                        "user_id": user_id
                    }
                )
        
        # Alert on server errors
        if status_code >= 500 and self.enabled:
            self.send_alert(
                title="Server Error",
                message=f"{method} {path} returned {status_code}",
                level="error",
                data={
                    "method": method,
                    "path": path,
                    "status_code": status_code,
                    "response_time": response_time,
                    "user_id": user_id
                }
            )
    
    def register_event_handler(self, event_type: str, handler: Callable):
        """Register a handler for a specific event type
        
        Args:
            event_type: The type of event to handle
            handler: The handler function
        """
        if event_type not in self.event_handlers:
            self.event_handlers[event_type] = []
            
        self.event_handlers[event_type].append(handler)
        logger.debug(f"Registered handler for event type: {event_type}")
    
    def emit_event(self, event_type: str, data: Dict[str, Any]):
        """Emit an event to all registered handlers
        
        Args:
            event_type: The type of event
            data: Event data
        """
        if event_type not in self.event_handlers:
            return
        
        for handler in self.event_handlers[event_type]:
            try:
                handler(data)
            except Exception as e:
                logger.error(f"Error in event handler for {event_type}: {str(e)}")
    
    def _send_to_discord(self, message: Dict[str, Any]) -> bool:
        """Send a message to Discord webhook
        
        Args:
            message: The message payload
            
        Returns:
            bool: Whether the message was sent successfully
        """
        if not self.discord_webhook_url:
            logger.warning("Discord webhook URL not configured")
            return False
        
        try:
            response = requests.post(
                self.discord_webhook_url,
                json=message,
                timeout=5,
                headers={"Content-Type": "application/json"}
            )
            
            if response.status_code >= 400:
                logger.error(f"Error sending Discord webhook: {response.status_code} {response.text}")
                return False
                
            return True
            
        except Exception as e:
            logger.error(f"Error sending Discord webhook: {str(e)}")
            return False
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get current metrics
        
        Returns:
            Dict: Current metrics
        """
        uptime = datetime.utcnow() - self.started_at
        
        # Calculate average response time from the last 1000 requests
        avg_response_time = 0
        if self.metrics["response_times"]:
            times = [t[1] for t in self.metrics["response_times"]]
            avg_response_time = sum(times) / len(times)
        
        # Calculate current memory usage
        memory_usage = 0
        try:
            process = psutil.Process(os.getpid())
            memory_usage = process.memory_info().rss / 1024 / 1024  # MB
        except:
            pass
        
        return {
            "app_name": self.app_name,
            "host": self.host,
            "started_at": self.started_at.isoformat(),
            "uptime_seconds": uptime.total_seconds(),
            "uptime_formatted": str(uptime).split('.')[0],  # Remove microseconds
            "requests": self.metrics["requests"],
            "errors": self.metrics["errors"],
            "warnings": self.metrics["warnings"],
            "avg_response_time_ms": avg_response_time * 1000,
            "memory_usage_mb": memory_usage
        }
    
    def performance_timer(self, name: str):
        """Decorator for timing function execution
        
        Args:
            name: Name of the operation
            
        Returns:
            Callable: Decorator function
        """
        def decorator(func):
            @wraps(func)
            def wrapper(*args, **kwargs):
                start_time = time.time()
                result = func(*args, **kwargs)
                elapsed_time = time.time() - start_time
                
                # Log slow operations
                if elapsed_time > 1:
                    logger.info(f"Slow operation: {name} took {elapsed_time:.2f}s")
                
                return result
            return wrapper
        return decorator
