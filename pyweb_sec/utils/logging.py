"""
Logging utilities for PyWebSec.
"""

import logging
import os
from typing import Optional

def setup_logger(
    name: str = "pyweb_sec",
    level: str = "INFO",
    log_file: Optional[str] = None,
    format_string: Optional[str] = None
) -> logging.Logger:
    """
    Set up a logger for the security middleware.
    
    Args:
        name: Name of the logger.
        level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL).
        log_file: Optional path to a log file.
        format_string: Optional format string for log messages.
        
    Returns:
        A configured logger instance.
    """
    # Convert string level to logging level
    level_map = {
        "DEBUG": logging.DEBUG,
        "INFO": logging.INFO,
        "WARNING": logging.WARNING,
        "ERROR": logging.ERROR,
        "CRITICAL": logging.CRITICAL
    }
    log_level = level_map.get(level.upper(), logging.INFO)
    
    # Use default format if none provided
    if not format_string:
        format_string = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    
    # Create formatter
    formatter = logging.Formatter(format_string)
    
    # Configure logger
    logger = logging.getLogger(name)
    logger.setLevel(log_level)
    
    # Remove existing handlers
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)
    
    # Add file handler if log_file is specified
    if log_file:
        # Ensure log directory exists
        log_dir = os.path.dirname(log_file)
        if log_dir and not os.path.exists(log_dir):
            os.makedirs(log_dir)
        
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    
    # Add console handler
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    
    return logger

class SecurityLogger:
    """
    Logger class for security events.
    """
    
    def __init__(self, config):
        """
        Initialize the security logger.
        
        Args:
            config: Configuration manager instance.
        """
        self.config = config
        self.enabled = config.get("logging.enabled", True)
        self.level = config.get("logging.level", "INFO")
        self.log_file = config.get("logging.file")
        
        self.logger = setup_logger(
            name="pyweb_sec",
            level=self.level,
            log_file=self.log_file
        )
    
    def log_attack(self, attack_type, details, request_info):
        """
        Log a detected attack attempt.
        
        Args:
            attack_type: Type of the attack (e.g., "SQL Injection").
            details: Details about the attack.
            request_info: Information about the request.
        """
        if not self.enabled:
            return
        
        message = f"ATTACK DETECTED - Type: {attack_type}"
        context = {
            "details": details,
            "request": request_info
        }
        self.logger.warning(f"{message} | {context}")
    
    def log_blocked(self, reason, request_info):
        """
        Log a blocked request.
        
        Args:
            reason: Reason for blocking the request.
            request_info: Information about the request.
        """
        if not self.enabled:
            return
        
        message = f"REQUEST BLOCKED - Reason: {reason}"
        self.logger.info(f"{message} | Request: {request_info}")
    
    def log_error(self, error, context=None):
        """
        Log an error.
        
        Args:
            error: The error message or exception.
            context: Optional context information.
        """
        if not self.enabled:
            return
        
        if context:
            self.logger.error(f"ERROR: {error} | Context: {context}")
        else:
            self.logger.error(f"ERROR: {error}")
    
    def log_info(self, message, context=None):
        """
        Log an informational message.
        
        Args:
            message: The message to log.
            context: Optional context information.
        """
        if not self.enabled:
            return
        
        if context:
            self.logger.info(f"{message} | {context}")
        else:
            self.logger.info(message)