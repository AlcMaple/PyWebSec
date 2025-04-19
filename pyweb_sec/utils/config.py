"""
Configuration module for PyWebSec.
Handles loading and validating configuration from YAML or JSON files.
"""

import os
import yaml
import json
from typing import Dict, Any, Optional

DEFAULT_CONFIG = {
    "enabled_filters": ["sql_injection", "xss", "csrf"],
    "ip_blacklist": [],
    "rate_limit": {
        "enabled": True,
        "requests_per_minute": 60
    },
    "logging": {
        "enabled": True,
        "level": "INFO",
        "file": None
    }
}

class ConfigManager:
    """Manages configuration for the security middleware."""
    
    def __init__(self, config_path: Optional[str] = None):
        """
        Initialize the configuration manager.
        
        Args:
            config_path: Path to a YAML or JSON configuration file.
        """
        self.config = DEFAULT_CONFIG.copy()
        if config_path:
            self.load_config(config_path)
    
    def load_config(self, config_path: str) -> None:
        """
        Load configuration from a file.
        
        Args:
            config_path: Path to a YAML or JSON configuration file.
        
        Raises:
            FileNotFoundError: If the configuration file does not exist.
            ValueError: If the configuration file is not valid YAML or JSON.
        """
        if not os.path.exists(config_path):
            raise FileNotFoundError(f"Config file not found: {config_path}")
        
        try:
            # Determine file type based on extension
            if config_path.lower().endswith(('.yaml', '.yml')):
                with open(config_path, 'r') as f:
                    user_config = yaml.safe_load(f)
            elif config_path.lower().endswith('.json'):
                with open(config_path, 'r') as f:
                    user_config = json.load(f)
            else:
                raise ValueError("Config file must be YAML or JSON")
            
            # Merge user config with default config
            self._update_config(user_config)
            
        except (yaml.YAMLError, json.JSONDecodeError) as e:
            raise ValueError(f"Invalid configuration file: {str(e)}")
    
    def _update_config(self, user_config: Dict[str, Any]) -> None:
        """
        Update the configuration with user-provided values.
        
        Args:
            user_config: User-provided configuration dictionary.
        """
        # Simple recursive dictionary update
        def update_dict(d, u):
            for k, v in u.items():
                if isinstance(v, dict) and k in d and isinstance(d[k], dict):
                    update_dict(d[k], v)
                else:
                    d[k] = v
        
        update_dict(self.config, user_config)
    
    def get(self, key: str, default: Any = None) -> Any:
        """
        Get a configuration value.
        
        Args:
            key: The configuration key.
            default: The default value if the key is not found.
        
        Returns:
            The configuration value.
        """
        parts = key.split('.')
        config = self.config
        
        for part in parts:
            if part not in config:
                return default
            config = config[part]
        
        return config