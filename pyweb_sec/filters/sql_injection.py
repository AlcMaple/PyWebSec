"""
SQL Injection protection filter for PyWebSec.
"""

import re
from typing import Dict, List, Optional, Tuple, Any

# SQL 注入攻击的常见模式
SQL_INJECTION_PATTERNS = [
    r"(\b|')OR\b.+?(--|#|\/\*|;|$)",  # OR 语句
    r"(\b|')UNION\b.+?(SELECT|ALL|FROM)",  # UNION SELECT 语句
    r"(;|\b)(DROP|ALTER|CREATE|TRUNCATE|RENAME|INSERT)\b\s+\w+",  # DDL/DML 语句
    r"(/\*|--).+?",  # 注释
    r"(SLEEP|BENCHMARK|WAIT FOR DELAY|WAITFOR)\s*\([^)]*\)",  # 时间延迟攻击
    r"\bSELECT\b.+?\bFROM\b",  # 基本 SELECT 语句
    r"\bUPDATE\b.+?\bSET\b",  # UPDATE 语句
    r"\bDELETE\b.+?\bFROM\b",  # DELETE 语句
    r"(INTO|LOAD_FILE|OUTFILE)",  # 文件操作
]

class SQLInjectionFilter:
    """
    Filter for detecting and blocking SQL injection attacks.
    """
    
    def __init__(self, logger=None):
        """
        Initialize the SQL injection filter.
        
        Args:
            logger: Optional logger instance.
        """
        self.logger = logger
        self.patterns = [re.compile(pattern, re.IGNORECASE) for pattern in SQL_INJECTION_PATTERNS]
    
    def is_sql_injection(self, value: str) -> Tuple[bool, Optional[str]]:
        """
        Check if a string contains SQL injection patterns.
        
        Args:
            value: The string to check.
            
        Returns:
            A tuple of (is_injection, matched_pattern).
        """
        if not value or not isinstance(value, str):
            return False, None
        
        for i, pattern in enumerate(self.patterns):
            match = pattern.search(value)
            if match:
                pattern_desc = SQL_INJECTION_PATTERNS[i]
                return True, f"Matched pattern: {pattern_desc}, Value: {match.group(0)}"
        
        return False, None
    
    def check_parameter(self, param_name: str, param_value: Any) -> Tuple[bool, Optional[str]]:
        """
        Check a request parameter for SQL injection.
        
        Args:
            param_name: The name of the parameter.
            param_value: The value of the parameter.
            
        Returns:
            A tuple of (is_injection, matched_pattern).
        """
        if isinstance(param_value, str):
            is_injection, pattern = self.is_sql_injection(param_value)
            if is_injection:
                if self.logger:
                    self.logger.log_attack(
                        "SQL Injection",
                        f"Parameter: {param_name}, {pattern}",
                        {"parameter": param_name}
                    )
                return True, pattern
        elif isinstance(param_value, list):
            for item in param_value:
                if isinstance(item, str):
                    is_injection, pattern = self.is_sql_injection(item)
                    if is_injection:
                        if self.logger:
                            self.logger.log_attack(
                                "SQL Injection",
                                f"Parameter: {param_name} (list item), {pattern}",
                                {"parameter": param_name}
                            )
                        return True, pattern
        
        return False, None
    
    def check_request(self, request_params: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
        """
        Check all request parameters for SQL injection.
        
        Args:
            request_params: Dictionary of request parameters.
            
        Returns:
            A tuple of (is_injection, reason).
        """
        for param_name, param_value in request_params.items():
            is_injection, pattern = self.check_parameter(param_name, param_value)
            if is_injection:
                return True, f"SQL injection detected in parameter '{param_name}': {pattern}"
        
        return False, None