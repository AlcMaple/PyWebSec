"""
XSS (Cross-Site Scripting) protection filter for PyWebSec.
"""

import re
import html
from typing import Dict, List, Optional, Tuple, Any

# XSS攻击的常见模式
XSS_PATTERNS = [
    r"<script[^>]*>.*?</script>",  # <script> 标签
    r"javascript\s*:",  # javascript: 协议
    r"on\w+\s*=",  # 事件处理程序（如onclick=）
    r"<iframe[^>]*>",  # <iframe> 标签
    r"<img[^>]*\s+onerror\s*=",  # 图片onerror事件
    r"document\.cookie",  # 访问cookie
    r"document\.write",  # 文档写入
    r"document\.location",  # 文档位置
    r"eval\s*\(",  # eval() 函数
    r"setTimeout\s*\(",  # 定时器函数
    r"setInterval\s*\(",  # 定时器函数
    r"alert\s*\(",  # alert() 函数
    r"String\.fromCharCode\(", # 字符编码转换
    r"(?:\\x[0-9a-fA-F]{2}){2,}", # 十六进制编码
]

class XSSFilter:
    """
    Filter for detecting and blocking Cross-Site Scripting (XSS) attacks.
    """
    
    def __init__(self, logger=None):
        """
        Initialize the XSS filter.
        
        Args:
            logger: Optional logger instance.
        """
        self.logger = logger
        self.patterns = [re.compile(pattern, re.IGNORECASE) for pattern in XSS_PATTERNS]
    
    def is_xss_attack(self, value: str) -> Tuple[bool, Optional[str]]:
        """
        Check if a string contains XSS attack patterns.
        
        Args:
            value: The string to check.
            
        Returns:
            A tuple of (is_xss, matched_pattern).
        """
        if not value or not isinstance(value, str):
            return False, None
        
        for i, pattern in enumerate(self.patterns):
            match = pattern.search(value)
            if match:
                pattern_desc = XSS_PATTERNS[i]
                return True, f"Matched pattern: {pattern_desc}, Value: {match.group(0)}"
        
        return False, None
    
    def check_parameter(self, param_name: str, param_value: Any) -> Tuple[bool, Optional[str]]:
        """
        Check a request parameter for XSS attacks.
        
        Args:
            param_name: The name of the parameter.
            param_value: The value of the parameter.
            
        Returns:
            A tuple of (is_xss, matched_pattern).
        """
        if isinstance(param_value, str):
            is_xss, pattern = self.is_xss_attack(param_value)
            if is_xss:
                if self.logger:
                    self.logger.log_attack(
                        "XSS",
                        f"Parameter: {param_name}, {pattern}",
                        {"parameter": param_name}
                    )
                return True, pattern
        elif isinstance(param_value, list):
            for item in param_value:
                if isinstance(item, str):
                    is_xss, pattern = self.is_xss_attack(item)
                    if is_xss:
                        if self.logger:
                            self.logger.log_attack(
                                "XSS",
                                f"Parameter: {param_name} (list item), {pattern}",
                                {"parameter": param_name}
                            )
                        return True, pattern
        
        return False, None
    
    def check_request(self, request_params: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
        """
        Check all request parameters for XSS attacks.
        
        Args:
            request_params: Dictionary of request parameters.
            
        Returns:
            A tuple of (is_xss, reason).
        """
        for param_name, param_value in request_params.items():
            is_xss, pattern = self.check_parameter(param_name, param_value)
            if is_xss:
                return True, f"XSS attack detected in parameter '{param_name}': {pattern}"
        
        return False, None
    
    def sanitize_html(self, value: str) -> str:
        """
        Sanitize HTML content by escaping special characters.
        
        Args:
            value: The string to sanitize.
            
        Returns:
            Sanitized string.
        """
        if not value or not isinstance(value, str):
            return value
        
        return html.escape(value)
    
    def sanitize_params(self, request_params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Sanitize all request parameters to prevent XSS.
        
        Args:
            request_params: Dictionary of request parameters.
            
        Returns:
            Dictionary with sanitized parameters.
        """
        sanitized_params = {}
        
        for param_name, param_value in request_params.items():
            if isinstance(param_value, str):
                sanitized_params[param_name] = self.sanitize_html(param_value)
            elif isinstance(param_value, list):
                sanitized_list = []
                for item in param_value:
                    if isinstance(item, str):
                        sanitized_list.append(self.sanitize_html(item))
                    else:
                        sanitized_list.append(item)
                sanitized_params[param_name] = sanitized_list
            else:
                sanitized_params[param_name] = param_value
        
        return sanitized_params