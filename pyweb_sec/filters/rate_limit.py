"""
请求速率限制功能，用于防止暴力攻击和DoS攻击。
"""

import time
from typing import Dict, Optional, Tuple, Any, List
from collections import defaultdict
import threading

class RateLimitFilter:
    """
    过滤器用于限制请求速率，防止暴力攻击和DoS攻击。
    """
    
    def __init__(self, logger=None, requests_per_minute: int = 60, window_size: int = 60):
        """
        初始化速率限制过滤器。
        
        Args:
            logger: 可选的日志记录器实例。
            requests_per_minute: 每分钟允许的最大请求数。
            window_size: 滑动窗口大小（秒）。
        """
        self.logger = logger
        self.requests_per_minute = requests_per_minute
        self.window_size = window_size
        
        # 记录每个IP的请求时间戳
        self.request_records = defaultdict(list)
        
        # IP白名单，不受速率限制
        self.whitelist = set()
        
        # 锁，用于线程安全的操作
        self.lock = threading.RLock()
        
        # 使用线程定期清理过期的记录
        self._start_cleanup_thread()
    
    def _start_cleanup_thread(self):
        """启动清理线程，定期移除过期记录"""
        def cleanup():
            while True:
                time.sleep(60)  # 每分钟清理一次
                self._cleanup_expired_records()
        
        cleanup_thread = threading.Thread(target=cleanup, daemon=True)
        cleanup_thread.start()
    
    def _cleanup_expired_records(self):
        """清理过期的请求记录"""
        current_time = time.time()
        cutoff_time = current_time - self.window_size
        
        with self.lock:
            for ip in list(self.request_records.keys()):
                # 过滤保留在窗口内的记录
                self.request_records[ip] = [
                    timestamp for timestamp in self.request_records[ip]
                    if timestamp > cutoff_time
                ]
                
                # 如果IP没有记录，移除该键
                if not self.request_records[ip]:
                    del self.request_records[ip]
    
    def add_to_whitelist(self, ip: str) -> None:
        """
        将IP添加到白名单，不受速率限制。
        
        Args:
            ip: 要添加的IP地址。
        """
        with self.lock:
            self.whitelist.add(ip)
            if self.logger:
                self.logger.log_info(f"IP {ip} 已添加到速率限制白名单")
    
    def remove_from_whitelist(self, ip: str) -> bool:
        """
        从白名单中移除IP。
        
        Args:
            ip: 要移除的IP地址。
            
        Returns:
            如果IP在白名单中并已移除则返回True，否则返回False。
        """
        with self.lock:
            if ip in self.whitelist:
                self.whitelist.remove(ip)
                if self.logger:
                    self.logger.log_info(f"IP {ip} 已从速率限制白名单中移除")
                return True
            return False
    
    def set_rate_limit(self, requests_per_minute: int) -> None:
        """
        设置每分钟允许的最大请求数。
        
        Args:
            requests_per_minute: 每分钟允许的最大请求数。
        """
        with self.lock:
            self.requests_per_minute = requests_per_minute
            if self.logger:
                self.logger.log_info(f"速率限制已更新为每分钟 {requests_per_minute} 个请求")
    
    def check_rate_limit(self, ip: str) -> Tuple[bool, Optional[int]]:
        """
        检查IP是否超过速率限制。
        
        Args:
            ip: 要检查的IP地址。
            
        Returns:
            一个元组(is_allowed, retry_after)。如果允许请求，is_allowed为True；
            否则为False，并在retry_after中提供建议的重试等待时间（秒）。
        """
        # 白名单IP不受限制
        with self.lock:
            if ip in self.whitelist:
                return True, None
            
            current_time = time.time()
            cutoff_time = current_time - self.window_size
            
            # 清理过期记录
            self.request_records[ip] = [
                timestamp for timestamp in self.request_records[ip]
                if timestamp > cutoff_time
            ]
            
            # 计算时间窗口内的请求数
            request_count = len(self.request_records[ip])
            
            # 检查是否超过限制
            if request_count >= self.requests_per_minute:
                # 计算最早请求的时间戳
                oldest_request = min(self.request_records[ip]) if self.request_records[ip] else current_time
                # 计算需要等待的时间
                retry_after = int(oldest_request + self.window_size - current_time) + 1
                retry_after = max(1, retry_after)  # 确保至少等待1秒
                
                if self.logger:
                    self.logger.log_blocked("速率限制", {
                        "ip": ip, 
                        "请求数": request_count,
                        "时间窗口(秒)": self.window_size,
                        "限制": self.requests_per_minute,
                        "建议等待(秒)": retry_after
                    })
                
                return False, retry_after
            
            # 记录本次请求时间戳
            self.request_records[ip].append(current_time)
            return True, None
    
    def check_request(self, environ: Dict[str, Any]) -> Tuple[bool, Optional[Dict[str, Any]]]:
        """
        检查请求是否超过速率限制。
        
        Args:
            environ: WSGI环境字典。
            
        Returns:
            一个元组(is_allowed, response_headers)。如果允许请求，is_allowed为True；
            否则为False，并在response_headers中提供相应的响应头。
        """
        # 尝试从HTTP头中获取客户端IP地址
        ip = environ.get('REMOTE_ADDR', '')
        
        # 处理X-Forwarded-For头（如果在代理服务器后面）
        forwarded_for = environ.get('HTTP_X_FORWARDED_FOR')
        if forwarded_for:
            # 使用最左边的IP（通常是原始客户端IP）
            ip = forwarded_for.split(',')[0].strip()
        
        # 检查速率限制
        is_allowed, retry_after = self.check_rate_limit(ip)
        
        if not is_allowed:
            # 设置响应头，包括Retry-After
            response_headers = {
                'Retry-After': str(retry_after),
                'X-RateLimit-Limit': str(self.requests_per_minute),
                'X-RateLimit-Reset': str(int(time.time() + retry_after))
            }
            return False, response_headers
        
        return True, None