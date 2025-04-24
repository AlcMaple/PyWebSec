"""
测试请求速率限制功能的单元测试。
"""

from pyweb_sec.filters.rate_limit import RateLimitFilter
from pyweb_sec.utils.config import ConfigManager
from pyweb_sec.utils.logging import SecurityLogger
import unittest
import time


class TestRateLimit(unittest.TestCase):
    """测试RateLimitFilter类的单元测试"""

    def setUp(self):
        """测试前的设置"""
        # 创建配置
        self.config = ConfigManager()
        # 创建日志记录器
        self.logger = SecurityLogger(self.config)
        # 创建速率限制过滤器，设置较小的限制以便于测试
        self.rate_filter = RateLimitFilter(
            self.logger, requests_per_minute=5, window_size=10
        )

    def test_basic_rate_limit(self):
        """测试基本速率限制功能"""
        ip = "192.168.1.1"

        # 前5个请求应该允许
        for i in range(5):
            is_allowed, retry_after = self.rate_filter.check_rate_limit(ip)
            self.assertTrue(is_allowed, f"第 {i+1} 个请求应该被允许")
            self.assertIsNone(retry_after)

        # 第6个请求应该被拒绝
        is_allowed, retry_after = self.rate_filter.check_rate_limit(ip)
        self.assertFalse(is_allowed, "第 6 个请求应该被拒绝")
        self.assertIsNotNone(retry_after)
        self.assertGreater(retry_after, 0)

    def test_whitelist(self):
        """测试白名单功能"""
        normal_ip = "192.168.1.1"
        whitelist_ip = "10.0.0.1"

        # 将IP添加到白名单
        self.rate_filter.add_to_whitelist(whitelist_ip)

        # 发送多个请求，超过限制
        for i in range(10):
            # 正常IP的请求
            normal_allowed, _ = self.rate_filter.check_rate_limit(normal_ip)
            # 白名单IP的请求
            whitelist_allowed, _ = self.rate_filter.check_rate_limit(whitelist_ip)

            # 检查结果
            if i < 5:
                self.assertTrue(normal_allowed, f"正常IP的第 {i+1} 个请求应该被允许")
            else:
                self.assertFalse(normal_allowed, f"正常IP的第 {i+1} 个请求应该被拒绝")

            # 白名单IP应该始终允许
            self.assertTrue(whitelist_allowed, f"白名单IP的第 {i+1} 个请求应该被允许")

        # 测试从白名单中移除IP
        result = self.rate_filter.remove_from_whitelist(whitelist_ip)
        self.assertTrue(result)

        # 移除后，该IP应该受到限制
        for i in range(6):
            is_allowed, _ = self.rate_filter.check_rate_limit(whitelist_ip)
            if i < 5:
                self.assertTrue(is_allowed)
            else:
                self.assertFalse(is_allowed)

    def test_window_expiry(self):
        """测试时间窗口过期后请求恢复"""
        ip = "192.168.1.2"

        # 发送5个请求，达到限制
        for i in range(5):
            is_allowed, _ = self.rate_filter.check_rate_limit(ip)
            self.assertTrue(is_allowed)

        # 第6个请求应该被拒绝
        is_allowed, _ = self.rate_filter.check_rate_limit(ip)
        self.assertFalse(is_allowed)

        # 等待窗口过期（由于窗口设置为10秒，我们等待11秒）
        # 注意：在实际测试中，这可能会使测试运行较慢
        # 对于CI/CD环境可以考虑模拟时间而不是实际等待
        print("等待速率限制窗口过期...")
        time.sleep(11)

        # 窗口过期后，新请求应该被允许
        is_allowed, _ = self.rate_filter.check_rate_limit(ip)
        self.assertTrue(is_allowed, "窗口过期后，请求应该被允许")

    def test_request_check(self):
        """测试请求检查功能"""
        # 创建一个WSGI环境
        environ = {"REMOTE_ADDR": "192.168.1.3"}

        # 发送多个请求，超过限制
        for i in range(6):
            is_allowed, headers = self.rate_filter.check_request(environ)

            if i < 5:
                self.assertTrue(is_allowed, f"第 {i+1} 个请求应该被允许")
                self.assertIsNone(headers)
            else:
                self.assertFalse(is_allowed, f"第 {i+1} 个请求应该被拒绝")
                self.assertIsNotNone(headers)
                self.assertIn("Retry-After", headers)
                self.assertIn("X-RateLimit-Limit", headers)
                self.assertIn("X-RateLimit-Reset", headers)

    def test_forwarded_ip(self):
        """测试X-Forwarded-For头处理"""
        # 创建一个带有X-Forwarded-For头的WSGI环境
        environ = {
            "REMOTE_ADDR": "10.0.0.1",  # 代理服务器IP
            "HTTP_X_FORWARDED_FOR": "192.168.1.4, 10.0.0.1",  # 客户端真实IP在最左边
        }

        # 发送多个请求，超过限制
        for i in range(6):
            is_allowed, headers = self.rate_filter.check_request(environ)

            if i < 5:
                self.assertTrue(is_allowed, f"第 {i+1} 个请求应该被允许")
            else:
                self.assertFalse(is_allowed, f"第 {i+1} 个请求应该被拒绝")


if __name__ == "__main__":
    unittest.main()
