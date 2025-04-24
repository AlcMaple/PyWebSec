"""
测试IP过滤器功能的单元测试。
"""

from pyweb_sec.filters.ip_filter import IPFilter
from pyweb_sec.utils.config import ConfigManager
from pyweb_sec.utils.logging import SecurityLogger
import unittest


class TestIPFilter(unittest.TestCase):
    """测试IPFilter类的单元测试"""

    def setUp(self):
        """测试前的设置"""
        # 创建配置
        self.config = ConfigManager()
        # 创建日志记录器
        self.logger = SecurityLogger(self.config)
        # 创建IP过滤器
        self.ip_filter = IPFilter(self.logger)

    def test_blacklist(self):
        """测试IP黑名单功能"""
        # 设置黑名单
        self.ip_filter.set_blacklist(["192.168.1.1", "10.0.0.5", "172.16.0.0/16"])

        # 测试在黑名单中的IP
        is_allowed, reason = self.ip_filter.check_ip("192.168.1.1")
        self.assertFalse(is_allowed)
        self.assertEqual(reason, "IP在黑名单中")

        # 测试在黑名单中的CIDR范围
        is_allowed, reason = self.ip_filter.check_ip("172.16.5.10")
        self.assertFalse(is_allowed)
        self.assertEqual(reason, "IP在黑名单中")

        # 测试不在黑名单中的IP
        is_allowed, reason = self.ip_filter.check_ip("192.168.1.2")
        self.assertTrue(is_allowed)
        self.assertIsNone(reason)

    def test_whitelist(self):
        """测试IP白名单功能"""
        # 设置白名单
        self.ip_filter.set_whitelist(["192.168.1.1", "10.0.0.0/8"])
        # 启用白名单
        self.ip_filter.enable_whitelist = True

        # 测试在白名单中的IP
        is_allowed, reason = self.ip_filter.check_ip("192.168.1.1")
        self.assertTrue(is_allowed)
        self.assertIsNone(reason)

        # 测试在白名单中的CIDR范围
        is_allowed, reason = self.ip_filter.check_ip("10.5.20.30")
        self.assertTrue(is_allowed)
        self.assertIsNone(reason)

        # 测试不在白名单中的IP
        is_allowed, reason = self.ip_filter.check_ip("192.168.1.2")
        self.assertFalse(is_allowed)
        self.assertEqual(reason, "IP不在白名单中")

    def test_whitelist_priority(self):
        """测试白名单优先级高于黑名单"""
        # 设置黑名单和白名单
        self.ip_filter.set_blacklist(["192.168.1.0/24"])
        self.ip_filter.set_whitelist(["192.168.1.100"])
        # 启用白名单
        self.ip_filter.enable_whitelist = True

        # 测试同时在黑名单和白名单中的IP
        is_allowed, reason = self.ip_filter.check_ip("192.168.1.100")
        self.assertTrue(is_allowed)
        self.assertIsNone(reason)

        # 测试仅在黑名单中的IP
        is_allowed, reason = self.ip_filter.check_ip("192.168.1.101")
        self.assertFalse(is_allowed)
        self.assertEqual(reason, "IP不在白名单中")

    def test_add_remove_operations(self):
        """测试添加和移除IP地址的操作"""
        # 添加到黑名单
        self.ip_filter.add_to_blacklist("192.168.1.1")
        self.assertIn("192.168.1.1", self.ip_filter.blacklist)

        # 移除黑名单中的IP
        result = self.ip_filter.remove_from_blacklist("192.168.1.1")
        self.assertTrue(result)
        self.assertNotIn("192.168.1.1", self.ip_filter.blacklist)

        # 尝试移除不在黑名单中的IP
        result = self.ip_filter.remove_from_blacklist("192.168.1.2")
        self.assertFalse(result)

        # 添加到白名单
        self.ip_filter.add_to_whitelist("10.0.0.1")
        self.assertIn("10.0.0.1", self.ip_filter.whitelist)

        # 移除白名单中的IP
        result = self.ip_filter.remove_from_whitelist("10.0.0.1")
        self.assertTrue(result)
        self.assertNotIn("10.0.0.1", self.ip_filter.whitelist)

    def test_normalize_ip(self):
        """测试IP地址规范化功能"""
        # IPv4地址
        normalized = self.ip_filter._normalize_ip("192.168.1.1")
        self.assertEqual(normalized, "192.168.1.1")

        # 带端口的IPv4地址
        normalized = self.ip_filter._normalize_ip("192.168.1.1:8080")
        self.assertEqual(normalized, "192.168.1.1")

        # 带空格的IP地址
        normalized = self.ip_filter._normalize_ip("  192.168.1.1  ")
        self.assertEqual(normalized, "192.168.1.1")

        # 简单的IPv6地址
        normalized = self.ip_filter._normalize_ip("::1")
        self.assertEqual(normalized, "::1")

        # 无效的IP地址（返回原始值）
        normalized = self.ip_filter._normalize_ip("invalid-ip")
        self.assertEqual(normalized, "invalid-ip")

    def test_check_request(self):
        """测试请求检查功能"""
        # 设置黑名单
        self.ip_filter.set_blacklist(["192.168.1.1"])

        # 创建一个WSGI环境
        environ = {"REMOTE_ADDR": "192.168.1.1"}

        # 检查被拦截的请求
        is_allowed, reason = self.ip_filter.check_request(environ)
        self.assertFalse(is_allowed)
        self.assertEqual(reason, "IP在黑名单中")

        # 使用不在黑名单中的IP
        environ["REMOTE_ADDR"] = "192.168.1.2"
        is_allowed, reason = self.ip_filter.check_request(environ)
        self.assertTrue(is_allowed)
        self.assertIsNone(reason)

        # 测试X-Forwarded-For头
        environ["HTTP_X_FORWARDED_FOR"] = "192.168.1.1, 10.0.0.1"
        is_allowed, reason = self.ip_filter.check_request(environ)
        self.assertFalse(is_allowed)
        self.assertEqual(reason, "IP在黑名单中")


if __name__ == "__main__":
    unittest.main()
