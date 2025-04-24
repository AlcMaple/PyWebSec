"""
IP过滤器模块，提供IP黑白名单功能。
"""

import re
from typing import Dict, List, Optional, Tuple, Any, Union
import ipaddress


class IPFilter:
    """
    过滤器用于基于IP黑白名单进行请求过滤。
    """

    def __init__(self, logger=None):
        """
        初始化IP过滤器。

        Args:
            logger: 可选的日志记录器实例。
        """
        self.logger = logger
        self.blacklist = []  # IP黑名单
        self.whitelist = []  # IP白名单
        self.enable_blacklist = True  # 启用黑名单
        self.enable_whitelist = False  # 默认不启用白名单

    def set_blacklist(self, ips: List[str]) -> None:
        """
        设置IP黑名单。

        Args:
            ips: IP地址列表。
        """
        self.blacklist = [self._normalize_ip(ip) for ip in ips]
        if self.logger:
            self.logger.log_info(f"IP黑名单已更新，共{len(self.blacklist)}个IP")

    def set_whitelist(self, ips: List[str]) -> None:
        """
        设置IP白名单。

        Args:
            ips: IP地址列表。
        """
        self.whitelist = [self._normalize_ip(ip) for ip in ips]
        if self.logger:
            self.logger.log_info(f"IP白名单已更新，共{len(self.whitelist)}个IP")

    def add_to_blacklist(self, ip: str) -> None:
        """
        将IP地址添加到黑名单。

        Args:
            ip: 要添加的IP地址。
        """
        normalized_ip = self._normalize_ip(ip)
        if normalized_ip not in self.blacklist:
            self.blacklist.append(normalized_ip)
            if self.logger:
                self.logger.log_info(f"IP {ip} 已添加到黑名单")

    def add_to_whitelist(self, ip: str) -> None:
        """
        将IP地址添加到白名单。

        Args:
            ip: 要添加的IP地址。
        """
        normalized_ip = self._normalize_ip(ip)
        if normalized_ip not in self.whitelist:
            self.whitelist.append(normalized_ip)
            if self.logger:
                self.logger.log_info(f"IP {ip} 已添加到白名单")

    def remove_from_blacklist(self, ip: str) -> bool:
        """
        从黑名单中移除IP地址。

        Args:
            ip: 要移除的IP地址。

        Returns:
            如果IP在黑名单中并已移除则返回True，否则返回False。
        """
        normalized_ip = self._normalize_ip(ip)
        if normalized_ip in self.blacklist:
            self.blacklist.remove(normalized_ip)
            if self.logger:
                self.logger.log_info(f"IP {ip} 已从黑名单中移除")
            return True
        return False

    def remove_from_whitelist(self, ip: str) -> bool:
        """
        从白名单中移除IP地址。

        Args:
            ip: 要移除的IP地址。

        Returns:
            如果IP在白名单中并已移除则返回True，否则返回False。
        """
        normalized_ip = self._normalize_ip(ip)
        if normalized_ip in self.whitelist:
            self.whitelist.remove(normalized_ip)
            if self.logger:
                self.logger.log_info(f"IP {ip} 已从白名单中移除")
            return True
        return False

    def _normalize_ip(self, ip: str) -> str:
        """
        规范化IP地址格式。

        Args:
            ip: 输入的IP地址。

        Returns:
            规范化后的IP地址。
        """
        # 移除空格
        ip = ip.strip()

        # 如果是CIDR格式，保留原样
        if "/" in ip:
            return ip

        # 处理IPv4格式的IP:port
        if ":" in ip and not ip.startswith("[") and ip.count(":") == 1:
            ip = ip.split(":", 1)[0]

        # 尝试解析IP地址以确保有效
        try:
            # 处理IPv4
            if "." in ip:
                parsed_ip = ipaddress.IPv4Address(ip)
                return str(parsed_ip)
            # 处理IPv6
            else:
                parsed_ip = ipaddress.IPv6Address(ip)
                return str(parsed_ip)
        except ValueError:
            # 如果无法解析为IP地址，返回原始值
            if self.logger:
                self.logger.log_error(f"无效的IP地址格式: {ip}")
            return ip

    def _match_ip(self, ip: str, ip_list: List[str]) -> bool:
        """
        检查IP地址是否匹配列表中的任何IP/CIDR。

        Args:
            ip: 要检查的IP地址。
            ip_list: IP地址或CIDR列表。

        Returns:
            如果匹配则返回True，否则返回False。
        """
        normalized_ip = self._normalize_ip(ip)

        try:
            # 转换为IP地址对象（只针对单个IP，不针对CIDR）
            if "/" not in normalized_ip:
                if "." in normalized_ip:  # IPv4
                    check_ip = ipaddress.IPv4Address(normalized_ip)
                else:  # IPv6
                    check_ip = ipaddress.IPv6Address(normalized_ip)

                # 检查每个列表项
                for list_ip in ip_list:
                    if "/" in list_ip:  # 这是一个CIDR
                        try:
                            network = ipaddress.ip_network(list_ip, strict=False)
                            if check_ip in network:
                                return True
                        except ValueError:
                            # 无法解析为网络，跳过
                            continue
                    else:  # 单个IP地址
                        try:
                            if "." in list_ip:  # IPv4
                                list_ip_obj = ipaddress.IPv4Address(list_ip)
                            else:  # IPv6
                                list_ip_obj = ipaddress.IPv6Address(list_ip)

                            if check_ip == list_ip_obj:
                                return True
                        except ValueError:
                            # 如果无法解析为IP，进行字符串比较
                            if normalized_ip == list_ip:
                                return True
            else:
                # 处理CIDR格式的IP
                for list_ip in ip_list:
                    if normalized_ip == list_ip:
                        return True
        except ValueError:
            # 如果无法解析为IP地址，进行字符串比较
            return normalized_ip in ip_list

        return False

    def check_ip(self, ip: str) -> Tuple[bool, Optional[str]]:
        """
        检查IP地址是否被允许访问。

        Args:
            ip: 要检查的IP地址。

        Returns:
            一个元组(is_allowed, reason)。如果IP被允许访问，is_allowed为True，
            否则为False，并在reason中提供被阻止的原因。
        """
        # 白名单优先级高于黑名单
        if self.enable_whitelist and self.whitelist:
            if self._match_ip(ip, self.whitelist):
                return True, None
            else:
                reason = "IP不在白名单中"
                if self.logger:
                    self.logger.log_blocked("白名单IP过滤", {"ip": ip, "原因": reason})
                return False, reason

        # 如果没有启用白名单或白名单为空，则检查黑名单
        if self.enable_blacklist and self.blacklist:
            if self._match_ip(ip, self.blacklist):
                reason = "IP在黑名单中"
                if self.logger:
                    self.logger.log_blocked("黑名单IP过滤", {"ip": ip, "原因": reason})
                return False, reason

        # 如果没有匹配任何规则，则允许访问
        return True, None

    def check_request(self, environ: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
        """
        检查请求的源IP地址是否被允许访问。

        Args:
            environ: WSGI环境字典。

        Returns:
            一个元组(is_allowed, reason)。如果请求被允许，is_allowed为True，
            否则为False，并在reason中提供被阻止的原因。
        """
        # 尝试从HTTP头中获取客户端IP地址
        ip = environ.get("REMOTE_ADDR", "")

        # 处理X-Forwarded-For头（如果在代理服务器后面）
        # 注意：使用X-Forwarded-For可能存在安全风险，应确保该头是由受信任的代理设置的
        forwarded_for = environ.get("HTTP_X_FORWARDED_FOR")
        if forwarded_for:
            # 使用最左边的IP（通常是原始客户端IP）
            ip = forwarded_for.split(",")[0].strip()

        # 检查IP
        return self.check_ip(ip)
