"""
Core security middleware implementation for PyWebSec.
"""

from typing import Any, Callable, Dict, List, Optional, Tuple, Union
import importlib
from .utils.config import ConfigManager
from .utils.logging import SecurityLogger


class SecurityMiddleware:
    """
    WSGI middleware that provides security features for web applications.

    This middleware can be used with any WSGI-compatible web framework
    including Flask and Django.
    """

    def __init__(self, app: Callable, config_path: Optional[str] = None):
        """
        Initialize the security middleware.

        Args:
            app: The WSGI application to wrap.
            config_path: Optional path to a configuration file.
        """
        self.app = app
        self.config = ConfigManager(config_path)
        self.logger = SecurityLogger(self.config)
        self.filters = self._load_filters()

    def _load_filters(self) -> Dict[str, Any]:
        """
        Load enabled security filters based on configuration.

        Returns:
            A dictionary of filter instances.
        """
        filters = {}
        enabled_filters = self.config.get("enabled_filters", [])

        for filter_name in enabled_filters:
            try:
                # Dynamically import filter modules
                if filter_name == "xss":
                    from .filters.xss import XSSFilter

                    filters["xss"] = XSSFilter(self.logger)
                elif filter_name == "sql_injection":
                    from .filters.sql_injection import SQLInjectionFilter

                    filters["sql_injection"] = SQLInjectionFilter(self.logger)
                elif filter_name == "csrf":
                    from .filters.csrf import CSRFFilter

                    filters["csrf"] = CSRFFilter(self.logger)
                elif filter_name == "ip_filter":
                    from .filters.ip_filter import IPFilter

                    ip_filter = IPFilter(self.logger)

                    # 配置IP黑名单
                    blacklist = self.config.get("ip_filter.blacklist", [])
                    if blacklist:
                        ip_filter.set_blacklist(blacklist)

                    # 配置IP白名单
                    whitelist = self.config.get("ip_filter.whitelist", [])
                    if whitelist:
                        ip_filter.set_whitelist(whitelist)
                        ip_filter.enable_whitelist = self.config.get(
                            "ip_filter.enable_whitelist", False
                        )

                    filters["ip_filter"] = ip_filter
                # 可在此处添加其他过滤器
                else:
                    self.logger.log_error(f"未知过滤器: {filter_name}")
            except Exception as e:
                self.logger.log_error(f"加载过滤器 {filter_name} 时出错: {str(e)}")

        return filters

    def _parse_request_data(self, environ: Dict[str, Any]) -> Dict[str, Any]:
        """
        Parse request data from the WSGI environ.

        Args:
            environ: WSGI environment dictionary.

        Returns:
            Parsed request data.
        """
        request_data = {}

        # 获取请求方法
        request_data["method"] = environ.get("REQUEST_METHOD", "")

        # 获取会话ID (框架通常将其存储在cookie中)
        session_id = None
        cookies = environ.get("HTTP_COOKIE", "")
        for cookie in cookies.split(";"):
            if "=" in cookie:
                name, value = cookie.strip().split("=", 1)
                if name.lower() in ("sessionid", "session_id"):
                    session_id = value
        request_data["session_id"] = session_id or "default_session"

        # 解析查询参数
        query_string = environ.get("QUERY_STRING", "")
        query_params = {}
        for param in query_string.split("&"):
            if "=" in param and param:
                key, value = param.split("=", 1)
                query_params[key] = value
        request_data["query_params"] = query_params

        # 解析表单数据 (对于POST/PUT请求)
        if request_data["method"] in ("POST", "PUT"):
            content_length = int(environ.get("CONTENT_LENGTH", 0) or 0)
            if content_length > 0:
                request_body = environ["wsgi.input"].read(content_length)
                form_data = {}
                # 简单的表单数据解析 (可扩展为JSON, multipart等)
                for param in request_body.decode("utf-8").split("&"):
                    if "=" in param and param:
                        key, value = param.split("=", 1)
                        form_data[key] = value
                request_data["form_data"] = form_data
            else:
                request_data["form_data"] = {}

        # 合并查询参数和表单参数以便于检查
        request_data["all_params"] = {**query_params}
        if request_data.get("form_data"):
            request_data["all_params"].update(request_data["form_data"])

        return request_data

    def __call__(self, environ: Dict[str, Any], start_response: Callable) -> Any:
        """
        WSGI entry point.

        Args:
            environ: WSGI environment dictionary.
            start_response: WSGI start_response function.

        Returns:
            The response from the wrapped application.
        """
        # IP过滤（应在其他检查之前）
        if "ip_filter" in self.filters:
            is_allowed, reason = self.filters["ip_filter"].check_request(environ)
            if not is_allowed:
                status = "403 Forbidden"
                response_headers = [("Content-type", "text/plain")]
                start_response(status, response_headers)
                return [f"IP访问被拒绝: {reason}".encode("utf-8")]

        # 解析请求数据
        request_data = self._parse_request_data(environ)

        # 安全检查
        blocked = False
        block_reason = None

        # 检查SQL注入
        if "sql_injection" in self.filters:
            is_injection, reason = self.filters["sql_injection"].check_request(
                request_data["all_params"]
            )
            if is_injection:
                blocked = True
                block_reason = reason
                self.logger.log_blocked(
                    "SQL注入",
                    {
                        "原因": reason,
                        "方法": request_data["method"],
                        "参数": request_data["all_params"],
                    },
                )

        # 检查XSS
        if not blocked and "xss" in self.filters:
            is_xss, reason = self.filters["xss"].check_request(
                request_data["all_params"]
            )
            if is_xss:
                blocked = True
                block_reason = reason
                self.logger.log_blocked(
                    "XSS",
                    {
                        "原因": reason,
                        "方法": request_data["method"],
                        "参数": request_data["all_params"],
                    },
                )

        # 检查CSRF (对于状态更改请求)
        if (
            not blocked
            and "csrf" in self.filters
            and request_data["method"] not in ("GET", "HEAD", "OPTIONS")
        ):
            is_valid, reason = self.filters["csrf"].check_request(
                request_data["method"],
                request_data["all_params"],
                request_data["session_id"],
            )
            if not is_valid:
                blocked = True
                block_reason = reason
                self.logger.log_blocked(
                    "CSRF",
                    {
                        "原因": reason,
                        "方法": request_data["method"],
                        "会话ID": request_data["session_id"],
                    },
                )

        # 如果被拦截，返回403 Forbidden
        if blocked:
            status = "403 Forbidden"
            response_headers = [("Content-type", "text/plain")]
            start_response(status, response_headers)
            return [f"安全违规: {block_reason}".encode("utf-8")]

        # 否则，传递给包装的应用程序
        return self.app(environ, start_response)
