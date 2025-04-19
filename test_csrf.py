from pyweb_sec.filters.csrf import CSRFFilter
from pyweb_sec.utils.config import ConfigManager
from pyweb_sec.utils.logging import SecurityLogger
import time

# 设置
config = ConfigManager()
logger = SecurityLogger(config)
csrf_filter = CSRFFilter(logger)

# 测试生成和验证令牌
print("=== CSRF令牌生成和验证测试 ===")
session_id = "test_session_123"
token = csrf_filter.generate_token(session_id)
print(f"生成的令牌: {token}")

# 验证有效令牌
is_valid = csrf_filter.validate_token(session_id, token)
print(f"有效令牌验证: {'通过' if is_valid else '失败'}")

# 验证无效令牌
invalid_token = "invalid_token_xyz"
is_valid = csrf_filter.validate_token(session_id, invalid_token)
print(f"无效令牌验证: {'通过' if is_valid else '失败'}")

# 验证过期令牌 (模拟)
# 创建一个自定义的短期令牌过滤器
short_expiry_filter = CSRFFilter(logger, token_expiry=1)  # 1秒过期
short_token = short_expiry_filter.generate_token(session_id)
print(f"短期令牌: {short_token}")
print("等待令牌过期 (2秒)...")
time.sleep(2)
is_valid = short_expiry_filter.validate_token(session_id, short_token)
print(f"过期令牌验证: {'通过' if is_valid else '失败'}")

# 测试请求检查
print("\n=== 请求检查测试 ===")

# GET请求 (不检查CSRF)
get_request = {
    "query": "search term"
}
is_valid, reason = csrf_filter.check_request("GET", get_request, session_id)
print(f"GET请求: {'通过' if is_valid else '失败'}")

# POST请求没有令牌
post_without_token = {
    "username": "test",
    "password": "password123"
}
is_valid, reason = csrf_filter.check_request("POST", post_without_token, session_id)
print(f"没有令牌的POST请求: {'通过' if is_valid else '失败'}")
if not is_valid:
    print(f"  原因: {reason}")

# POST请求有无效令牌
post_with_invalid_token = {
    "username": "test",
    "password": "password123",
    "_csrf_token": "invalid_token"
}
is_valid, reason = csrf_filter.check_request("POST", post_with_invalid_token, session_id)
print(f"有无效令牌的POST请求: {'通过' if is_valid else '失败'}")
if not is_valid:
    print(f"  原因: {reason}")

# POST请求有有效令牌
valid_token = csrf_filter.generate_token(session_id)
post_with_valid_token = {
    "username": "test",
    "password": "password123",
    "_csrf_token": valid_token
}
is_valid, reason = csrf_filter.check_request("POST", post_with_valid_token, session_id)
print(f"有有效令牌的POST请求: {'通过' if is_valid else '失败'}")

# 令牌使用不同会话ID
other_session_id = "other_session_456"
other_token = csrf_filter.generate_token(other_session_id)
post_with_other_token = {
    "username": "test",
    "password": "password123",
    "_csrf_token": other_token
}
is_valid, reason = csrf_filter.check_request("POST", post_with_other_token, session_id)
print(f"使用其他会话令牌的POST请求: {'通过' if is_valid else '失败'}")
if not is_valid:
    print(f"  原因: {reason}")