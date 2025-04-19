from pyweb_sec.filters.sql_injection import SQLInjectionFilter
from pyweb_sec.utils.config import ConfigManager
from pyweb_sec.utils.logging import SecurityLogger

# 设置
config = ConfigManager()
logger = SecurityLogger(config)
sql_filter = SQLInjectionFilter(logger)

# 测试用例
test_cases = [
    # 正常参数
    ("username", "john_doe", False),
    ("search", "product name", False),
    ("comment", "This is a normal comment!", False),
    
    # SQL注入尝试
    ("username", "admin' OR 1=1--", True),
    ("search", "product'; DROP TABLE users;--", True),
    ("id", "1; SELECT * FROM users", True),
    ("query", "UNION SELECT username, password FROM users", True),
    ("text", "anything' OR 'x'='x", True),
    ("param", "1 UNION ALL SELECT null, null, null", True),
    ("data", "; SLEEP(5)", True)
]

# 运行测试
print("=== SQL注入过滤器测试 ===")
for param_name, param_value, expected_result in test_cases:
    is_injection, pattern = sql_filter.check_parameter(param_name, param_value)
    result = "检测到SQL注入" if is_injection else "正常参数"
    status = "✓" if is_injection == expected_result else "✗"
    
    print(f"{status} 参数: '{param_name}', 值: '{param_value}' => {result}")
    if is_injection:
        print(f"   检测详情: {pattern}")

# 测试请求检查
print("\n=== 请求检查测试 ===")
clean_request = {
    "username": "john",
    "password": "secure123",
    "remember": "true"
}

malicious_request = {
    "username": "admin' OR 1=1--",
    "password": "anything",
    "remember": "true"
}

is_injection, reason = sql_filter.check_request(clean_request)
print(f"正常请求: {'被拦截' if is_injection else '通过'}")

is_injection, reason = sql_filter.check_request(malicious_request)
print(f"恶意请求: {'被拦截' if is_injection else '通过'}")
if is_injection:
    print(f"拦截原因: {reason}")