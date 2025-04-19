from pyweb_sec.utils.config import ConfigManager

# 测试默认配置
print("=== 测试默认配置 ===")
config = ConfigManager()
print(f"启用的过滤器: {config.get('enabled_filters')}")
print(f"每分钟请求限制: {config.get('rate_limit.requests_per_minute')}")
print(f"日志级别: {config.get('logging.level')}")

# 测试自定义配置
print("\n=== 测试自定义配置 ===")
config = ConfigManager("test_config.yaml")
print(f"启用的过滤器: {config.get('enabled_filters')}")
print(f"每分钟请求限制: {config.get('rate_limit.requests_per_minute')}")
print(f"日志级别: {config.get('logging.level')}")
print(f"日志文件: {config.get('logging.file')}")

# 测试配置键不存在的情况
print("\n=== 测试键不存在 ===")
print(f"不存在的键: {config.get('not_exist', '默认值')}")