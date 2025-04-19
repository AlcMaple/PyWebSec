from pyweb_sec.utils.config import ConfigManager
from pyweb_sec.utils.logging import SecurityLogger

# 创建配置
config = ConfigManager()

# 创建日志记录器
logger = SecurityLogger(config)

# 测试日志功能
print("=== 测试日志功能 ===")
logger.log_info("测试信息日志")
logger.log_attack("SQL注入", "检测到可疑SQL语句", {"ip": "127.0.0.1", "url": "/login"})
logger.log_blocked("IP黑名单", {"ip": "192.168.1.1", "url": "/admin"})
logger.log_error("测试错误日志", {"module": "测试模块"})

print("\n日志应该已输出到控制台，请检查上面的输出。")