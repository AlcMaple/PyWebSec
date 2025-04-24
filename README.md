# PyWebSec - Python 网站安全防护系统

PyWebSec 是一个轻量级的网站安全防护系统，设计用于加强各种技术栈网站应用的安全性，防御常见的网络攻击。系统可集成到任何基于 WSGI 的 Python Web 框架（如 Flask、Django）中，同时也支持 Vue 开发的前端应用以及传统的 HTML+CSS+JS 三件套开发的网站，提供全面的安全防护能力。

## 目录

- [项目介绍](#项目介绍)
- [功能特性](#功能特性)
- [项目结构](#项目结构)
- [安装方法](#安装方法)
- [使用方法](#使用方法)
- [项目进度追踪](#项目进度追踪)
    - [功能开发](#功能开发)
    - [文档和示例](#文档和示例)
    - [测试和验证](#测试和验证)
- [贡献指南](#贡献指南)

## 项目介绍

PyWebSec 旨在提供一套全面的网站安全防护系统，适用于多种技术栈开发的网站，包括 Python Web 应用（Flask、Django 等）、Vue 开发的单页应用以及传统的 HTML+CSS+JS 三件套网站。该系统实现了多种安全过滤器，用于防御 SQL 注入、XSS（跨站脚本）和 CSRF（跨站请求伪造）等常见攻击。

## 项目结构

```
PyWebSec/
├── pyweb_sec/               # 核心模块
│   ├── __init__.py          # 模块初始化
│   ├── middleware.py        # 核心安全中间件
│   ├── proxy.py             # 反向代理组件
│   ├── filters/             # 安全过滤器模块
│   │   ├── __init__.py
│   │   ├── csrf.py          # CSRF 防护
│   │   ├── sql_injection.py # SQL 注入防护
│   │   ├── xss.py           # XSS 防护
│   │   ├── ip_filter.py     # IP 过滤
│   │   └── rate_limit.py    # 速率限制
│   └── utils/               # 通用工具
│       ├── __init__.py
│       ├── config.py        # 配置管理
│       └── logging.py       # 安全日志
│
├── tests/                   # 测试模块
│   ├── __init__.py
│   ├── test_filters/        # 过滤器测试
│   │   ├── __init__.py
│   │   ├── test_sql_injection.py
│   │   └── test_xss.py
│   └── test_middleware.py   # 中间件测试
│
├── examples/                # 集成样例
│   ├── django_example.py    # Django 集成
│   ├── flask_example.py     # Flask 集成
│   └── vue_integration.md   # Vue 集成指南
│
├── test_config.py           # 配置模块测试
├── test_logging.py          # 日志模块测试
├── test_csrf.py             # CSRF 模块测试
├── test_sql_injection.py    # SQL 注入模块测试
├── test_xss.py              # XSS 模块测试
├── setup.py                 # 安装配置
├── requirements.txt         # 依赖要求
├── test_config.yaml         # 测试配置文件
└── README.md                # 项目说明
```

## 安装方法

```bash
git clone https://github.com/AlcMaple/PyWebSec.git
cd PyWebSec
pip install -e .
```

## 使用方法

待项目完成基本功能后补充。

## 🚀 项目进度追踪

### 📋 功能开发
| 状态 | 功能 | 备注 |
|:---:|---|---|
| ✅ | 项目基础结构 | 基本文件结构和模块划分 |
| ✅ | 配置管理模块 | 支持 YAML/JSON 配置 |
| ✅ | 日志记录模块 | 安全事件和攻击记录 |
| ✅ | SQL 注入防护 | 检测和阻止 SQL 注入尝试 |
| ✅ | XSS 防护 | 检测和净化跨站脚本 |
| ✅ | CSRF 防护 | token生成和验证 |
| ✅ | IP 过滤 | 黑白名单机制 |
| ⬜ | 请求速率限制 | 防止暴力攻击 |
| ✅ | 安全中间件完善 | 完成所有过滤器的集成 |
| ⬜ | 前端安全组件 | 用于 Vue 和 HTML+JS 的安全库 |
| ⬜ | 文件上传防护 | 安全的文件上传处理 |

### 📋 文档和示例
| 状态 | 任务 | 备注 |
|:---:|---|---|
| ✅ | README.md | 基本项目介绍和进度跟踪 |
| ⬜ | 安装文档 | 详细的安装说明 |
| ⬜ | API 文档 | 函数和类的详细说明 |
| ⬜ | 配置参考 | 配置选项详解 |
| ⬜ | Django 集成示例 | Django 框架集成指南 |
| ⬜ | Flask 集成示例 | Flask 框架集成指南 |
| ⬜ | Vue 集成指南 | Vue 项目集成方法 |
| ⬜ | HTML+CSS+JS 集成指南 | 传统三件套网站集成方法 |

### 📋 测试和验证
| 状态 | 任务 | 备注 |
|:---:|---|---|
| ✅ | 基础配置测试 | 配置加载和管理测试 |
| ✅ | 日志模块测试 | 日志记录功能测试 |
| ✅ | SQL 注入过滤器测试 | SQL 注入检测测试 |
| ✅ | XSS 过滤器测试 | XSS 检测和净化测试 |
| ✅ | CSRF 过滤器测试 | token生成和验证测试 |
| ✅ | 中间件单元测试 | 安全中间件核心功能测试 |
| ✅ | IP过滤器测试 | IP黑白名单功能测试 |
| ⬜ | 集成测试 | 与框架的集成测试 |
| ⬜ | 性能测试 | 中间件性能影响测试 |
| ⬜ | 安全测试 | OWASP Top 10 漏洞测试 |

## 贡献指南

欢迎提交 Pull Request 或提出 Issue。贡献前请先阅读贡献指南（计划中）。