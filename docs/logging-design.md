# 日志设计方案

## 核心目标

**一句话**：知道谁、什么时候、在哪个域名登录了。

## 日志格式规范

**Logrus 自动添加 time**：所有使用 Logrus 的日志都会自动添加 `time` 字段，`key=value` 之间用空格分隔

```text
time="2026-01-24T08:54:37+08:00" level=info msg="User logged in" host=www.app.com user=user@example.com source_ip=192.168.1.100
```

**说明**：

- `time` - Logrus 自动添加（`FullTimestamp: true`）
- `level` - 日志级别（info/debug/error）
- `msg` - 日志消息
- 其他字段 - 业务字段（host/user/source_ip 等）

## 启动日志

### 横幅（纯文本，无 Logrus 格式）

```text
============================================================
Beagle Gateway Forward Auth
------------------------------------------------------------
Version:    v2.3.1
Git Commit: 6deff3d
Build Date: 2026-01-23_16:48:15
Go Version: go1.25.6
============================================================
```

### 配置日志（Logrus 格式，自动添加 time）

```text
time="2026-01-24T00:00:00+08:00" level=info msg="Configuration loaded" provider=oidc auth_host=auth.example.com cookie_name=_auth_cookie log_level=info
time="2026-01-24T00:00:01+08:00" level=info msg="Listening on :4181"
```

## 运行日志

### 登录成功

```text
time="2026-01-24T08:54:37+08:00" level=info msg="User logged in" host=www.app.com user=user@example.com source_ip=192.168.1.100
```

**说明**：

- `time` - 几点几分（Logrus 自动添加）
- `host` - 哪个域名
- `user` - 哪个用户（email/phone/username）
- `source_ip` - 从哪里来的

### 跨域访问（已登录）

```text
time="2026-01-24T08:55:12+08:00" level=info msg="User accessed from new domain" host=www.bpp.com user=user@example.com source_ip=192.168.1.100
```

### 登出

```text
time="2026-01-24T09:30:00+08:00" level=info msg="User logged out" host=www.app.com
```

## 日志级别

### INFO（默认）

- 启动配置
- 登录成功
- 跨域访问
- 登出

### DEBUG（排查问题时）

- ID Token 包含哪些字段
- 使用了哪个字段作为用户标识
- Cookie 值、Session ID
- 认证流程详细信息

### ERROR

- 登录失败
- OAuth 错误

## 配置

### 生产环境

```yaml
- name: LOG_LEVEL
  value: "info" # 启动信息 + 登录日志
```

### 排查问题

```yaml
- name: LOG_LEVEL
  value: "debug" # 详细调试信息
```

## 总结

**横幅**：纯文本，无 Logrus 格式

**所有其他日志**：Logrus 自动添加 `time`，`key=value` 空格分隔

**INFO 日志**：时间、域名、用户、IP

**DEBUG 日志**：认证流程详细信息

**统一了。**
