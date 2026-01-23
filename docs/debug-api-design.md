# 调试 API 设计

## 目标

提供调试端点，查看当前用户的认证信息和 OIDC Provider 返回的完整数据结构。

## 端点

### `/_oauth/debug`

**用途**：返回当前用户的 Session 信息和 ID Token Claims

**访问方式**：浏览器直接访问（需要已登录）

**响应格式**：JSON

## 响应结构

### 已认证

```json
{
  "authenticated": true,
  "session_id": "xxx",
  "email": "user@example.com",
  "created_at": "2026-01-24T00:54:37+08:00",
  "expires_at": "2026-01-24T12:54:37+08:00",
  "claims": {
    "sub": "user123",
    "email": "user@example.com",
    "email_verified": true,
    "phone_number": "+86 138 0000 0000",
    "preferred_username": "zhangsan",
    "name": "张三",
    "picture": "https://example.com/avatar.jpg"
  }
}
```

**字段说明**：

- `authenticated` - 是否已认证
- `session_id` - Session ID
- `email` - 当前使用的用户标识
- `created_at` - Session 创建时间
- `expires_at` - Session 过期时间
- `claims` - OIDC Provider 返回的所有 ID Token Claims

### 未认证

```json
{
  "error": "Not authenticated",
  "message": "No session cookie found"
}
```

### Session 不存在

```json
{
  "error": "Session not found",
  "session_id": "xxx"
}
```

## 使用场景

### 1. 排查用户标识为空问题

当日志显示 `user=` 为空时：

1. 访问 `/_oauth/debug`
2. 查看 `claims` 字段
3. 确认 OIDC Provider 返回了哪些字段
4. 决定使用哪个字段作为用户标识

### 2. 验证 Scope 配置

修改 `PROVIDERS_OIDC_SCOPE` 后：

1. 清除 Cookie 重新登录
2. 访问 `/_oauth/debug`
3. 查看 `claims` 是否包含新的字段

### 3. 调试跨域认证

在不同域名下访问 `/_oauth/debug`：

- `https://auth.example.com/_oauth/debug`
- `https://www.app.com/_oauth/debug`

确认 Session 是否正确共享。

## 常见 OIDC Claims

### 用户标识

- `sub` - 用户唯一标识（必有）
- `email` - 邮箱地址
- `phone_number` - 电话号码
- `preferred_username` - 首选用户名

### 用户信息

- `name` - 显示名称
- `given_name` - 名
- `family_name` - 姓
- `nickname` - 昵称
- `picture` - 头像 URL
- `profile` - 个人资料页面 URL

### 验证状态

- `email_verified` - 邮箱是否验证
- `phone_number_verified` - 电话是否验证

### Token 信息

- `iss` - Issuer（发行者）
- `aud` - Audience（受众）
- `exp` - Expiration Time（过期时间）
- `iat` - Issued At（签发时间）

## Scope 配置

### 标准 Scopes

- `openid` - 必需，启用 OIDC，返回 `sub`
- `email` - 返回 `email`, `email_verified`
- `profile` - 返回 `name`, `preferred_username`, `picture` 等
- `phone` - 返回 `phone_number`, `phone_number_verified`
- `address` - 返回 `address`

### 配置示例

```yaml
- name: PROVIDERS_OIDC_SCOPE
  value: "openid,email,profile,phone"
```

## 用户标识提取策略

根据 `claims` 内容，按优先级提取：

1. `email` - 优先使用邮箱
2. `phone_number` - 其次使用电话
3. `preferred_username` - 再次使用用户名
4. `sub` - 最后使用唯一标识

## 安全考虑

### 访问控制

- 端点需要已登录才能访问
- 只返回当前用户自己的信息
- 不暴露其他用户的数据

### 生产环境

- 可以通过配置禁用调试端点
- 或者限制只在特定环境启用

## 总结

**端点**：`/_oauth/debug`

**用途**：查看当前用户的 Session 和 ID Token Claims

**响应**：JSON 格式，包含完整的 claims 数据

**场景**：排查用户标识问题、验证 Scope 配置、调试跨域认证
