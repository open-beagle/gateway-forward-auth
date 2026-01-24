# 跨域 Cookie 认证设计方案

## 核心设计：跨域 Cookie 与内存 Session

### 设计原理

由于浏览器的同源策略，不同域名的 Cookie 无法共享。本设计通过**统一 cookie_id** 的方式，让所有域名最终使用相同的 cookie_id，指向同一个 Session。

**核心思路**：

1. **首次登录**：`www.app.com` 和 `auth.example.com` 使用**相同的 cookie_id**（如 1234）
2. **跨域访问**：`www.bpp.com` 首次访问时生成临时 cookie_id（如 1235）
3. **检测已登录**：跳转到 `auth.example.com` 时，发现 cookie_id 1234 已登录
4. **统一 cookie_id**：将 `www.bpp.com` 的 cookie_id 从 1235 改为 1234
5. **最终状态**：所有域名的 cookie_id 都是 1234，指向同一个 Session

### 数据结构设计

**Session 存储**：

- key: cookie_id（同时也是 session_id）
- value: Session 对象（包含 email、创建时间、过期时间）

**临时 Cookie ID 映射**：

- key: 临时 cookie_id（如 1235）
- value: 主 cookie_id（如 1234）

**关键点**：

- 不需要 `cookie_id -> session_id` 的映射
- cookie_id 直接作为 session_id
- 所有域名最终使用相同的 cookie_id

### 工作流程

#### 首次登录（www.app.com）

1. 用户访问 `www.app.com`
2. Forward Auth 生成 cookie_id: 1234
3. 在 `www.app.com` 域名下设置 Cookie: `${COOKIE_NAME}=1234`
4. 重定向到 `auth.example.com` 进行 OAuth 登录
5. 在 `auth.example.com` 域名下也设置 Cookie: `${COOKIE_NAME}=1234`（相同的值）
6. 用户完成 OAuth 登录
7. 在内存中创建 Session: `sessions["1234"]`
8. 跳转回 `www.app.com`，登录完成

**结果**：

- `www.app.com` 的 Cookie：`${COOKIE_NAME}=1234`
- `auth.example.com` 的 Cookie：`${COOKIE_NAME}=1234`
- 内存 Session：`sessions["1234"]`

#### 跨域访问（www.bpp.com）

1. 用户访问 `www.bpp.com`（首次）
2. Traefik 透传请求给 Forward Auth，`www.bpp.com` 没有 Cookie
3. Forward Auth 生成临时 cookie_id: 1235
4. 在 `www.bpp.com` 域名下设置 Cookie: `${COOKIE_NAME}=1235`
5. 重定向到 `auth.example.com`
6. 浏览器跳转到 `auth.example.com`，自动带上 `auth.example.com` 的 Cookie: 1234
7. `auth.example.com` 检查 Session: `sessions["1234"]` 存在且未过期，用户已登录
8. 记录临时映射：`1235 -> 1234`
9. 跳转回 `www.bpp.com`
10. 浏览器访问 `www.bpp.com`，带上 Cookie: 1235
11. Forward Auth 检查：1235 是临时 ID，对应主 ID 是 1234
12. 返回 307 重定向，Set-Cookie 统一为 1234
13. 浏览器收到 307，设置新 Cookie 并重新请求
14. 浏览器再次访问 `www.bpp.com`，带上新 Cookie: 1234
15. Forward Auth 验证：`sessions["1234"]` 存在且未过期，返回 200
16. Traefik 放行请求到后端服务

**结果**：

- `www.app.com` 的 Cookie：`${COOKIE_NAME}=1234`
- `www.bpp.com` 的 Cookie：`${COOKIE_NAME}=1234`（已统一）
- `auth.example.com` 的 Cookie：`${COOKIE_NAME}=1234`
- 内存 Session：`sessions["1234"]`（唯一）

#### 验证请求

1. 用户访问 `www.app.com/api/resource`
2. 浏览器发送请求，带上 Cookie: `${COOKIE_NAME}=1234`
3. Traefik 透传给 Forward Auth
4. Forward Auth 读取 Cookie 值：1234
5. 查询内存 Session: `sessions["1234"]`
6. Session 存在且未过期，返回 200

### 设计优势

1. **最终一致性**：所有域名最终使用相同的 cookie_id，只有一个 Session 对象
2. **无需复杂映射**：cookie_id 直接作为 session_id，只需临时维护 `temp_cookie_id -> main_cookie_id` 的映射
3. **自动统一**：跨域访问时自动检测已登录状态，自动将临时 cookie_id 替换为主 cookie_id
4. **符合浏览器安全策略**：每个域名独立设置 Cookie，通过 Forward Auth 机制实现跨域统一
5. **用户体验好**：跨域访问无需重新登录，自动完成 cookie_id 统一，用户无感知

### 配置要点

**Cookie 名称统一**：

- 所有域名使用统一的 Cookie 名称（如 `_beagle_auth`）
- 通过环境变量 `COOKIE_NAME` 配置

**Cookie Domain 设置**：

- **使用精确的请求域名**，不使用顶级域名
- 例如：`www.app.com` 设置 Domain 为 `www.app.com`
- 例如：`auth.example.com` 设置 Domain 为 `auth.example.com`
- 从 `X-Forwarded-Host` 头获取原始请求域名
- **优势**：避免多个 Forward Auth 实例的 Cookie 冲突，支持真正的跨域单点登录

**Session 持久化**：

- 建议使用 Redis 持久化，避免 Pod 重启导致 Session 丢失
- Session 存储：`session:{cookie_id} -> {email, created_at, expires_at}`
- 临时映射存储：`temp:{temp_cookie_id} -> {main_cookie_id}`（短期存储，如 5 分钟）

### 关键点总结

1. **首次登录**：`www.app.com` 和 `auth.example.com` 使用相同的 cookie_id（如 1234）
2. **跨域访问**：先生成临时 cookie_id（如 1235），检测到已登录后统一为主 cookie_id（1234）
3. **最终状态**：所有域名的 cookie_id 都是 1234，指向唯一的 Session
4. **数据结构简单**：cookie_id 直接作为 session_id，无需复杂映射
5. **自动统一**：Forward Auth 自动检测并统一 cookie_id，用户无感知
6. **统一认证流程**：不使用 CSRF cookie，统一使用 session_id 作为 CSRF token
7. **Cookie 名称统一**：所有域名使用 `COOKIE_NAME` 环境变量配置的统一名称

## 前端 Hash 路由丢失的解决方案

### 问题说明

由于 HTTP 协议的限制，URL 的 hash 部分（`#` 后面的内容）永远不会发送到服务器。这导致用户访问带 hash 的 URL 时，认证后会丢失 hash 路由。

**示例**：

- 用户访问：`https://www.app.com/#/resource/detail/123?tab=config`
- 服务器只能获取：`https://www.app.com/`
- 认证后跳转回：`https://www.app.com/`（hash 丢失）

### 推荐方案：改用 History 模式

**将前端路由从 Hash 模式改为 History 模式**：

- Hash 模式：`https://www.app.com/#/resource/detail/123`
- History 模式：`https://www.app.com/resource/detail/123`

**优势**：

- History 模式下，完整的路径会发送到服务器，认证后可以正确跳转回原始 URL
- 无需前端 JS 额外处理，认证流程自动保留完整路径

**配置要求**：

需要配置服务器（Traefik/Nginx）支持 History 模式，将所有前端路由都返回 `index.html`。

### 为什么 JS 保存方案无效

虽然理论上可以通过前端 JS 在 `sessionStorage` 中保存 hash，但在单点登录场景下**此方案无效**：

**原因**：单点登录的重定向发生在前端 JS 执行之前。

**流程**：

1. 用户访问：`https://www.app.com/#/resource/detail/123`
2. Traefik Forward Auth 拦截请求（此时前端 JS 还未加载）
3. 返回 307 重定向到 OAuth 登录页面
4. 浏览器直接跳转，前端 JS 根本没有机会执行

**结论**：前端 JS 无法在重定向前保存 hash，因此无法恢复。唯一可行的方案是改用 History 模式。
