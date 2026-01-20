# gateway-forward-auth

跨域 SSO 认证网关，基于 traefik-forward-auth 扩展，支持多域名共享登录状态。

## 跨域 SSO 认证流程

```text
┌─────────────────────────────────────────────────────────────────────────────────────┐
│                              跨域 SSO 认证流程图                                      │
└─────────────────────────────────────────────────────────────────────────────────────┘

用户浏览器                    k8s.xny.wodcloud.local           auth.ali.wodcloud.com              Logto (OIDC)
    │                              (Traefik)                    (Forward-Auth)                        │
    │                                  │                              │                               │
    │  1. GET /app                     │                              │                               │
    ├─────────────────────────────────>│                              │                               │
    │                                  │                              │                               │
    │                                  │  2. Forward Auth 检查        │                               │
    │                                  ├─────────────────────────────>│                               │
    │                                  │                              │                               │
    │                                  │  3. 无 session，生成 session_id                              │
    │                                  │     返回 307 + Set-Cookie    │                               │
    │                                  │<─────────────────────────────┤                               │
    │                                  │                              │                               │
    │  4. 307 Redirect                 │                              │                               │
    │     Set-Cookie: _session=xxx (在 wodcloud.local 域名下)         │                               │
    │     Location: auth.ali.wodcloud.com/_oauth?action=start         │                               │
    │               &session_id=xxx&provider=oidc&redirect=原始URL    │                               │
    │<─────────────────────────────────┤                              │                               │
    │                                  │                              │                               │
    │  5. GET /_oauth?action=start&session_id=xxx&...                 │                               │
    ├────────────────────────────────────────────────────────────────>│                               │
    │                                  │                              │                               │
    │  6. 307 Redirect (直接跳转，无需设置 cookie)                     │                               │
    │     Location: login.ali.wodcloud.com/oidc/auth                  │                               │
    │               &state=session_id:redirect_url                    │                               │
    │<────────────────────────────────────────────────────────────────┤                               │
    │                                  │                              │                               │
    │  7. GET /oidc/auth?client_id=xxx&redirect_uri=auth.../_oauth&state=session_id:redirect          │
    ├────────────────────────────────────────────────────────────────────────────────────────────────>│
    │                                  │                              │                               │
    │  8. 用户登录                      │                              │                               │
    │<───────────────────────────────────────────────────────────────────────────────────────────────>│
    │                                  │                              │                               │
    │  9. 302 Redirect                 │                              │                               │
    │     Location: auth.ali.wodcloud.com/_oauth?code=xxx&state=session_id:redirect                   │
    │<────────────────────────────────────────────────────────────────────────────────────────────────┤
    │                                  │                              │                               │
    │  10. GET /_oauth?code=xxx&state=session_id:redirect             │                               │
    ├────────────────────────────────────────────────────────────────>│                               │
    │                                  │                              │                               │
    │                                  │                              │  11. 解析 state 获取 session_id
    │                                  │                              │      Exchange code for token  │
    │                                  │                              ├──────────────────────────────>│
    │                                  │                              │                               │
    │                                  │                              │  12. 返回 access_token        │
    │                                  │                              │<──────────────────────────────┤
    │                                  │                              │                               │
    │                                  │                              │  13. 获取用户信息 (email)     │
    │                                  │                              │      存入 session_store       │
    │                                  │                              │      session_id -> email      │
    │                                  │                              │                               │
    │  14. 307 Redirect                │                              │                               │
    │      Location: k8s.xny.wodcloud.local/app (原始URL)             │                               │
    │<────────────────────────────────────────────────────────────────┤                               │
    │                                  │                              │                               │
    │  15. GET /app                    │                              │                               │
    │      Cookie: _session=xxx        │                              │                               │
    ├─────────────────────────────────>│                              │                               │
    │                                  │                              │                               │
    │                                  │  16. Forward Auth 检查       │                               │
    │                                  │      Cookie: _session=xxx    │                               │
    │                                  ├─────────────────────────────>│                               │
    │                                  │                              │                               │
    │                                  │  17. 查询 session_store      │                               │
    │                                  │      找到 email，认证通过    │                               │
    │                                  │      返回 200                │                               │
    │                                  │      X-Forwarded-User: email │                               │
    │                                  │<─────────────────────────────┤                               │
    │                                  │                              │                               │
    │  18. 返回应用内容                 │                              │                               │
    │<─────────────────────────────────┤                              │                               │
    │                                  │                              │                               │
```

## 关键设计

### Session 机制

- 第一次访问时在**原始域名**下设置 session cookie
- session_id 通过 URL 参数传递给 AUTH_HOST，再通过 OAuth state 参数传递给 OIDC Provider
- 登录成功后，AUTH_HOST 从 state 解析 session_id，将 email 存入内存 session store
- 回到原始域名时，浏览器自动带上 session cookie，forward-auth 查询 session store 完成认证

### 为什么不需要 CSRF Cookie？

传统流程需要 CSRF cookie 防止伪造请求，但在跨域场景下：

- session_id 是随机生成的 32 字节，本身就具有防伪造能力
- session_id 通过 URL 传递，不依赖 cookie 跨域
- 只有持有 session_id 的请求才能更新对应的 session

### 为什么需要这样设计？

浏览器安全策略不允许跨域设置 cookie：

- `auth.ali.wodcloud.com` 无法为 `k8s.xny.wodcloud.local` 设置 cookie
- 所以必须在第一跳时就在原始域名下设置 session cookie
- 然后通过 URL 参数传递 session_id，最后通过后端 session store 关联用户信息

## 配置示例

```yaml
env:
  - name: DEFAULT_PROVIDER
    value: "oidc"
  - name: PROVIDERS_OIDC_ISSUER_URL
    value: "https://login.ali.wodcloud.com/oidc"
  - name: PROVIDERS_OIDC_CLIENT_ID
    valueFrom:
      secretKeyRef:
        name: logto-forward-auth
        key: PROVIDERS_OIDC_CLIENT_ID
  - name: PROVIDERS_OIDC_CLIENT_SECRET
    valueFrom:
      secretKeyRef:
        name: logto-forward-auth
        key: PROVIDERS_OIDC_CLIENT_SECRET
  - name: SECRET
    valueFrom:
      secretKeyRef:
        name: logto-forward-auth
        key: SECRET
  # 认证回调域名 - 所有域名共用这一个回调地址
  - name: AUTH_HOST
    value: "auth.ali.wodcloud.com"
  - name: URL_PATH
    value: "/_oauth"
  # 可选：配置已知的 cookie 域名（不配置则自动提取顶级域名）
  # - name: COOKIE_DOMAIN
  #   value: "wodcloud.com"
  - name: LOG_LEVEL
    value: "info"
```

## Logto 配置

在 Logto 控制台创建应用：

1. 应用类型: Traditional Web
2. Redirect URIs: `https://auth.ali.wodcloud.com/_oauth`（只需要这一个）
3. 获取 Client ID 和 Client Secret

## git

```bash
git remote add upstream git@github.com:thomseddon/traefik-forward-auth.git
git fetch upstream
git merge v2.3.0
```

## build

```bash
bash .beagle/build.sh
```
