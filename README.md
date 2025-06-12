# Auth Worker

本项目是基于 Cloudflare Workers 的简易认证中间件，支持密码登录和 Cookie 认证，适用于需要简单保护的服务。

- 测试页面：

  https://auth-test.shuvi.moe/

- 测试配置：
  ```jsonc
    "auth-test.shuvi.moe": {
      "COOKIE_MAX_AGE": 60,
      "PASSWORD": "test",
      "WHITE_LIST": ["^/public", "^.*/static"],
      "REFRESH": true
    }
  ```
- 测试目录结构：

  https://github.com/cyb233/auth-test/tree/main/public

## 功能

- 密码登录，支持多域名配置不同密码
- 登录后通过加密 Cookie 维持会话
- 未登录自动跳转到登录页
- 支持 Cloudflare Workers 智能部署

## 目录结构

- `src/index.ts`：主 Worker 逻辑
- `public/login.html`：登录页面
- `wrangler.jsonc`：Cloudflare Worker 配置

## 开发

1. 安装依赖
   ```bash
   npm install
   ```
2. 启动本地开发服务
   ```bash
   npm run dev
   ```
3. 访问 [http://localhost:8787/](http://localhost:8787/) 查看效果

## 配置

- 在 `wrangler.jsonc` 的 `vars` 字段中为每个域名配置密码和可选的白名单路径，例如：
  ```jsonc
  "vars": {
    "ENCRYPTION_KEY": "your-encryption-key",
    "COOKIE_MAX_AGE": 3600,
    "REFRESH": false,
    "example.com": {
      "PASSWORD": "your-password",
      "WHITE_LIST": ["^/public", "^.*/static"],
      "ENCRYPTION_KEY": "your-another-key",
      "COOKIE_MAX_AGE": 60,
      "REFRESH": true
    }
  }
  ```

**全局配置项**

| 配置项           | 类型    | 作用说明                                                                    | 是否必填 |
| ---------------- | ------- | --------------------------------------------------------------------------- | -------- |
| `ENCRYPTION_KEY` | string  | 用于加解密 Cookie，建议设置为 128 bit，加密方式为 AES，**注意不要泄露密钥** | 是       |
| `COOKIE_MAX_AGE` | number  | Cookie 的最大有效期（秒），用于控制登录会话的持续时间                       | 是       |
| `REFRESH`        | boolean | 是否每次访问自动续期 Cookie（默认为 false）                                 | 否       |

**域名配置项**

| 配置项           | 类型     | 作用说明                                                                                                                                  | 是否必填 |
| ---------------- | -------- | ----------------------------------------------------------------------------------------------------------------------------------------- | -------- |
| `PASSWORD`       | string   | 指定该域名的登录密码                                                                                                                      | 是       |
| `WHITE_LIST`     | string[] | 路径的白名单数组（[正则表达式语法](https://developer.mozilla.org/zh-CN/docs/Web/JavaScript/Guide/Regular_expressions)），若匹配则无需认证 | 否       |
| `ENCRYPTION_KEY` | string   | 覆盖全局的加密密钥                                                                                                                        | 否       |
| `COOKIE_MAX_AGE` | number   | 覆盖全局的 Cookie 有效期                                                                                                                  | 否       |
| `REFRESH`        | boolean  | 覆盖全局的自动续期设置                                                                                                                    | 否       |

- 全局配置可被域名下的同名配置覆盖，优先级：域名 > 全局。

## 部署

- 配置路由

  参考：[Configuration - Wrangler · Cloudflare Workers docs](https://developers.cloudflare.com/workers/wrangler/configuration/#routes)

- 部署
  ```bash
  npm run deploy
  ```

## 参考

- [Cloudflare Workers 文档](https://developers.cloudflare.com/workers/)
- [Wrangler 配置文档](https://developers.cloudflare.com/workers/wrangler/configuration/)
