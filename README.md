# Auth Worker

本项目是基于 Cloudflare Workers 的简易认证中间件，支持密码登录和 Cookie 认证，适用于需要简单保护的服务。

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
  {
  	"vars": {
  		"ENCRYPTION_KEY": "your-encryption-key",
  		"COOKIE_MAX_AGE": 3600,
  		"example.com": {
  			"password": "your-password",
  			"whiteList": ["^/public", "^.*/static"]
  		}
  	},
  }
  ```
  - `ENCRYPTION_KEY`：用于加解密 Cookie，建议设置为 128 bit，加密方式为 AES，**_注意不要泄露_**
  - `COOKIE_MAX_AGE`：Cookie 的最大有效期（秒），用于控制登录会话的持续时间
  - `example.com`：针对各个域名的配置
    - `password`：指定该域名的登录密码
    - `whiteList`：可选，路径白名单数组（支持正则表达式），若匹配则无需认证

## 部署

- 配置域或路由
  参考：[Configuration - Wrangler · Cloudflare Workers docs](https://developers.cloudflare.com/workers/wrangler/configuration/#routes)

- 部署
  ```bash
  npm run deploy
  ```

## 参考

- [Cloudflare Workers 文档](https://developers.cloudflare.com/workers/)
- [Wrangler 配置文档](https://developers.cloudflare.com/workers/wrangler/configuration/)
