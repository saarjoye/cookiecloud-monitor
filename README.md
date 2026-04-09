# CookieCloud Monitor

一个独立的 Docker 辅助项目，用来给 [CookieCloud](https://github.com/easychen/CookieCloud) 增加同步可观测性。

它不是去修改 CookieCloud 源码，而是作为 **前置代理（Reverse Proxy，反向代理）** 放在 CookieCloud 前面：

- 浏览器插件继续请求 `POST /update` 和 `GET/POST /get/:uuid`
- 监控服务把请求转发给真正的 CookieCloud
- 同时把每次同步的时间、UUID、成功/失败、状态码、耗时、客户端信息写入 SQLite
- 通过 Web 页面查看每日统计、近 7 天趋势和单条详情

## 功能

- 查看每日同步成功数、失败数、成功率
- 按 `upload` / `download` 拆分统计
- 查看近 7 天趋势
- 按 UUID 汇总同步情况
- 查看最近同步明细和单条详情
- 支持基础认证保护仪表盘
- **不保存原始 Cookie 或 LocalStorage 明文**

## 快速启动

### 1. 启动服务

```bash
docker compose up -d --build
```

默认会启动两个容器：

- `cookiecloud-app`：官方 CookieCloud 服务
- `cookiecloud-monitor`：本项目监控代理 + Web 仪表盘

### 2. 修改浏览器插件地址

把浏览器里的 CookieCloud 服务器地址从原来的 CookieCloud 地址，改成：

```text
http://你的服务器IP:8090
```

这样插件的同步请求会先经过本监控服务，再转发到真实的 CookieCloud。

### 3. 打开仪表盘

```text
http://你的服务器IP:8090/dashboard
```

默认账号密码来自 `docker-compose.yml`：

- 用户名：`admin`
- 密码：`change-me`

**上线前务必修改默认密码。**

## 配置项

| 变量 | 说明 | 默认值 |
| --- | --- | --- |
| `COOKIECLOUD_TARGET_URL` | 真正的 CookieCloud 地址 | `http://cookiecloud:8088` |
| `MONITOR_DB_PATH` | SQLite 数据库路径 | `/data/monitor.db` |
| `MONITOR_TIMEZONE` | 页面和统计使用的时区 | `Asia/Shanghai` |
| `DASHBOARD_USERNAME` | 仪表盘账号，为空则不启用认证 | `admin` |
| `DASHBOARD_PASSWORD` | 仪表盘密码，为空则不启用认证 | `change-me` |
| `RECENT_LOG_LIMIT` | 仪表盘最近明细条数 | `50` |

## 适配已有 CookieCloud

如果你已经有单独运行中的 CookieCloud，不想让本项目再启动一个新的：

1. 把 `COOKIECLOUD_TARGET_URL` 改成你现有的 CookieCloud 地址
2. 从 `docker-compose.yml` 中删除或注释 `cookiecloud` 服务
3. 只启动 `monitor` 服务

示例：

```yaml
services:
  monitor:
    build:
      context: .
    environment:
      COOKIECLOUD_TARGET_URL: http://192.168.1.20:8088
```

## 关键接口

- `GET /dashboard`：Web 仪表盘
- `GET /logs/{id}`：单条同步详情
- `GET /api/summary`：汇总统计 JSON
- `GET /api/logs`：明细 JSON
- `POST /update`：代理 CookieCloud 上传接口
- `GET/POST /get/{uuid}`：代理 CookieCloud 下载接口
- `GET /healthz`：健康检查

## 结果判定逻辑

- **上传成功**：上游返回 `2xx`
- **下载成功**：上游返回 `2xx`，且返回体可识别到 `encrypted` / `cookie_data` / `local_storage_data`
- **失败**：上游返回非 `2xx`，或代理无法连通上游

说明：

- 这是基于请求/响应的监控判定，不会解析你的 Cookie 明文内容
- 如果上游未来变更返回格式，成功/失败判定规则可以在 `app/main.py` 里继续扩展

## 安全说明

- 本项目默认只保存请求元数据和请求载荷摘要 `SHA-256`
- 不保存浏览器同步上来的原始加密串全文
- 不保存明文 Cookie
- 如果服务暴露到公网，建议额外放到 Nginx 或 Cloudflare Tunnel 后面，并限制访问来源

## 参考

- CookieCloud 官方仓库：<https://github.com/easychen/CookieCloud>
- 官方 Docker 镜像：<https://hub.docker.com/r/easychen/cookiecloud>

## 自动发布镜像

仓库已包含 GitHub Actions 工作流 [`publish-image.yml`](./.github/workflows/publish-image.yml)：

- 默认发布到 `ghcr.io/saarjoye/cookiecloud-monitor`
- 如果配置了 Docker Hub 凭据，也会同步发布到 `docker.io/<你的用户名>/cookiecloud-monitor`

需要在 GitHub 仓库设置里补两个值：

| 类型 | 名称 | 说明 |
| --- | --- | --- |
| Variable | `DOCKERHUB_USERNAME` | Docker Hub 用户名 |
| Secret | `DOCKERHUB_TOKEN` | Docker Hub Access Token |

配置完成后，向 `main` 分支推送一次，或在 Actions 页面手动执行 `Publish Docker Image` 即可。
# CookieCloud Monitor

一个独立的 Docker 辅助项目，用来给 [CookieCloud](https://github.com/easychen/CookieCloud) 增加同步可观测性。

它不是去修改 CookieCloud 源码，而是作为 **前置代理（Reverse Proxy，反向代理）** 放在 CookieCloud 前面：

- 浏览器插件继续请求 `POST /update` 和 `GET/POST /get/:uuid`
- 监控服务把请求转发给真正的 CookieCloud
- 同时把每次同步的时间、UUID、成功/失败、状态码、耗时、客户端信息写入 SQLite
- 通过 Web 页面查看每日统计、近 7 天趋势和单条详情

## 功能

- 查看每日同步成功数、失败数、成功率
- 按 `upload` / `download` 拆分统计
- 查看近 7 天趋势
- 按 UUID 汇总同步情况
- 查看最近同步明细和单条详情
- 支持基础认证保护仪表盘
- **不保存原始 Cookie 或 LocalStorage 明文**

## 快速启动

### 1. 启动服务

```bash
docker compose up -d --build
```

默认会启动两个容器：

- `cookiecloud-app`：官方 CookieCloud 服务
- `cookiecloud-monitor`：本项目监控代理 + Web 仪表盘

### 2. 修改浏览器插件地址

把浏览器里的 CookieCloud 服务器地址从原来的 CookieCloud 地址，改成：

```text
http://你的服务器IP:8090
```

这样插件的同步请求会先经过本监控服务，再转发到真实的 CookieCloud。

### 3. 打开仪表盘

```text
http://你的服务器IP:8090/dashboard
```

默认账号密码来自 `docker-compose.yml`：

- 用户名：`admin`
- 密码：`change-me`

**上线前务必修改默认密码。**

## 配置项

| 变量 | 说明 | 默认值 |
| --- | --- | --- |
| `COOKIECLOUD_TARGET_URL` | 真正的 CookieCloud 地址 | `http://cookiecloud:8088` |
| `MONITOR_DB_PATH` | SQLite 数据库路径 | `/data/monitor.db` |
| `MONITOR_TIMEZONE` | 页面和统计使用的时区 | `Asia/Shanghai` |
| `DASHBOARD_USERNAME` | 仪表盘账号，为空则不启用认证 | `admin` |
| `DASHBOARD_PASSWORD` | 仪表盘密码，为空则不启用认证 | `change-me` |
| `RECENT_LOG_LIMIT` | 仪表盘最近明细条数 | `50` |

## 适配已有 CookieCloud

如果你已经有单独运行中的 CookieCloud，不想让本项目再启动一个新的：

1. 把 `COOKIECLOUD_TARGET_URL` 改成你现有的 CookieCloud 地址
2. 从 `docker-compose.yml` 中删除或注释 `cookiecloud` 服务
3. 只启动 `monitor` 服务

示例：

```yaml
services:
  monitor:
    build:
      context: .
    environment:
      COOKIECLOUD_TARGET_URL: http://192.168.1.20:8088
```

## 关键接口

- `GET /dashboard`：Web 仪表盘
- `GET /logs/{id}`：单条同步详情
- `GET /api/summary`：汇总统计 JSON
- `GET /api/logs`：明细 JSON
- `POST /update`：代理 CookieCloud 上传接口
- `GET/POST /get/{uuid}`：代理 CookieCloud 下载接口
- `GET /healthz`：健康检查

## 结果判定逻辑

- **上传成功**：上游返回 `2xx`
- **下载成功**：上游返回 `2xx`，且返回体可识别到 `encrypted` / `cookie_data` / `local_storage_data`
- **失败**：上游返回非 `2xx`，或代理无法连通上游

说明：

- 这是基于请求/响应的监控判定，不会解析你的 Cookie 明文内容
- 如果上游未来变更返回格式，成功/失败判定规则可以在 `app/main.py` 里继续扩展

## 安全说明

- 本项目默认只保存请求元数据和请求载荷摘要 `SHA-256`
- 不保存浏览器同步上来的原始加密串全文
- 不保存明文 Cookie
- 如果服务暴露到公网，建议额外放到 Nginx 或 Cloudflare Tunnel 后面，并限制访问来源

## 参考

- CookieCloud 官方仓库：<https://github.com/easychen/CookieCloud>
- 官方 Docker 镜像：<https://hub.docker.com/r/easychen/cookiecloud>
