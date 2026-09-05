# DeployFlow — 动态网站部署平台

基于 Node.js + Express + MySQL 的动态网站部署平台，支持用户注册登录、项目部署管理、文件上传、留言板四大核心功能。

## 功能模块

| 模块 | 说明 |
|------|------|
| 用户注册/登录 | 邮箱注册（验证码）、GitHub 登录、微信登录，JWT 会话管理，bcrypt 密码加密 |
| 内容发布/管理 | 项目创建（Git 导入/文件上传/模板），部署到服务器，文件编辑同步，自定义域名 |
| 文件上传与管理 | 拖拽上传多文件，部署后可通过 `/deployed/<slug>/` 访问，支持在线编辑同步 |
| 留言板/评论 | 公开留言板，登录后发布留言，支持删除自己的留言 |

## 技术栈

- **前端**: HTML/CSS/JavaScript（单页应用，响应式设计，深色/浅色主题）
- **后端**: Node.js + Express
- **数据库**: MySQL 8.0+
- **认证**: JWT + bcrypt
- **文件存储**: 磁盘 + MySQL 双写

## 快速开始

### 1. 安装依赖

```bash
cd deployflow
npm install
```

### 2. 配置数据库

复制 `.env.example` 为 `.env`，修改数据库配置：

```bash
cp .env.example .env
```

```env
PORT=3000
DB_HOST=localhost
DB_PORT=3306
DB_USER=root
DB_PASSWORD=your_password
DB_NAME=deployflow
JWT_SECRET=change_this_to_random_string
BASE_URL=http://localhost:3000
```

### 3. 初始化数据库

确保 MySQL 已启动，然后运行：

```bash
node database/init.js
```

这会自动创建 `deployflow` 数据库和所有表（users, projects, project_files, deployments, guestbook, api_tokens, team_members, notifications, domains, verify_codes）。

### 4. 启动服务器

```bash
npm start
```

打开浏览器访问 `http://localhost:3000` 即可使用。

## 项目结构

```
deployflow/
├── server.js              # Express 主服务
├── package.json
├── .env.example           # 环境变量模板
├── config/
│   └── database.js        # MySQL 连接池
├── middleware/
│   └── auth.js            # JWT 认证中间件
├── routes/
│   ├── auth.js            # 认证 + 邮件 + 通知 + 团队
│   ├── projects.js        # 项目 + 部署 + 同步 + 文件 + Token + 域名
│   └── guestbook.js       # 留言板
├── database/
│   └── init.js            # 数据库初始化脚本
├── public/
│   ├── index.html         # 前端页面
│   └── verify.html        # 验证码接收器
├── deployed/              # 已部署的网站（自动生成）
└── uploads/               # 上传文件临时目录
```

## API 接口

### 认证
| 方法 | 路径 | 说明 |
|------|------|------|
| POST | /api/auth/register | 邮箱注册 |
| POST | /api/auth/login | 邮箱登录 |
| POST | /api/auth/github | GitHub 登录 |
| POST | /api/auth/wechat | 微信登录 |
| GET | /api/auth/me | 获取当前用户 |
| PUT | /api/auth/profile | 更新资料 |
| PUT | /api/auth/password | 修改密码 |
| POST | /api/send-email | 发送验证码 |

### 项目
| 方法 | 路径 | 说明 |
|------|------|------|
| GET | /api/projects | 项目列表 |
| GET | /api/projects/:id | 项目详情 |
| POST | /api/deploy | 部署项目 |
| PUT | /api/projects/:id | 更新项目 |
| DELETE | /api/projects/:id | 删除项目 |
| POST | /api/sync | 文件同步 |
| POST | /api/auto-sync | 自动同步 |
| GET | /api/files/:project/:filename | 获取文件内容 |

### 留言板
| 方法 | 路径 | 说明 |
|------|------|------|
| GET | /api/guestbook | 留言列表 |
| POST | /api/guestbook | 发布留言 |
| DELETE | /api/guestbook/:id | 删除留言 |

### 其他
| 方法 | 路径 | 说明 |
|------|------|------|
| GET/POST/DELETE | /api/tokens | API Token 管理 |
| POST | /api/domains | 域名绑定/解绑 |
| GET/POST | /api/notifications | 通知管理 |
| GET/POST/DELETE | /api/team | 团队管理 |

## 部署到 Cloudflare

> **注意**: Cloudflare Workers/Pages 原生不支持 Node.js + Express + MySQL 运行环境。Cloudflare 使用 V8 isolate 运行时和 D1（SQLite）数据库，与本项目技术栈不兼容。

### 推荐方案：Cloudflare DNS + VPS

1. **在 VPS 上运行 DeployFlow**：在任意支持 Node.js 的服务器（如 AWS EC2、Vultr、Hetzner）上部署本项目
2. **用 Cloudflare 做 DNS 和 CDN**：
   - 在 Cloudflare 添加你的域名
   - 将域名 A 记录指向 VPS IP
   - 开启 Cloudflare 代理（橙色云朵）
   - Cloudflare 自动提供 HTTPS、DDoS 防护、全球 CDN 加速
3. **访问 MySQL**：MySQL 运行在 VPS 上，无需外部访问

### 替代方案

如果必须使用 Cloudflare 全家桶：
- 将后端改写为 Cloudflare Pages Functions + D1 数据库（需要大规模重构，不推荐）
- 使用 Cloudflare Tunnel 将 VPS 上的服务暴露到公网

## 验证码说明

未配置 SMTP 时，验证码以演示模式运行：
- 调用 `/api/send-email` 后，验证码会直接在响应中返回
- 前端注册页面会显示验证码
- 也可访问 `/verify.html` 查看最新验证码

配置 SMTP 后，验证码会通过邮件发送：
```env
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your_email@gmail.com
SMTP_PASS=your_app_password
SMTP_FROM=noreply@yourdomain.com
```

## 许可证

MIT
