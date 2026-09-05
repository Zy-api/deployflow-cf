import { Hono } from 'hono';
import { handle } from 'hono/cloudflare-pages';
import { SignJWT, jwtVerify } from 'jose';

const app = new Hono();
const JWT_SECRET = 'deployflow_secret_key_2026';
const secretKey = new TextEncoder().encode(JWT_SECRET);

// ==================== Utilities ====================

function bytesToB64(bytes) {
  let binary = '';
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary);
}

function b64ToBytes(b64) {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

function b64ToText(b64) {
  return new TextDecoder().decode(b64ToBytes(b64));
}

function textToB64(text) {
  const bytes = new TextEncoder().encode(text);
  let binary = '';
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary);
}

function randomHex(n) {
  const arr = new Uint8Array(n);
  crypto.getRandomValues(arr);
  return Array.from(arr).map(b => b.toString(16).padStart(2, '0')).join('');
}

function ts(dateStr) {
  if (!dateStr) return null;
  try {
    const s = typeof dateStr === 'string' ? dateStr.replace(' ', 'T') : dateStr;
    return new Date(s.endsWith('Z') ? s : s + 'Z').getTime();
  } catch { return null; }
}

function getContentType(filename) {
  const ext = (filename.split('.').pop() || '').toLowerCase();
  const types = {
    html: 'text/html; charset=utf-8', htm: 'text/html; charset=utf-8',
    css: 'text/css; charset=utf-8', js: 'application/javascript; charset=utf-8',
    json: 'application/json; charset=utf-8', xml: 'application/xml; charset=utf-8',
    txt: 'text/plain; charset=utf-8', md: 'text/plain; charset=utf-8',
    png: 'image/png', jpg: 'image/jpeg', jpeg: 'image/jpeg',
    gif: 'image/gif', svg: 'image/svg+xml', ico: 'image/x-icon',
    webp: 'image/webp', avif: 'image/avif', bmp: 'image/bmp',
    mp4: 'video/mp4', webm: 'video/webm', ogg: 'video/ogg',
    mp3: 'audio/mpeg', wav: 'audio/wav', flac: 'audio/flac',
    pdf: 'application/pdf', zip: 'application/zip', gz: 'application/gzip',
    woff: 'font/woff', woff2: 'font/woff2', ttf: 'font/ttf', otf: 'font/otf',
    eot: 'application/vnd.ms-fontobject',
  };
  return types[ext] || 'application/octet-stream';
}

// ==================== D1 Helpers ====================

async function dbAll(env, sql, ...params) {
  const stmt = params.length > 0 ? env.DB.prepare(sql).bind(...params) : env.DB.prepare(sql);
  const result = await stmt.all();
  return result.results || [];
}

async function dbFirst(env, sql, ...params) {
  const stmt = params.length > 0 ? env.DB.prepare(sql).bind(...params) : env.DB.prepare(sql);
  return await stmt.first();
}

async function dbRun(env, sql, ...params) {
  const stmt = params.length > 0 ? env.DB.prepare(sql).bind(...params) : env.DB.prepare(sql);
  return await stmt.run();
}

// ==================== JWT ====================

async function signToken(payload) {
  return await new SignJWT(payload)
    .setProtectedHeader({ alg: 'HS256' })
    .setIssuedAt()
    .setExpirationTime('7d')
    .sign(secretKey);
}

async function getTokenPayload(token) {
  try {
    const { payload } = await jwtVerify(token, secretKey);
    return payload;
  } catch { return null; }
}

// ==================== Password (PBKDF2) ====================

async function hashPassword(password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), { name: 'PBKDF2' }, false, ['deriveBits']);
  const hash = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' }, key, 256);
  return 'pbkdf2:' + bytesToB64(new Uint8Array(salt)) + ':' + bytesToB64(new Uint8Array(hash));
}

async function verifyPassword(password, stored) {
  if (!stored) return false;
  const parts = stored.split(':');
  if (parts.length !== 3 || parts[0] !== 'pbkdf2') return false;
  const salt = b64ToBytes(parts[1]);
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), { name: 'PBKDF2' }, false, ['deriveBits']);
  const hash = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' }, key, 256);
  return bytesToB64(new Uint8Array(hash)) === parts[2];
}

// ==================== Auth Middleware ====================

async function authMiddleware(c, next) {
  const authHeader = c.req.header('Authorization') || '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.substring(7) : '';
  if (!token) return c.json({ success: false, error: '请先登录' }, 401);
  const payload = await getTokenPayload(token);
  if (!payload) return c.json({ success: false, error: '登录已过期，请重新登录' }, 401);
  c.set('userId', payload.userId);
  c.set('user', payload);
  await next();
}

// ==================== Health ====================

app.get('/api/health', (c) => c.json({ success: true, message: 'DeployFlow Cloudflare Pages API' }));

// ==================== Auth Routes ====================

app.post('/api/auth/register', async (c) => {
  let body;
  try { body = await c.req.json(); } catch { return c.json({ success: false, error: '请求体格式错误' }, 400); }
  const { email, password } = body;
  const name = body.name || (email ? email.split('@')[0] : null);
  if (!email || !password) return c.json({ success: false, error: '请填写所有必填字段' }, 400);

  const existing = await dbFirst(c.env, 'SELECT id FROM users WHERE email = ?', email);
  if (existing) return c.json({ success: false, error: '该邮箱已注册' }, 400);

  const hashed = await hashPassword(password);
  const result = await dbRun(c.env, 'INSERT INTO users (email, password, name, provider) VALUES (?, ?, ?, ?)', email, hashed, name, 'email');
  const userId = result.meta ? result.meta.last_row_id : result.lastInsertRowid;
  const token = await signToken({ userId: Number(userId), email, name, avatar: null });
  return c.json({ success: true, token, user: { id: Number(userId), email, name, avatar: null } });
});

app.post('/api/auth/login', async (c) => {
  let body;
  try { body = await c.req.json(); } catch { return c.json({ success: false, error: '请求体格式错误' }, 400); }
  const { email, password } = body;
  if (!email || !password) return c.json({ success: false, error: '请输入邮箱和密码' }, 400);

  const user = await dbFirst(c.env, 'SELECT * FROM users WHERE email = ?', email);
  if (!user) return c.json({ success: false, error: '邮箱或密码错误' }, 400);

  const valid = await verifyPassword(password, user.password);
  if (!valid) return c.json({ success: false, error: '邮箱或密码错误' }, 400);

  const token = await signToken({ userId: user.id, email: user.email, name: user.name, avatar: user.avatar });
  return c.json({ success: true, token, user: { id: user.id, email: user.email, name: user.name, avatar: user.avatar } });
});

app.post('/api/auth/github', async (c) => {
  let body;
  try { body = await c.req.json(); } catch { return c.json({ success: false, error: '请求体格式错误' }, 400); }
  const { login, name, avatar, email } = body;
  if (!login) return c.json({ success: false, error: 'GitHub 信息不完整' }, 400);

  let user = await dbFirst(c.env, 'SELECT * FROM users WHERE github_login = ?', login);
  if (!user && email) user = await dbFirst(c.env, 'SELECT * FROM users WHERE email = ?', email);

  if (user) {
    await dbRun(c.env, 'UPDATE users SET github_login=?, github_avatar=?, github_name=?, avatar=? WHERE id=?', login, avatar, name, avatar || user.avatar, user.id);
  } else {
    const result = await dbRun(c.env, 'INSERT INTO users (email, name, avatar, provider, github_login, github_avatar, github_name) VALUES (?, ?, ?, ?, ?, ?, ?)', email || (login + '@github.local'), name || login, avatar, 'github', login, avatar, name);
    const newId = result.meta ? result.meta.last_row_id : result.lastInsertRowid;
    user = await dbFirst(c.env, 'SELECT * FROM users WHERE id = ?', Number(newId));
  }

  const token = await signToken({ userId: user.id, email: user.email, name: user.name, avatar: user.avatar });
  return c.json({ success: true, token, user: { id: user.id, email: user.email, name: user.name, avatar: user.avatar } });
});

app.post('/api/auth/wechat', async (c) => {
  let body;
  try { body = await c.req.json(); } catch { return c.json({ success: false, error: '请求体格式错误' }, 400); }
  const { openid, nickname, avatar } = body;
  if (!openid) return c.json({ success: false, error: '微信信息不完整' }, 400);

  let user = await dbFirst(c.env, 'SELECT * FROM users WHERE email = ?', 'wx_' + openid + '@wechat.local');
  if (!user) {
    const result = await dbRun(c.env, 'INSERT INTO users (email, name, avatar, provider) VALUES (?, ?, ?, ?)', 'wx_' + openid + '@wechat.local', nickname || '微信用户', avatar, 'wechat');
    const newId = result.meta ? result.meta.last_row_id : result.lastInsertRowid;
    user = await dbFirst(c.env, 'SELECT * FROM users WHERE id = ?', Number(newId));
  }

  const token = await signToken({ userId: user.id, email: user.email, name: user.name, avatar: user.avatar });
  return c.json({ success: true, token, user: { id: user.id, email: user.email, name: user.name, avatar: user.avatar } });
});

app.get('/api/auth/me', authMiddleware, (c) => {
  const u = c.get('user');
  return c.json({ success: true, user: { id: u.userId, email: u.email, name: u.name, avatar: u.avatar } });
});

app.put('/api/auth/profile', authMiddleware, async (c) => {
  let body;
  try { body = await c.req.json(); } catch { return c.json({ success: false, error: '请求体格式错误' }, 400); }
  const userId = c.get('userId');
  const { name, avatar } = body;
  const fields = [];
  const params = [];
  if (name) { fields.push('name = ?'); params.push(name); }
  if (avatar) { fields.push('avatar = ?'); params.push(avatar); }
  if (fields.length === 0) return c.json({ success: false, error: '没有要更新的字段' }, 400);
  params.push(userId);
  await dbRun(c.env, 'UPDATE users SET ' + fields.join(', ') + ' WHERE id = ?', ...params);
  const user = await dbFirst(c.env, 'SELECT * FROM users WHERE id = ?', userId);
  const token = await signToken({ userId: user.id, email: user.email, name: user.name, avatar: user.avatar });
  return c.json({ success: true, user: { id: user.id, email: user.email, name: user.name, avatar: user.avatar }, token });
});

app.put('/api/auth/password', authMiddleware, async (c) => {
  let body;
  try { body = await c.req.json(); } catch { return c.json({ success: false, error: '请求体格式错误' }, 400); }
  const userId = c.get('userId');
  const { currentPassword, newPassword } = body;
  if (!currentPassword || !newPassword) return c.json({ success: false, error: '请填写当前密码和新密码' }, 400);

  const user = await dbFirst(c.env, 'SELECT * FROM users WHERE id = ?', userId);
  if (!user) return c.json({ success: false, error: '用户不存在' }, 404);

  const valid = await verifyPassword(currentPassword, user.password);
  if (!valid) return c.json({ success: false, error: '当前密码错误' }, 400);

  const hashed = await hashPassword(newPassword);
  await dbRun(c.env, 'UPDATE users SET password = ? WHERE id = ?', hashed, userId);
  return c.json({ success: true, message: '密码修改成功' });
});

// ==================== Email / Verify ====================

app.get('/api/send-email', async (c) => {
  const check = c.req.query('check');
  if (check) {
    const row = await dbFirst(c.env, "SELECT code, email FROM verify_codes WHERE expires_at > datetime('now') ORDER BY created_at DESC");
    if (row) return c.json({ success: true, code: row.code, email: row.email, message: '最新验证码' });
    return c.json({ success: false, message: '暂无有效验证码' }, 404);
  }

  const email = c.req.query('email');
  if (!email) return c.json({ success: false, error: '请输入邮箱' }, 400);
  const code = String(Math.floor(100000 + Math.random() * 900000));
  await dbRun(c.env, "INSERT INTO verify_codes (email, code, expires_at) VALUES (?, ?, datetime('now', '+5 minutes'))", email, code);
  return c.json({ success: true, code, message: '验证码已生成（Pages 环境下返回 code 字段，请前端展示）' });
});

app.post('/api/send-email', async (c) => {
  let body;
  try { body = await c.req.json(); } catch { body = {}; }
  const email = body.email || c.req.query('email');
  if (!email) return c.json({ success: false, error: '请输入邮箱' }, 400);
  const code = body.code || String(Math.floor(100000 + Math.random() * 900000));
  await dbRun(c.env, "INSERT INTO verify_codes (email, code, expires_at) VALUES (?, ?, datetime('now', '+5 minutes'))", email, code);
  return c.json({ success: true, code, message: '验证码已生成（Pages 环境下返回 code 字段，请前端展示）' });
});

// ==================== Notifications ====================

app.get('/api/notifications', authMiddleware, async (c) => {
  const userId = c.get('userId');
  const rows = await dbAll(c.env, 'SELECT * FROM notifications WHERE user_id = ? ORDER BY created_at DESC', userId);
  return c.json({ success: true, list: rows.map(n => ({ ...n, created_at: ts(n.created_at), is_read: !!n.is_read })) });
});

app.post('/api/notifications', authMiddleware, async (c) => {
  let body;
  try { body = await c.req.json(); } catch { return c.json({ success: false, error: '请求体格式错误' }, 400); }
  const userId = c.get('userId');
  const { type = 'info', title, description } = body;
  if (!title) return c.json({ success: false, error: '标题不能为空' }, 400);
  await dbRun(c.env, 'INSERT INTO notifications (user_id, type, title, description) VALUES (?, ?, ?, ?)', userId, type, title, description || '');
  return c.json({ success: true, message: '通知已创建' });
});

app.put('/api/notifications/:id/read', authMiddleware, async (c) => {
  const userId = c.get('userId');
  await dbRun(c.env, 'UPDATE notifications SET is_read = 1 WHERE id = ? AND user_id = ?', c.req.param('id'), userId);
  return c.json({ success: true, message: '已标记为已读' });
});

app.put('/api/notifications/read-all', authMiddleware, async (c) => {
  const userId = c.get('userId');
  await dbRun(c.env, 'UPDATE notifications SET is_read = 1 WHERE user_id = ?', userId);
  return c.json({ success: true, message: '全部已读' });
});

// ==================== Team ====================

app.get('/api/team', authMiddleware, async (c) => {
  const userId = c.get('userId');
  const rows = await dbAll(c.env, 'SELECT * FROM team_members WHERE user_id = ? ORDER BY created_at DESC', userId);
  return c.json({ success: true, list: rows.map(r => ({ ...r, created_at: ts(r.created_at) })) });
});

app.post('/api/team', authMiddleware, async (c) => {
  let body;
  try { body = await c.req.json(); } catch { return c.json({ success: false, error: '请求体格式错误' }, 400); }
  const userId = c.get('userId');
  const { email, role = 'member' } = body;
  if (!email) return c.json({ success: false, error: '邮箱不能为空' }, 400);
  await dbRun(c.env, 'INSERT INTO team_members (user_id, email, role) VALUES (?, ?, ?)', userId, email, role);
  return c.json({ success: true, message: '成员已添加' });
});

app.delete('/api/team/:id', authMiddleware, async (c) => {
  const userId = c.get('userId');
  await dbRun(c.env, 'DELETE FROM team_members WHERE id = ? AND user_id = ?', c.req.param('id'), userId);
  return c.json({ success: true, message: '成员已移除' });
});

// ==================== Projects ====================

app.get('/api/projects', authMiddleware, async (c) => {
  const userId = c.get('userId');
  const rows = await dbAll(c.env, 'SELECT * FROM projects WHERE user_id = ? ORDER BY created_at DESC', userId);
  return c.json({ success: true, list: rows.map(p => ({
    id: p.id, name: p.name, slug: p.slug, framework: p.framework,
    projectType: p.project_type, method: p.method, source: p.source,
    url: p.url, customDomain: p.custom_domain, fileList: p.file_list,
    entryDir: p.entry_dir, entryFile: p.entry_file,
    createdAt: ts(p.created_at), lastDeploy: ts(p.last_deploy)
  })) });
});

app.get('/api/projects/:id', authMiddleware, async (c) => {
  const userId = c.get('userId');
  const p = await dbFirst(c.env, 'SELECT * FROM projects WHERE id = ? AND user_id = ?', c.req.param('id'), userId);
  if (!p) return c.json({ success: false, error: '项目不存在' }, 404);
  return c.json({ success: true, project: {
    id: p.id, name: p.name, slug: p.slug, framework: p.framework,
    projectType: p.project_type, method: p.method, source: p.source,
    url: p.url, customDomain: p.custom_domain, fileList: p.file_list,
    entryDir: p.entry_dir, entryFile: p.entry_file,
    createdAt: ts(p.created_at), lastDeploy: ts(p.last_deploy)
  } });
});

app.post('/api/deploy', authMiddleware, async (c) => {
  let body;
  try { body = await c.req.json(); } catch { return c.json({ success: false, error: '请求体格式错误' }, 400); }
  const userId = c.get('userId');
  const { name, files, framework = '静态文件', project_type = 'static', method = 'manual', source, url, custom_domain, entry_dir, entry_file } = body;

  if (!name || !files || !Array.isArray(files) || files.length === 0)
    return c.json({ success: false, error: '项目名称和文件不能为空' }, 400);

  const slugBase = name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '') || 'project';
  let slug = slugBase;
  let counter = 1;
  while (await dbFirst(c.env, 'SELECT id FROM projects WHERE slug = ?', slug)) {
    slug = slugBase + '-' + counter++;
  }

  const projectId = randomHex(12);
  await dbRun(c.env, 'INSERT INTO projects (id, user_id, name, slug, framework, project_type, method, source, url, custom_domain, file_list, entry_dir, entry_file, last_deploy) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime(\'now\'))',
    projectId, userId, name, slug, framework, project_type, method, source || null, url || null, custom_domain || null, JSON.stringify(files.map(f => f.name)), entry_dir || null, entry_file || null);

  await dbRun(c.env, 'DELETE FROM project_files WHERE project_slug = ?', slug);
  for (const f of files) {
    const content = f.content || '';
    const b64 = textToB64(content);
    await dbRun(c.env, 'INSERT INTO project_files (project_slug, filename, file_size, content) VALUES (?, ?, ?, ?) ON CONFLICT(project_slug, filename) DO UPDATE SET content = excluded.content, file_size = excluded.file_size, created_at = datetime(\'now\')',
      slug, f.name, content.length, b64);
  }

  return c.json({ success: true, slug, url: '/deployed/' + slug + '/', projectId, project_type: project_type, process: null });
});

app.put('/api/projects/:id', authMiddleware, async (c) => {
  let body;
  try { body = await c.req.json(); } catch { return c.json({ success: false, error: '请求体格式错误' }, 400); }
  const userId = c.get('userId');
  const { name, custom_domain, framework, entry_dir, entry_file } = body;
  const fields = [];
  const params = [];
  if (name) { fields.push('name = ?'); params.push(name); }
  if (custom_domain !== undefined) { fields.push('custom_domain = ?'); params.push(custom_domain); }
  if (framework) { fields.push('framework = ?'); params.push(framework); }
  if (entry_dir) { fields.push('entry_dir = ?'); params.push(entry_dir); }
  if (entry_file) { fields.push('entry_file = ?'); params.push(entry_file); }
  if (fields.length === 0) return c.json({ success: false, error: '没有要更新的字段' }, 400);
  params.push(c.req.param('id'), userId);
  await dbRun(c.env, 'UPDATE projects SET ' + fields.join(', ') + ' WHERE id = ? AND user_id = ?', ...params);
  return c.json({ success: true, message: '项目已更新' });
});

app.delete('/api/projects/:id', authMiddleware, async (c) => {
  const userId = c.get('userId');
  const p = await dbFirst(c.env, 'SELECT slug FROM projects WHERE id = ? AND user_id = ?', c.req.param('id'), userId);
  if (p) await dbRun(c.env, 'DELETE FROM project_files WHERE project_slug = ?', p.slug);
  await dbRun(c.env, 'DELETE FROM projects WHERE id = ? AND user_id = ?', c.req.param('id'), userId);
  return c.json({ success: true, message: '项目已删除' });
});

app.post('/api/sync', async (c) => {
  let token = (c.req.header('Authorization') || '').replace('Bearer ', '');
  const apiKey = c.req.header('X-API-Key');
  let userId = null;

  if (token) {
    const payload = await getTokenPayload(token);
    if (payload) userId = payload.userId;
  }
  if (!userId && apiKey) {
    const row = await dbFirst(c.env, 'SELECT user_id FROM api_tokens WHERE token = ? AND active = 1', apiKey);
    if (row) {
      userId = row.user_id;
      await dbRun(c.env, 'UPDATE api_tokens SET usage_count = usage_count + 1, last_used = datetime(\'now\') WHERE token = ?', apiKey);
    }
  }
  if (!userId) return c.json({ success: false, error: '未授权' }, 401);

  let body;
  try { body = await c.req.json(); } catch { return c.json({ success: false, error: '请求体格式错误' }, 400); }
  const { project, files } = body;
  if (!project || !files) return c.json({ success: false, error: '缺少 project 或 files' }, 400);

  const slugBase = project.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '') || 'project';
  let slug = slugBase;
  let counter = 1;
  while (await dbFirst(c.env, 'SELECT id FROM projects WHERE slug = ? AND user_id != ?', slug, userId)) {
    slug = slugBase + '-' + counter++;
  }

  const projectId = randomHex(12);
  await dbRun(c.env, 'INSERT INTO projects (id, user_id, name, slug, framework, project_type, method, source, file_list, last_deploy) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, datetime(\'now\'))',
    projectId, userId, project, slug, '静态文件', 'static', 'sync', 'api', JSON.stringify(files.map(f => f.name)));

  for (const f of files) {
    const content = f.content || '';
    const b64 = textToB64(content);
    await dbRun(c.env, 'INSERT INTO project_files (project_slug, filename, file_size, content) VALUES (?, ?, ?, ?) ON CONFLICT(project_slug, filename) DO UPDATE SET content = excluded.content, file_size = excluded.file_size',
      slug, f.name, content.length, b64);
  }

  return c.json({ success: true, slug, url: '/deployed/' + slug + '/' });
});

app.post('/api/auto-sync', authMiddleware, async (c) => {
  let body;
  try { body = await c.req.json(); } catch { return c.json({ success: false, error: '请求体格式错误' }, 400); }
  const userId = c.get('userId');
  const { project, files, name } = body;
  const projectName = name || project;
  if (!projectName || !files) return c.json({ success: false, error: '缺少项目名或文件' }, 400);

  const slugBase = projectName.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '') || 'project';
  let slug = slugBase;
  let counter = 1;
  while (await dbFirst(c.env, 'SELECT id FROM projects WHERE slug = ? AND user_id != ?', slug, userId)) {
    slug = slugBase + '-' + counter++;
  }

  const projectId = randomHex(12);
  await dbRun(c.env, 'INSERT INTO projects (id, user_id, name, slug, framework, project_type, method, source, file_list, last_deploy) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, datetime(\'now\'))',
    projectId, userId, projectName, slug, '静态文件', 'static', 'auto-sync', 'auto', JSON.stringify(files.map(f => f.name)));

  for (const f of files) {
    const content = f.content || '';
    const b64 = textToB64(content);
    await dbRun(c.env, 'INSERT INTO project_files (project_slug, filename, file_size, content) VALUES (?, ?, ?, ?) ON CONFLICT(project_slug, filename) DO UPDATE SET content = excluded.content, file_size = excluded.file_size',
      slug, f.name, content.length, b64);
  }

  return c.json({ success: true, slug, url: '/deployed/' + slug + '/', projectId });
});

app.get('/api/files/:project/:filename', async (c) => {
  const slug = c.req.param('project');
  let filename = c.req.param('filename');
  const rows = await dbAll(c.env, 'SELECT content FROM project_files WHERE project_slug = ? AND filename = ?', slug, filename);
  if (rows.length === 0) return c.json({ success: false, error: '文件不存在' }, 404);
  return c.json({ success: true, content: b64ToText(rows[0].content) });
});

// ==================== API Tokens ====================

app.get('/api/tokens', authMiddleware, async (c) => {
  const userId = c.get('userId');
  const rows = await dbAll(c.env, 'SELECT * FROM api_tokens WHERE user_id = ? ORDER BY created_at DESC', userId);
  return c.json({ success: true, list: rows.map(t => ({ ...t, created_at: ts(t.created_at), last_used: ts(t.last_used) })) });
});

app.post('/api/tokens', authMiddleware, async (c) => {
  let body;
  try { body = await c.req.json(); } catch { return c.json({ success: false, error: '请求体格式错误' }, 400); }
  const userId = c.get('userId');
  const { name } = body;
  if (!name) return c.json({ success: false, error: 'Token 名称不能为空' }, 400);
  const tokenId = randomHex(8);
  const tokenStr = 'df_' + randomHex(24);
  await dbRun(c.env, 'INSERT INTO api_tokens (id, user_id, name, token, scope) VALUES (?, ?, ?, ?, ?)', tokenId, userId, name, tokenStr, 'sync');
  return c.json({ success: true, token: { id: tokenId, name, token: tokenStr, scope: 'sync' } });
});

app.delete('/api/tokens/:id', authMiddleware, async (c) => {
  const userId = c.get('userId');
  await dbRun(c.env, 'DELETE FROM api_tokens WHERE id = ? AND user_id = ?', c.req.param('id'), userId);
  return c.json({ success: true, message: 'Token 已删除' });
});

// ==================== Domains ====================

app.post('/api/domains', authMiddleware, async (c) => {
  let body;
  try { body = await c.req.json(); } catch { return c.json({ success: false, error: '请求体格式错误' }, 400); }
  const userId = c.get('userId');
  const { domain, project_slug } = body;
  if (!domain || !project_slug) return c.json({ success: false, error: '域名和项目不能为空' }, 400);
  const existing = await dbFirst(c.env, 'SELECT id FROM domains WHERE domain = ?', domain);
  if (existing) return c.json({ success: false, error: '该域名已被绑定' }, 400);
  await dbRun(c.env, 'INSERT INTO domains (domain, project_slug, user_id) VALUES (?, ?, ?)', domain, project_slug, userId);
  return c.json({ success: true, message: '域名绑定成功（Pages 环境下需在 Cloudflare Dashboard 配置 Custom Domain 路由）' });
});

// ==================== Databases ====================

app.get('/api/databases', authMiddleware, async (c) => {
  const userId = c.get('userId');
  const rows = await dbAll(c.env, 'SELECT * FROM user_databases WHERE user_id = ? ORDER BY created_at DESC', userId);
  return c.json({ success: true, list: rows.map(d => ({ ...d, created_at: ts(d.created_at) })) });
});

app.post('/api/databases', authMiddleware, async (c) => {
  let body;
  try { body = await c.req.json(); } catch { return c.json({ success: false, error: '请求体格式错误' }, 400); }
  const userId = c.get('userId');
  const { display_name } = body;
  if (!display_name) return c.json({ success: false, error: '数据库名称不能为空' }, 400);

  const cleanName = display_name.toLowerCase().replace(/[^a-z0-9_]/g, '_');
  const realName = 'df_u' + userId + '_' + cleanName;
  const dbUser = realName + '_user';
  const dbPass = randomHex(16);

  const existing = await dbFirst(c.env, 'SELECT id FROM user_databases WHERE real_name = ?', realName);
  if (existing) return c.json({ success: false, error: '数据库已存在' }, 400);

  await dbRun(c.env, 'INSERT INTO user_databases (user_id, display_name, real_name, db_user, db_password) VALUES (?, ?, ?, ?, ?)', userId, display_name, realName, dbUser, dbPass);

  const tables = await dbAll(c.env, "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' AND name NOT LIKE 'df_%' ORDER BY name");

  return c.json({ success: true, database: { display_name, real_name: realName, db_user: dbUser, db_password: dbPass, tables: tables.map(t => t.name), type: 'SQLite (D1)' } });
});

app.delete('/api/databases/:id', authMiddleware, async (c) => {
  const userId = c.get('userId');
  await dbRun(c.env, 'DELETE FROM user_databases WHERE id = ? AND user_id = ?', c.req.param('id'), userId);
  return c.json({ success: true, message: '数据库记录已删除（D1 为共享数据库，实际表未删除）' });
});

app.get('/api/databases/:id/tables', authMiddleware, async (c) => {
  const userId = c.get('userId');
  const dbRecord = await dbFirst(c.env, 'SELECT * FROM user_databases WHERE id = ? AND user_id = ?', c.req.param('id'), userId);
  if (!dbRecord) return c.json({ success: false, error: '数据库不存在' }, 404);
  const tables = await dbAll(c.env, "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' AND name NOT LIKE 'df_%' ORDER BY name");
  return c.json({ success: true, tables: tables.map(t => t.name) });
});

app.post('/api/databases/:id/query', authMiddleware, async (c) => {
  let body;
  try { body = await c.req.json(); } catch { return c.json({ success: false, error: '请求体格式错误' }, 400); }
  const userId = c.get('userId');
  const dbRecord = await dbFirst(c.env, 'SELECT * FROM user_databases WHERE id = ? AND user_id = ?', c.req.param('id'), userId);
  if (!dbRecord) return c.json({ success: false, error: '数据库不存在' }, 404);

  const { sql } = body;
  if (!sql || !sql.trim()) return c.json({ success: false, error: 'SQL 不能为空' }, 400);

  const sqlUpper = sql.trim().toUpperCase();
  const isSelect = sqlUpper.startsWith('SELECT') || sqlUpper.startsWith('WITH') || sqlUpper.startsWith('PRAGMA');

  try {
    if (isSelect) {
      const result = await c.env.DB.prepare(sql.trim()).all();
      return c.json({ success: true, data: result.results || [], changes: 0 });
    } else {
      const result = await c.env.DB.prepare(sql.trim()).run();
      return c.json({ success: true, data: [], changes: result.meta ? result.meta.changes : 0 });
    }
  } catch (err) {
    return c.json({ success: false, error: 'SQL 执行错误: ' + err.message }, 400);
  }
});

app.get('/api/databases/:id/connection', authMiddleware, async (c) => {
  const userId = c.get('userId');
  const dbRecord = await dbFirst(c.env, 'SELECT * FROM user_databases WHERE id = ? AND user_id = ?', c.req.param('id'), userId);
  if (!dbRecord) return c.json({ success: false, error: '数据库不存在' }, 404);
  return c.json({ success: true, connection: {
    type: 'SQLite (D1)',
    database: dbRecord.real_name,
    username: dbRecord.db_user,
    password: dbRecord.db_password,
    host: 'cloudflare-d1',
    note: 'D1 为共享 SQLite 数据库，以上为逻辑隔离标识。实际连接请通过 DeployFlow API 执行 SQL。'
  } });
});

app.delete('/api/databases/:id/tables/:tableName', authMiddleware, async (c) => {
  const userId = c.get('userId');
  const dbRecord = await dbFirst(c.env, 'SELECT * FROM user_databases WHERE id = ? AND user_id = ?', c.req.param('id'), userId);
  if (!dbRecord) return c.json({ success: false, error: '数据库不存在' }, 404);
  const tableName = c.req.param('tableName').replace(/[^a-zA-Z0-9_]/g, '');
  await dbRun(c.env, 'DROP TABLE IF EXISTS ' + tableName);
  return c.json({ success: true, message: '表已删除' });
});

// ==================== Processes (Limited on Pages) ====================

app.post('/api/processes/:slug/start', authMiddleware, (c) => {
  return c.json({ success: false, error: 'Pages 环境不支持运行动态后端进程。仅支持静态文件部署。' }, 501);
});

app.post('/api/processes/:slug/stop', authMiddleware, (c) => {
  return c.json({ success: false, error: 'Pages 环境不支持运行动态后端进程。' }, 501);
});

app.post('/api/processes/:slug/restart', authMiddleware, (c) => {
  return c.json({ success: false, error: 'Pages 环境不支持运行动态后端进程。' }, 501);
});

app.get('/api/processes/:slug/status', authMiddleware, (c) => {
  return c.json({ success: true, status: 'static', message: 'Pages 环境仅支持静态部署，无独立进程' });
});

app.get('/api/processes/:slug/logs', authMiddleware, (c) => {
  return c.json({ success: true, logs: 'Pages 环境无运行时日志。' });
});

// ==================== Guestbook ====================

app.get('/api/guestbook', async (c) => {
  const rows = await dbAll(c.env, 'SELECT g.*, u.name as user_name, u.avatar as user_avatar FROM guestbook g LEFT JOIN users u ON g.user_id = u.id ORDER BY g.created_at DESC LIMIT 100');
  return c.json({ success: true, list: rows.map(g => ({ id: g.id, user_id: g.user_id, username: g.username, content: g.content, parent_id: g.parent_id, user_name: g.user_name, user_avatar: g.user_avatar, created_at: ts(g.created_at) })) });
});

app.post('/api/guestbook', authMiddleware, async (c) => {
  let body;
  try { body = await c.req.json(); } catch { return c.json({ success: false, error: '请求体格式错误' }, 400); }
  const userId = c.get('userId');
  const user = c.get('user');
  const { content, parent_id } = body;
  if (!content || !content.trim()) return c.json({ success: false, error: '留言内容不能为空' }, 400);
  await dbRun(c.env, 'INSERT INTO guestbook (user_id, username, content, parent_id) VALUES (?, ?, ?, ?)', userId, user.name || '匿名用户', content.trim(), parent_id || null);
  return c.json({ success: true, message: '留言成功' });
});

app.delete('/api/guestbook/:id', authMiddleware, async (c) => {
  const userId = c.get('userId');
  await dbRun(c.env, 'DELETE FROM guestbook WHERE id = ? AND user_id = ?', c.req.param('id'), userId);
  return c.json({ success: true, message: '留言已删除' });
});

// ==================== Deployed Files Serving ====================

app.all('/deployed/*', async (c) => {
  const path = c.req.path;
  const rest = path.substring('/deployed/'.length);
  const slashIdx = rest.indexOf('/');
  const slug = slashIdx === -1 ? rest : rest.substring(0, slashIdx);
  let filename = slashIdx === -1 ? '' : rest.substring(slashIdx + 1);

  if (!filename || filename.endsWith('/')) filename += 'index.html';

  let rows = await dbAll(c.env, 'SELECT content FROM project_files WHERE project_slug = ? AND filename = ?', slug, filename);
  if (rows.length === 0) {
    rows = await dbAll(c.env, 'SELECT content FROM project_files WHERE project_slug = ? AND filename = ?', slug, 'index.html');
    if (rows.length === 0) return c.text('Not Found: ' + slug + '/' + filename, 404);
    return new Response(b64ToBytes(rows[0].content), { headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'public, max-age=0' } });
  }

  return new Response(b64ToBytes(rows[0].content), { headers: { 'Content-Type': getContentType(filename), 'Cache-Control': 'public, max-age=0' } });
});

// ==================== Error Handler ====================

app.onError((err, c) => {
  console.error('Unhandled error:', err);
  return c.json({ success: false, error: err.message || '服务器内部错误' }, 500);
});

export const onRequest = handle(app);
