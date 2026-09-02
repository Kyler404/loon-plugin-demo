/* =============================================================================
 * Loon Plugin Studio
 * -----------------------------------------------------------------------------
 * 语法依据（Loon 官方文档）：
 *   插件元信息：#!name / #!desc / #!icon / #!author / #!homepage / #!tag / #!system
 *   插件可用区块：[Rule] / [URL Rewrite] / [Script] / [MITM]
 *   MITM：        hostname = a.com, b.com        （逗号分隔，单行）
 *   逻辑规则：    AND,((子规则),(子规则)),策略    （子规则不带策略；NOT 只接受 1 个）
 *   插件策略限制：DIRECT / PROXY / REJECT 系列
 *   脚本参数：    script-path=, requires-body=, timeout=, tag=, enable=, argument=
 * ========================================================================== */
'use strict';

/* ========================= 常量 ========================= */

const STORE_KEY = 'loon-plugin-studio.v1';
const UI_STORE_KEY = 'loon-plugin-studio.ui.v1';

/** 规则类型 */
const RULE_TYPES = [
  'DOMAIN',
  'DOMAIN-SUFFIX',
  'DOMAIN-KEYWORD',
  'DOMAIN-REGEX',
  'USER-AGENT',
  'URL-REGEX',
  'IP-CIDR',
  'IP-CIDR6',
  'IP-ASN',
  'GEOIP',
  'PROTOCOL',
  'DEST-PORT',
  'SRC-PORT',
  'AND',
  'OR',
  'NOT'
];

/** 插件内允许的策略（Loon 限制：DIRECT / PROXY / REJECT 系列） */
const POLICIES = [
  { v: 'DIRECT', label: 'DIRECT · 直连' },
  { v: 'PROXY', label: 'PROXY · 用户指定策略组' },
  { v: 'REJECT', label: 'REJECT · 拒绝' },
  { v: 'REJECT-DROP', label: 'REJECT-DROP · 丢弃连接' },
  { v: 'REJECT-NO-DROP', label: 'REJECT-NO-DROP' },
  { v: 'REJECT-IMG', label: 'REJECT-IMG · 1px 图片' },
  { v: 'REJECT-IMG-NO-DROP', label: 'REJECT-IMG-NO-DROP' },
  { v: 'REJECT-VIDEO', label: 'REJECT-VIDEO · 空白视频' },
  { v: 'REJECT-VIDEO-NO-DROP', label: 'REJECT-VIDEO-NO-DROP' },
  { v: 'REJECT-DICT', label: 'REJECT-DICT · 空 JSON' },
  { v: 'REJECT-DICT-NO-DROP', label: 'REJECT-DICT-NO-DROP' },
  { v: 'REJECT-ARRAY', label: 'REJECT-ARRAY · 空数组' },
  { v: 'REJECT-ARRAY-NO-DROP', label: 'REJECT-ARRAY-NO-DROP' }
];
const POLICY_SET = new Set(POLICIES.map((p) => p.v));

/** 脚本类型 */
const SCRIPT_TYPES = [
  { v: 'http-response', label: 'http-response · 响应返回后', match: '匹配 URL 正则', body: true },
  { v: 'http-request', label: 'http-request · 请求发出前', match: '匹配 URL 正则', body: true },
  { v: 'cron', label: 'cron · 定时执行', match: 'Cron 表达式', body: false },
  { v: 'network-changed', label: 'network-changed · 网络变化', match: '', body: false },
  { v: 'generic', label: 'generic · 手动触发', match: '', body: false }
];

/** 复写类型 */
const REWRITE_TYPES = [
  { v: '302', label: '302 临时重定向', target: true },
  { v: '301', label: '301 永久重定向', target: true },
  { v: '307', label: '307 重定向', target: true },
  { v: '308', label: '308 重定向', target: true },
  { v: 'header', label: 'header · 仅改 URL 不跳转', target: true },
  { v: 'reject', label: 'reject · 断开连接', target: false },
  { v: 'reject-200', label: 'reject-200 · 空响应体', target: false },
  { v: 'reject-img', label: 'reject-img · 1px 图片', target: false },
  { v: 'reject-dict', label: 'reject-dict · {}', target: false },
  { v: 'reject-array', label: 'reject-array · []', target: false }
];

/** 区块元信息 */
const BLOCK_META = {
  details: { title: '详情', desc: '#!name / #!desc / #!icon 等元信息', badge: '信息' },
  hostnames: { title: '主机名', desc: '[MITM] 需要解密的主机名', badge: 'MITM' },
  rules: { title: '规则', desc: '[Rule] 分流 / 拦截策略', badge: '规则' },
  rewrite: { title: '复写', desc: '[URL Rewrite] 重定向与改写', badge: '复写' },
  script: { title: '脚本', desc: '[Script] 挂载 JS 脚本', badge: 'JS' }
};

/** 区块默认数据 */
const BLOCK_TEMPLATES = {
  details: {
    type: 'details',
    data: {
      desc: '一个用于演示的 Loon 插件',
      author: 'kyler404',
      homepage: 'https://github.com/kyler404/loon-plugin-demo',
      tag: 'Proxy',
      system: 'iOS,iPadOS,tvOS,macOS',
      icon: 'https://raw.githubusercontent.com/kyler404/loon-plugin-demo/main/assets/icon.png'
    }
  },
  hostnames: {
    type: 'hostnames',
    data: { hosts: 'api.example.com\napi2.example.com' }
  },
  rules: {
    type: 'rules',
    data: {
      root: {
        conditions: [
          { type: 'DOMAIN-SUFFIX', value: 'example.com', policy: 'DIRECT' },
          { type: 'AND', value: '', policy: 'REJECT', children: [
            { type: 'DOMAIN-KEYWORD', value: 'ads', policy: 'DIRECT' },
            { type: 'USER-AGENT', value: '*AdBot*', policy: 'DIRECT' }
          ] }
        ]
      }
    }
  },
  rewrite: {
    type: 'rewrite',
    data: {
      list: [{ from: '^https?:\\/\\/(www\\.)?example\\.cn\\/path', to: 'https://example.com/path', type: '302' }]
    }
  },
  script: {
    type: 'script',
    data: {
      scriptType: 'http-response',
      match: '^https?:\\/\\/api\\.example\\.com\\/v1\\/user',
      tag: 'DemoUser',
      file: 'demo.js',
      path: 'https://raw.githubusercontent.com/kyler404/loon-plugin-demo/main/scripts/demo.js',
      timeout: '10',
      requiresBody: 'true',
      enable: 'true',
      code: [
        'const body = JSON.parse($response.body || "{}");',
        '',
        'if (!body || typeof body !== "object") {',
        '  $done({});',
        '} else {',
        '  body.data = body.data || {};',
        '  body.data.demo = true;',
        '  body.data.message = "Hello from Loon Plugin Studio";',
        '  $done({ status: 200, body: JSON.stringify(body) });',
        '}'
      ].join('\n')
    }
  }
};

/* ========================= 状态 ========================= */

const state = {
  plugins: [],
  selectedId: null,
  tab: 'plugin',
  rewriteSyntax: 'url-rewrite', // url-rewrite | rewrite
  dragId: null,
  /* 界面偏好：collapsed=预览面板折叠；sideCollapsed=侧栏折叠；w/h 分别记住宽屏与窄屏下的预览尺寸 */
  ui: { collapsed: false, sideCollapsed: false, w: 420, h: 320 },
  view: { text: '', scripts: [], issues: [] }
};

/** 预览面板最小/最大尺寸（px） */
const PREVIEW_MIN = 180;
const PREVIEW_MAX_RATIO = 0.75;

/* ========================= 工具 ========================= */

const $ = (sel) => document.querySelector(sel);

const ICONS = {
  grip: '<svg class="icon" aria-hidden="true" viewBox="0 0 24 24"><circle cx="9" cy="6" r="1"/><circle cx="15" cy="6" r="1"/><circle cx="9" cy="12" r="1"/><circle cx="15" cy="12" r="1"/><circle cx="9" cy="18" r="1"/><circle cx="15" cy="18" r="1"/></svg>',
  chevronUp: '<svg class="icon" aria-hidden="true" viewBox="0 0 24 24"><path d="m18 15-6-6-6 6"/></svg>',
  chevronDown: '<svg class="icon" aria-hidden="true" viewBox="0 0 24 24"><path d="m6 9 6 6 6-6"/></svg>',
  up: '<svg class="icon" aria-hidden="true" viewBox="0 0 24 24"><path d="m12 19V5m0 0-5 5m5-5 5 5"/></svg>',
  down: '<svg class="icon" aria-hidden="true" viewBox="0 0 24 24"><path d="M12 5v14m0 0 5-5m-5 5-5-5"/></svg>',
  copy: '<svg class="icon" aria-hidden="true" viewBox="0 0 24 24"><rect x="9" y="9" width="11" height="11" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>',
  more: '<svg class="icon" aria-hidden="true" viewBox="0 0 24 24"><circle cx="5" cy="12" r="1"/><circle cx="12" cy="12" r="1"/><circle cx="19" cy="12" r="1"/></svg>',
  trash: '<svg class="icon" aria-hidden="true" viewBox="0 0 24 24"><path d="M4 7h16M10 11v6m4-6v6M9 7l1-3h4l1 3m-9 0 1 13h10l1-13"/></svg>',
  alert: '<svg class="icon" aria-hidden="true" viewBox="0 0 24 24"><path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><path d="M12 9v4m0 4h.01"/></svg>',
  check: '<svg class="icon" aria-hidden="true" viewBox="0 0 24 24"><path d="m20 6-11 11-5-5"/></svg>',
  info: '<svg class="icon" aria-hidden="true" viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="M12 11v5m0-8h.01"/></svg>',
  xCircle: '<svg class="icon" aria-hidden="true" viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="m15 9-6 6m0-6 6 6"/></svg>'
};

/* Toast 状态分级：图标 + 语义类名 */
const TOAST_LEVELS = {
  info: { icon: ICONS.info, cls: 'is-info' },
  success: { icon: ICONS.check, cls: 'is-success' },
  warn: { icon: ICONS.alert, cls: 'is-warn' },
  error: { icon: ICONS.xCircle, cls: 'is-error' }
};

function uid() {
  if (window.crypto && typeof crypto.randomUUID === 'function') return crypto.randomUUID();
  return `id-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`;
}

function escapeHtml(value) {
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

function isLogical(type) {
  return type === 'AND' || type === 'OR' || type === 'NOT';
}

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

function currentPlugin() {
  return state.plugins.find((p) => p.id === state.selectedId) || state.plugins[0];
}

function getBlock(blockId) {
  const plugin = currentPlugin();
  return plugin ? plugin.blocks.find((b) => b.id === blockId) : null;
}

function blocksOfType(type) {
  const plugin = currentPlugin();
  return plugin ? plugin.blocks.filter((b) => b.type === type) : [];
}

function optionsHtml(list, selected, fallbackLabel) {
  return list
    .map((item) => {
      const value = typeof item === 'string' ? item : item.v;
      const label = typeof item === 'string' ? item : item.label || item.v;
      const isSel = value === selected ? ' selected' : '';
      return `<option value="${escapeHtml(value)}"${isSel}>${escapeHtml(label)}</option>`;
    })
    .join('');
}

/* ========================= DOM 引用 ========================= */

const el = {
  pluginList: $('#pluginList'),
  pluginCount: $('#pluginCount'),
  nameInput: $('#nameInput'),
  blockCount: $('#blockCount'),
  statusHint: $('#statusHint'),
  canvas: $('#builderCanvas'),
  palette: $('#blockPalette'),
  addBlockBtn: $('#addBlockBtn'),
  newPluginBtn: $('#newPluginBtn'),
  resetBtn: $('#resetBtn'),
  copyBtn: $('#copyBtn'),
  exportBtn: $('#exportBtn'),
  exportLabel: $('#exportLabel'),
  tabs: $('#tabs'),
  codePreview: $('#codePreview'),
  issuesPanel: $('#issuesPanel'),
  issueCount: $('#issueCount'),
  rewriteSyntax: $('#rewriteSyntax'),
  saveHint: $('#saveHint'),
  toast: $('#toast'),
  /* 面板折叠 */
  app: $('#app'),
  sidebar: $('#sidebar'),
  sidebarToggle: $('#sidebarToggle'),
  sidebarExpand: $('#sidebarExpand'),
  preview: $('#preview'),
  previewFoot: $('#previewFoot'),
  previewToggle: $('#previewToggle'),
  previewExpand: $('#previewExpand'),
  previewResizer: $('#previewResizer')
};

/* ========================= 持久化 ========================= */

let saveTimer = null;

/* 界面偏好（预览面板折叠状态 / 尺寸）单独存，不混进插件数据 */
function saveUi() {
  try {
    localStorage.setItem(UI_STORE_KEY, JSON.stringify(state.ui));
  } catch (err) {
    /* 存不下就算了，不该因为记不住布局打断编辑 */
  }
}

function loadUi() {
  try {
    const parsed = JSON.parse(localStorage.getItem(UI_STORE_KEY) || 'null');
    if (!parsed || typeof parsed !== 'object') return;
    state.ui.collapsed = !!parsed.collapsed;
    state.ui.sideCollapsed = !!parsed.sideCollapsed;
    if (Number(parsed.w) >= PREVIEW_MIN) state.ui.w = Math.round(Number(parsed.w));
    if (Number(parsed.h) >= PREVIEW_MIN) state.ui.h = Math.round(Number(parsed.h));
  } catch (err) {
    /* 忽略损坏的偏好，用默认值 */
  }
}

function scheduleSave() {
  window.clearTimeout(saveTimer);
  saveTimer = window.setTimeout(() => {
    try {
      localStorage.setItem(
        STORE_KEY,
        JSON.stringify({
          plugins: state.plugins,
          selectedId: state.selectedId,
          rewriteSyntax: state.rewriteSyntax
        })
      );
      const time = new Date().toLocaleTimeString('zh-CN', { hour12: false });
      el.saveHint.textContent = `已自动保存 · ${time}`;
    } catch (err) {
      el.saveHint.textContent = '本地保存失败（存储空间不足？）';
    }
  }, 450);
}

function loadState() {
  let raw = null;
  try {
    raw = localStorage.getItem(STORE_KEY);
  } catch (err) {
    raw = null;
  }
  if (raw) {
    try {
      const parsed = JSON.parse(raw);
      if (Array.isArray(parsed.plugins) && parsed.plugins.length) {
        state.plugins = parsed.plugins.filter((p) => p && Array.isArray(p.blocks));
        state.selectedId = parsed.selectedId;
        if (parsed.rewriteSyntax) state.rewriteSyntax = parsed.rewriteSyntax;
      }
    } catch (err) {
      console.warn('无法解析本地草稿，已回退到示例插件', err);
    }
  }
  if (!state.plugins.length) {
    state.plugins = [createDemoPlugin()];
    state.selectedId = null;
  }
  if (!state.plugins.some((p) => p.id === state.selectedId)) {
    state.selectedId = state.plugins[0].id;
  }
  state.plugins.forEach((p) => p.blocks.forEach((b) => {
    if (!b.id) b.id = uid();
  }));
}

/* ========================= 插件 / 区块操作 ========================= */

function createDemoPlugin() {
  return {
    id: uid(),
    name: 'Demo Plugin',
    blocks: ['details', 'hostnames', 'rules', 'rewrite', 'script'].map((type) =>
      Object.assign({ id: uid() }, clone(BLOCK_TEMPLATES[type]))
    )
  };
}

function createPlugin(name) {
  return {
    id: uid(),
    name,
    blocks: [Object.assign({ id: uid() }, clone(BLOCK_TEMPLATES.details))]
  };
}

function addBlock(type) {
  if (!BLOCK_TEMPLATES[type]) return;
  const plugin = currentPlugin();
  if (!plugin) return;
  plugin.blocks.push(Object.assign({ id: uid() }, clone(BLOCK_TEMPLATES[type])));
  renderCanvas();
  renderPreview();
  updateChrome();
  scheduleSave();
  toast(`已添加「${BLOCK_META[type].title}」区块`, 'success');
}

/* ========================= 规则树操作 ========================= */

function createCondition(type = 'DOMAIN-SUFFIX') {
  const cond = { type, value: isLogical(type) ? '' : 'example.com', policy: 'DIRECT', children: [] };
  if (isLogical(type)) {
    cond.children = [{ type: 'DOMAIN-SUFFIX', value: 'example.com', policy: 'DIRECT', children: [] }];
  }
  return cond;
}

function resolveCondition(root, path) {
  if (!root) return null;
  if (!path || path === 'root') return root;
  let current = root;
  for (const index of String(path).split('.').filter(Boolean).map(Number)) {
    const list = current.conditions || current.children || [];
    current = list[index];
    if (!current) return null;
  }
  return current;
}

function removeConditionAt(root, path) {
  const segments = String(path).split('.').filter(Boolean).map(Number);
  if (!segments.length) return;
  let current = root;
  for (let i = 0; i < segments.length - 1; i += 1) {
    const list = current.conditions || current.children || [];
    current = list[segments[i]];
    if (!current) return;
  }
  const list = current.conditions || current.children || [];
  list.splice(segments[segments.length - 1], 1);
}

/* ========================= 生成器 ========================= */

/**
 * 生成插件文本 + 脚本文件 + 语法问题清单。
 * 这里是整个项目最容易出错的地方，所有规则都按官方文档序列化。
 */
function buildOutput() {
  const plugin = currentPlugin();
  const issues = [];
  const add = (level, msg, blockId) => issues.push({ level, msg, blockId });
  const lines = [];
  const scripts = [];

  if (!plugin) return { text: '', scripts: [], issues: [] };

  /* ---------- 元信息 ---------- */
  const detailsBlocks = blocksOfType('details');
  const d = detailsBlocks.length ? detailsBlocks[0].data : {};
  if (detailsBlocks.length > 1) {
    add('warn', `有 ${detailsBlocks.length} 个「详情」区块，只有第一个会生效，其余会被忽略。`, detailsBlocks[1].id);
  }
  if (!detailsBlocks.length) {
    add('warn', '没有「详情」区块，插件缺少 #!desc / #!icon 等元信息（#!name 仍会使用上方插件名）。');
  }

  const name = (plugin.name || '').trim();
  if (!name) add('error', '插件名称为空。<code>#!name</code> 是 Loon 插件的必需字段。');

  lines.push(`#!name=${name || 'Untitled Plugin'}`);
  lines.push(`#!desc=${(d.desc || '').trim() || 'Loon plugin'}`);

  const icon = (d.icon || '').trim();
  if (icon) lines.push(`#!icon=${icon}`);
  else add('warn', '未填写 <code>#!icon</code>，Loon 的插件列表会显示默认图标。', detailsBlocks[0] && detailsBlocks[0].id);

  const author = (d.author || '').trim();
  if (author) lines.push(`#!author=${author}`);

  const homepage = (d.homepage || '').trim();
  if (homepage) {
    if (/^https?:\/\//i.test(homepage)) lines.push(`#!homepage=${homepage}`);
    else add('warn', `<code>#!homepage</code> 需要以 http:// 或 https:// 开头，已跳过。`, detailsBlocks[0] && detailsBlocks[0].id);
  }

  const tag = (d.tag || '').trim();
  if (tag) lines.push(`#!tag=${tag}`);

  const system = (d.system || '').trim();
  if (system) lines.push(`#!system=${system}`);

  lines.push('');

  /* ---------- [Rule] ---------- */
  const ruleLines = [];
  blocksOfType('rules').forEach((block) => {
    const root = block.data.root || { conditions: [] };
    const conditions = root.conditions || [];
    if (!conditions.length) add('warn', '「规则」区块里还没有规则，<code>[Rule]</code> 会被跳过。', block.id);
    conditions.forEach((cond) => {
      const line = serializeCondition(cond, true, add, block.id);
      if (line) ruleLines.push(line);
    });
  });
  if (ruleLines.length) {
    lines.push('[Rule]');
    ruleLines.forEach((line) => lines.push(line));
    lines.push('');
  }

  /* ---------- [URL Rewrite] / [Rewrite] ---------- */
  const rewriteSection = state.rewriteSyntax === 'rewrite' ? '[Rewrite]' : '[URL Rewrite]';
  const rewriteLines = [];
  blocksOfType('rewrite').forEach((block) => {
    (block.data.list || []).forEach((item) => {
      const line = serializeRewrite(item, add, block.id);
      if (line) rewriteLines.push(line);
    });
  });
  if (rewriteLines.length) {
    lines.push(rewriteSection);
    rewriteLines.forEach((line) => lines.push(line));
    lines.push('');
  }

  /* ---------- [Script] ---------- */
  const scriptLines = [];
  blocksOfType('script').forEach((block) => {
    const line = serializeScript(block.data, add, block.id);
    if (line) scriptLines.push(line);
    const code = (block.data.code || '').trim();
    if (code) {
      scripts.push({
        file: (block.data.file || 'script.js').trim() || 'script.js',
        tag: (block.data.tag || '').trim(),
        code
      });
    }
  });
  if (scriptLines.length) {
    lines.push('[Script]');
    scriptLines.forEach((line) => lines.push(line));
    lines.push('');
  }

  /* ---------- [MITM] ---------- */
  const hosts = [];
  blocksOfType('hostnames').forEach((block) => {
    String(block.data.hosts || '')
      .split(/[\n,，;；\s]+/)
      .map((item) => item.trim())
      .filter(Boolean)
      .forEach((host) => {
        if (/^https?:\/\//i.test(host)) {
          add('warn', `主机名 <code>${escapeHtml(host)}</code> 不该带协议头，只要写域名（可用 <code>*.example.com</code>）。`, block.id);
          return;
        }
        if (!/^[\w.*-]+$/.test(host)) {
          add('warn', `主机名 <code>${escapeHtml(host)}</code> 含非法字符，已跳过。`, block.id);
          return;
        }
        if (!hosts.includes(host)) hosts.push(host);
      });
  });
  if (hosts.length) {
    lines.push('[MITM]');
    lines.push(`hostname = ${hosts.join(', ')}`);
    lines.push('');
  }

  const needMitm =
    blocksOfType('script').some((b) => /^http-(request|response)$/.test(b.data.scriptType || '')) ||
    rewriteLines.length > 0;
  if (needMitm && !hosts.length) {
    add('warn', '脚本要改写 HTTPS 内容 / 复写要生效，必须配置 <code>[MITM]</code> 主机名，否则不会被执行。');
  }
  if (hosts.length && !needMitm) {
    add('warn', '配置了 <code>[MITM]</code> 主机名，但插件没有需要解密的脚本或复写，通常可以去掉。');
  }

  if (!plugin.blocks.length) add('warn', '还没有任何区块，点右上角「添加区块」开始组装插件。');

  while (lines.length && lines[lines.length - 1] === '') lines.pop();

  return { text: lines.join('\n') + '\n', scripts, issues };
}

/** 序列化单条规则；withPolicy=false 时用于逻辑规则的子规则（子规则不能带策略） */
function serializeCondition(cond, withPolicy, add, blockId) {
  if (!cond) return null;
  const type = (cond.type || 'DOMAIN-SUFFIX').trim();
  const value = (cond.value || '').trim();
  let policy = (cond.policy || 'DIRECT').trim();

  if (withPolicy && !POLICY_SET.has(policy)) {
    add('error', `策略 <code>${escapeHtml(policy)}</code> 在插件中不受支持（只能用 DIRECT / PROXY / REJECT 系列），已回退为 DIRECT。`, blockId);
    policy = 'DIRECT';
  }

  if (isLogical(type)) {
    const children = (cond.children || [])
      .map((child) => {
        const inner = serializeCondition(child, false, add, blockId);
        return inner ? `(${inner})` : null;
      })
      .filter(Boolean);

    if (!children.length) {
      add('error', `逻辑规则 <code>${type}</code> 没有子规则，该行不会生成。`, blockId);
      return null;
    }
    if (type === 'NOT' && children.length > 1) {
      add('warn', `<code>NOT</code> 只接受一个子规则，多余的已被忽略（当前 ${children.length} 个）。`, blockId);
      return `${type},(${children[0]})${withPolicy ? `,${policy}` : ''}`;
    }
    return `${type},(${children.join(',')})${withPolicy ? `,${policy}` : ''}`;
  }

  if (!value) {
    add('error', `规则 <code>${escapeHtml(type)}</code> 的条件值为空，该行不会生成。`, blockId);
    return null;
  }
  return `${type},${value}${withPolicy ? `,${policy}` : ''}`;
}

/** 序列化复写条目：[URL Rewrite] 为 pattern target type，[Rewrite] 为 pattern type target */
function serializeRewrite(item, add, blockId) {
  const pattern = (item.from || '').trim();
  const target = (item.to || '').trim();
  const type = (item.type || '302').trim();
  const meta = REWRITE_TYPES.find((t) => t.v === type) || { v: type, target: true };

  if (!pattern) {
    add('error', '复写缺少匹配正则，该行不会生成。', blockId);
    return null;
  }
  if (meta.target && !target) {
    add('error', `复写类型 <code>${escapeHtml(type)}</code> 需要目标地址。`, blockId);
    return null;
  }

  const parts = meta.target
    ? state.rewriteSyntax === 'rewrite'
      ? [pattern, type, target]
      : [pattern, target, type]
    : [pattern, type];
  return parts.join(' ');
}

/** 序列化脚本条目 */
function serializeScript(data, add, blockId) {
  const type = (data.scriptType || 'http-response').trim();
  const meta = SCRIPT_TYPES.find((s) => s.v === type) || { v: type, match: '', body: false };
  const path = (data.path || '').trim();
  const match = (data.match || '').trim();
  const params = [];

  if (!path) {
    add('error', '脚本缺少 <code>script-path</code>，Loon 无法加载脚本，该行不会生成。', blockId);
    return null;
  }
  if (meta.match && !match) {
    add('error', `${type} 脚本缺少${type === 'cron' ? ' Cron 表达式' : '匹配 URL 正则'}，该行不会生成。`, blockId);
    return null;
  }
  if (type === 'cron') {
    const fields = match.replace(/^["']|["']$/g, '').trim().split(/\s+/);
    if (fields.length < 5 || fields.length > 6) {
      add('warn', `Cron 表达式 <code>${escapeHtml(match)}</code> 应为 5 段（分 时 日 月 周）或 6 段（秒 分 时 日 月 周）。`, blockId);
    }
  }
  if (!/^https?:\/\//i.test(path) && !/\.js$/i.test(path)) {
    add('warn', `本地脚本 <code>${escapeHtml(path)}</code> 需要放在 Loon 的脚本目录下，否则无法加载。`, blockId);
  }

  params.push(`script-path=${path}`);
  if (meta.body && data.requiresBody === 'true') params.push('requires-body=true');
  if (String(data.timeout || '').trim()) params.push(`timeout=${String(data.timeout).trim()}`);
  if ((data.tag || '').trim()) params.push(`tag=${data.tag.trim()}`);
  if (data.enable === 'false') params.push('enable=false');

  const head = meta.match ? `${type} ${type === 'cron' ? `"${match.replace(/^["']|["']$/g, '')}"` : match}` : type;
  return `${head} ${params.join(', ')}`;
}

/* ========================= 语法高亮 ========================= */

const TYPE_WORDS = /\b(DOMAIN-SUFFIX|DOMAIN-KEYWORD|DOMAIN-REGEX|DOMAIN|IP-CIDR6|IP-CIDR|IP-ASN|GEOIP|USER-AGENT|URL-REGEX|PROTOCOL|DEST-PORT|SRC-PORT|AND|OR|NOT)\b/g;

function span(cls, text) {
  return `<span class="${cls}">${text}</span>`;
}

function highlightPlugin(text) {
  return text
    .split('\n')
    .map((line) => {
      if (!line) return '';
      if (/^#!/.test(line)) return span('tk-meta', escapeHtml(line));
      if (/^\[[^\]]+\]$/.test(line)) return span('tk-section', escapeHtml(line));
      if (/^hostname\s*=/.test(line)) {
        const idx = line.indexOf('=');
        return (
          span('tk-key', escapeHtml(line.slice(0, idx).trim())) +
          span('tk-dim', ' = ') +
          span('tk-str', escapeHtml(line.slice(idx + 1).trim()))
        );
      }
      if (/^(http-request|http-response|cron|network-changed|generic|dns)\b/.test(line)) return hlScriptLine(line);
      if (/^(AND|OR|NOT),/.test(line)) return hlRuleLine(line);
      if (REWRITE_TYPES.some((t) => line.split(/\s+/).pop() === t.v)) return hlRewriteLine(line);
      if (/^(DOMAIN|IP-|GEOIP|USER-AGENT|URL-REGEX|PROTOCOL|DEST-PORT|SRC-PORT)/.test(line)) return hlRuleLine(line);
      return escapeHtml(line);
    })
    .join('\n');
}

function hlRuleLine(line) {
  const idx = line.lastIndexOf(',');
  if (idx < 0) return escapeHtml(line).replace(TYPE_WORDS, (m) => span('tk-type', m));
  const head = escapeHtml(line.slice(0, idx)).replace(TYPE_WORDS, (m) => span('tk-type', m));
  const policy = line.slice(idx + 1);
  let tail;
  if (/^REJECT/.test(policy)) tail = span('tk-reject', escapeHtml(policy));
  else if (policy === 'PROXY') tail = span('tk-proxy', policy);
  else if (policy === 'DIRECT') tail = span('tk-direct', policy);
  else tail = escapeHtml(policy);
  return `${head}${span('tk-dim', ',')}${tail}`;
}

function hlRewriteLine(line) {
  const parts = line.split(/\s+/);
  const type = parts.pop();
  return `${escapeHtml(parts.join(' '))} ${span('tk-type', type)}`;
}

function hlScriptLine(line) {
  const sp = line.indexOf(' script-path=');
  let type = line;
  let match = '';
  let params = '';
  if (sp >= 0) {
    const head = line.slice(0, sp);
    const hi = head.indexOf(' ');
    type = hi >= 0 ? head.slice(0, hi) : head;
    match = hi >= 0 ? head.slice(hi + 1) : '';
    params = line.slice(sp + 1);
  } else {
    const hi = line.indexOf(' ');
    type = hi >= 0 ? line.slice(0, hi) : line;
    params = hi >= 0 ? line.slice(hi + 1) : '';
  }
  const paramsHtml = escapeHtml(params).replace(
    /([a-z-]+)=([^,]*)/g,
    (_, key, value) => `${span('tk-key', key)}${span('tk-dim', '=')}${span('tk-str', value)}`
  );
  return `${span('tk-type', escapeHtml(type))} ${span('tk-str', escapeHtml(match))} ${paramsHtml}`.trim();
}

const JS_KEYWORDS = /\b(const|let|var|function|if|else|return|new|typeof|for|while|true|false|null|undefined)\b/g;

function highlightJs(text) {
  return text
    .split('\n')
    .map((line) => {
      const trimmed = line.trim();
      if (trimmed.startsWith('//')) return span('tk-comment', escapeHtml(line));
      let html = escapeHtml(line)
        .replace(/(&quot;[^&]*?&quot;|&#039;[^&]*?&#039;)/g, (m) => span('tk-str', m))
        .replace(JS_KEYWORDS, (m) => span('tk-type', m))
        .replace(/(\$done|\$response|\$request|\$argument|\$persistentStore)/g, (m) => span('tk-key', m));
      const ci = line.indexOf('//');
      if (ci > 0 && !line.slice(0, ci).includes('://')) {
        const codePart = escapeHtml(line.slice(0, ci)).replace(JS_KEYWORDS, (m) => span('tk-type', m));
        html = `${codePart}${span('tk-comment', escapeHtml(line.slice(ci)))}`;
      }
      return html;
    })
    .join('\n');
}

/* ========================= 渲染：侧栏 ========================= */

function renderSidebar() {
  el.pluginList.innerHTML = state.plugins
    .map(
      (plugin) => `
      <div class="plugin-item ${plugin.id === state.selectedId ? 'is-active' : ''}" data-plugin-id="${plugin.id}" role="button" tabindex="0">
        <span class="p-name">${escapeHtml(plugin.name || '未命名插件')}</span>
        <button class="btn-icon is-danger p-del" data-act="del-plugin" data-plugin-id="${plugin.id}" title="删除插件" aria-label="删除插件 ${escapeHtml(plugin.name || '未命名插件')}">${ICONS.trash}</button>
      </div>`
    )
    .join('');
  el.pluginCount.textContent = String(state.plugins.length);
}

/* ========================= 渲染：画布 ========================= */

function renderCanvas() {
  const plugin = currentPlugin();
  if (!plugin) {
    el.canvas.innerHTML = '';
    return;
  }
  if (!plugin.blocks.length) {
    el.canvas.innerHTML = `
      <div class="empty">
        <h3>这个插件还是空的</h3>
        <p>从下面挑一个区块开始，或者直接点右上角「添加区块」。</p>
        <div class="empty-actions">
          ${Object.keys(BLOCK_META)
            .map((type) => `<button class="btn btn-soft btn-sm" data-act="add-block" data-type="${type}">添加${BLOCK_META[type].title}</button>`)
            .join('')}
        </div>
      </div>`;
    return;
  }
  el.canvas.innerHTML = plugin.blocks.map(renderBlock).join('');
}

function renderBlock(block, index) {
  const meta = BLOCK_META[block.type] || { title: block.type, desc: '', badge: '·' };
  const total = currentPlugin().blocks.length;
  return `
    <article class="card card--${escapeHtml(block.type)} ${block.collapsed ? 'is-collapsed' : ''}" data-id="${block.id}">
      <header class="card-head">
        <button class="drag-handle" type="button" title="按住拖动排序" aria-label="拖动排序">${ICONS.grip}</button>
        <span class="card-badge" aria-hidden="true">${meta.badge}</span>
        <div class="card-title">
          <strong>${escapeHtml(meta.title)}</strong>
          <span>${escapeHtml(meta.desc)}</span>
        </div>
        <div class="card-tools">
          <button class="card-toggle" type="button" data-act="collapse" data-id="${block.id}" aria-expanded="${String(!block.collapsed)}">
            ${block.collapsed ? ICONS.chevronDown : ICONS.chevronUp}<span>${block.collapsed ? '展开' : '收起'}</span>
          </button>
          <div class="card-order" role="group" aria-label="区块排序">
            <span>排序</span>
            <button type="button" data-act="up" data-id="${block.id}" title="上移" aria-label="上移区块" ${index === 0 ? 'disabled' : ''}>${ICONS.up}</button>
            <button type="button" data-act="down" data-id="${block.id}" title="下移" aria-label="下移区块" ${index === total - 1 ? 'disabled' : ''}>${ICONS.down}</button>
          </div>
          <details class="card-more">
            <summary aria-label="更多区块操作">${ICONS.more}<span>更多</span></summary>
            <div class="card-menu" role="group" aria-label="更多区块操作">
              <button type="button" data-act="dup" data-id="${block.id}">${ICONS.copy}<span>复制区块</span></button>
              <button class="is-danger" type="button" data-act="del" data-id="${block.id}">${ICONS.trash}<span>删除区块</span></button>
            </div>
          </details>
        </div>
      </header>
      <div class="card-body">${renderBlockBody(block)}</div>
    </article>`;
}

function renderBlockBody(block) {
  if (block.type === 'details') return renderDetails(block);
  if (block.type === 'hostnames') return renderHostnames(block);
  if (block.type === 'rules') return renderRules(block);
  if (block.type === 'rewrite') return renderRewrite(block);
  if (block.type === 'script') return renderScript(block);
  return '';
}

function renderDetails(block) {
  const d = block.data;
  return `
    <div class="grid">
      <div class="field span-all">
        <label>插件描述 · #!desc</label>
        <input type="text" data-field="desc" value="${escapeHtml(d.desc || '')}" placeholder="一句话说明这个插件做什么" />
      </div>
      <div class="field span-all">
        <label>图标地址 · #!icon</label>
        <input type="text" data-field="icon" value="${escapeHtml(d.icon || '')}" placeholder="https://.../icon.png" />
        <span class="hint">留空则 Loon 使用默认图标。</span>
      </div>
      <div class="field">
        <label>作者 · #!author</label>
        <input type="text" data-field="author" value="${escapeHtml(d.author || '')}" />
      </div>
      <div class="field">
        <label>分类标签 · #!tag</label>
        <input type="text" data-field="tag" value="${escapeHtml(d.tag || '')}" placeholder="去广告,工具" />
        <span class="hint">多个标签用英文逗号分隔。</span>
      </div>
      <div class="field span-all">
        <label>主页 · #!homepage</label>
        <input type="text" data-field="homepage" value="${escapeHtml(d.homepage || '')}" placeholder="https://github.com/..." />
      </div>
      <div class="field span-all">
        <label>支持系统 · #!system</label>
        <input type="text" data-field="system" value="${escapeHtml(d.system || '')}" placeholder="iOS,iPadOS,tvOS,macOS" />
      </div>
    </div>`;
}

function renderHostnames(block) {
  return `
    <div class="field">
      <label>MITM 主机名 · hostname =</label>
      <textarea data-field="hosts" rows="4" placeholder="api.example.com&#10;*.example.com">${escapeHtml(block.data.hosts || '')}</textarea>
      <span class="hint">每行一个或用英文逗号分隔，导出时会自动合并为单行逗号分隔（Loon 要求）。支持 <code>*.example.com</code> 通配。</span>
    </div>`;
}

function renderRules(block) {
  const root = block.data.root || { conditions: [] };
  const conditions = root.conditions || [];
  return `
    <div class="rows">
      ${renderRuleRows(conditions, block.id, 'root')}
    </div>
    <button class="btn btn-sm add-row" type="button" data-act="add-cond" data-id="${block.id}" data-path="root">＋ 添加规则</button>
    <div class="note-box">
      顶层规则每行单独生效；选择 AND / OR / NOT 会生成逻辑规则，子规则写在括号里且<b>不带策略</b>（NOT 只接受一个子规则）。
      插件中策略只能使用 <code>DIRECT</code>、<code>PROXY</code> 与 <code>REJECT</code> 系列。
    </div>`;
}

function renderRuleRows(conditions, blockId, parentPath) {
  return conditions
    .map((cond, idx) => {
      const path = parentPath === 'root' ? String(idx) : `${parentPath}.${idx}`;
      const logical = isLogical(cond.type);
      const isRoot = parentPath === 'root';

      const typeField = `
        <div class="field">
          <label>条件类型</label>
          <select data-field="type" data-path="${path}">${optionsHtml(RULE_TYPES, cond.type)}</select>
        </div>`;

      const policyField = isRoot
        ? `<div class="field">
             <label>执行策略</label>
             <select data-field="policy" data-path="${path}">${optionsHtml(POLICIES, cond.policy)}</select>
           </div>`
        : '<div></div>';

      const valueField = logical
        ? `<div class="field">
             <label>条件值</label>
             <input type="text" value="—" disabled />
           </div>`
        : `<div class="field">
             <label>条件值</label>
             <input type="text" data-field="value" data-path="${path}" value="${escapeHtml(cond.value || '')}" placeholder="example.com" />
           </div>`;

      const subtree = logical
        ? `<div class="subtree">
             <div class="subtree-label">${cond.type} 的子规则${cond.type === 'NOT' ? '（仅第一个生效）' : ''}</div>
             <div class="rows">${renderRuleRows(cond.children || [], blockId, path)}</div>
             <button class="btn btn-sm add-row" type="button" data-act="add-cond" data-id="${blockId}" data-path="${path}">＋ 添加子规则</button>
           </div>`
        : '';

      return `
        <div class="${parentPath === 'root' ? 'row' : 'row is-nested'}" data-path="${path}">
          ${typeField}
          ${policyField}
          ${valueField}
          <div class="row-actions">
            <button class="btn-icon is-danger" type="button" data-act="del-cond" data-id="${blockId}" data-path="${path}" title="删除规则" aria-label="删除规则">${ICONS.trash}</button>
          </div>
        </div>
        ${subtree}`;
    })
    .join('');
}

function renderRewrite(block) {
  const list = block.data.list || [];
  return `
    <div class="rows">
      ${list
        .map(
          (item, idx) => `
        <div class="row is-rewrite" data-idx="${idx}">
          <div class="field">
            <label>匹配正则</label>
            <input type="text" data-field="from" value="${escapeHtml(item.from || '')}" placeholder="^https?:\\/\\/example\\.com" />
          </div>
          <div class="field">
            <label>目标地址</label>
            <input type="text" data-field="to" value="${escapeHtml(item.to || '')}" placeholder="https://example.com" />
          </div>
          <div class="field">
            <label>类型</label>
            <select data-field="type">${optionsHtml(REWRITE_TYPES, item.type || '302')}</select>
          </div>
          <div class="row-actions">
            <button class="btn-icon is-danger" type="button" data-act="del-rewrite" data-idx="${idx}" title="删除复写" aria-label="删除复写">${ICONS.trash}</button>
          </div>
        </div>`
        )
        .join('')}
    </div>
    <button class="btn btn-sm add-row" type="button" data-act="add-rewrite" data-id="${block.id}">＋ 添加复写</button>
    <div class="note-box">类型填 <code>302/301/307/308/header</code> 时必须填目标地址；选 <code>reject*</code> 时目标地址会被忽略。</div>`;
}

function renderScript(block) {
  const d = block.data;
  const meta = SCRIPT_TYPES.find((s) => s.v === (d.scriptType || 'http-response')) || SCRIPT_TYPES[0];
  return `
    <div class="grid">
      <div class="field">
        <label>脚本类型</label>
        <select data-field="scriptType">${optionsHtml(SCRIPT_TYPES, d.scriptType || 'http-response')}</select>
      </div>
      <div class="field">
        <label>${meta.match ? meta.match : '（该类型无需匹配）'}</label>
        <input type="text" data-field="match" value="${escapeHtml(d.match || '')}" ${meta.match ? '' : 'disabled'} placeholder="${meta.match === 'Cron 表达式' ? '0 8 * * *' : '^https?:\\/\\/api\\.example\\.com'}" />
      </div>
      <div class="field">
        <label>脚本标签 · tag</label>
        <input type="text" data-field="tag" value="${escapeHtml(d.tag || '')}" placeholder="DemoUser" />
      </div>
      <div class="field">
        <label>超时（秒） · timeout</label>
        <input type="number" min="1" data-field="timeout" value="${escapeHtml(d.timeout || '10')}" />
      </div>
      <div class="field">
        <label>脚本文件名（导出用）</label>
        <input type="text" data-field="file" value="${escapeHtml(d.file || 'script.js')}" placeholder="demo.js" />
      </div>
      <div class="field">
        <label>${meta.body ? 'requires-body' : '启用 · enable'}</label>
        ${
          meta.body
            ? `<select data-field="requiresBody">${optionsHtml([{ v: 'true', label: 'true · 需要响应体' }, { v: 'false', label: 'false' }], d.requiresBody || 'true')}</select>`
            : `<select data-field="enable">${optionsHtml([{ v: 'true', label: 'true · 启用' }, { v: 'false', label: 'false · 停用' }], d.enable || 'true')}</select>`
        }
      </div>
      <div class="field span-all">
        <label>script-path</label>
        <input type="text" data-field="path" value="${escapeHtml(d.path || '')}" placeholder="https://.../scripts/demo.js 或 demo.js" />
        <span class="hint">远程脚本填完整 https 链接；本地脚本填文件名，并把 .js 放到 Loon 的脚本目录。</span>
      </div>
      <div class="field span-all">
        <label>脚本代码（不写入 .plugin，需单独导出为 .js）</label>
        <textarea data-field="code" rows="8">${escapeHtml(d.code || '')}</textarea>
      </div>
    </div>
    <div class="note-box is-warn">
      Loon 的 <code>.plugin</code> 文件里<b>不能内嵌 JS 代码</b>，只能通过 <code>script-path</code> 引用。这里的编辑器只是帮你把代码导出成 .js 文件。
    </div>`;
}

/* ========================= 预览面板（折叠 / 尺寸） ========================= */

/** 窄屏时预览面板在页面底部，宽屏时在右侧 */
function isBottomPreview() {
  return window.matchMedia('(max-width: 1180px)').matches;
}

/** 把 remember 的尺寸写进 CSS 变量；宽屏=宽度，窄屏=高度 */
function applyPreviewSize() {
  const size = isBottomPreview() ? state.ui.h : state.ui.w;
  el.app.style.setProperty('--preview-size', `${size}px`);
}

function setSideCollapsed(collapsed) {
  state.ui.sideCollapsed = !!collapsed;
  el.app.classList.toggle('is-side-collapsed', state.ui.sideCollapsed);
  el.sidebar.classList.toggle('is-collapsed', state.ui.sideCollapsed);
  el.sidebarToggle.setAttribute('aria-expanded', String(!state.ui.sideCollapsed));
  el.sidebarExpand.setAttribute('aria-expanded', String(!state.ui.sideCollapsed));
  saveUi();
}

function setPreviewCollapsed(collapsed) {
  state.ui.collapsed = !!collapsed;
  el.app.classList.toggle('is-preview-collapsed', state.ui.collapsed);
  el.preview.classList.toggle('is-collapsed', state.ui.collapsed);
  el.previewToggle.setAttribute('aria-expanded', String(!state.ui.collapsed));
  el.previewExpand.setAttribute('aria-expanded', String(!state.ui.collapsed));
  saveUi();
}

function bindPreviewResizer() {
  let axis = 'x';
  let startPoint = 0;
  let startSize = 0;

  const onMove = (event) => {
    const point = axis === 'x' ? event.clientX : event.clientY;
    /* 宽屏向左拖变大，窄屏向上拖变大，所以都是 start - current */
    const delta = startPoint - point;
    const viewport = axis === 'x' ? window.innerWidth : window.innerHeight;
    const max = viewport * PREVIEW_MAX_RATIO;
    const size = Math.min(max, Math.max(PREVIEW_MIN, startSize + delta));
    if (axis === 'x') state.ui.w = Math.round(size);
    else state.ui.h = Math.round(size);
    applyPreviewSize();
  };

  const onUp = () => {
    el.previewResizer.classList.remove('is-active');
    document.removeEventListener('pointermove', onMove);
    document.body.style.userSelect = '';
    document.body.style.cursor = '';
    saveUi();
  };

  el.previewResizer.addEventListener('pointerdown', (event) => {
    event.preventDefault();
    axis = isBottomPreview() ? 'y' : 'x';
    startPoint = axis === 'x' ? event.clientX : event.clientY;
    startSize = axis === 'x' ? state.ui.w : state.ui.h;
    el.previewResizer.classList.add('is-active');
    document.body.style.userSelect = 'none';
    document.body.style.cursor = axis === 'x' ? 'col-resize' : 'row-resize';
    document.addEventListener('pointermove', onMove);
    document.addEventListener('pointerup', onUp, { once: true });
  });

  /* 跨越 1180px 断点时要换一套尺寸，重新套用一次 */
  window.addEventListener('resize', applyPreviewSize);
}

/** 导出按钮跟着当前页签变：.plugin 页导出插件，脚本页下载 JS，校验页不显示 */
function updateExportButton() {
  const tab = state.tab;
  if (tab === 'plugin') {
    el.exportBtn.hidden = false;
    el.exportLabel.textContent = '导出 .plugin';
    el.exportBtn.title = '把生成的插件文件保存到本地';
  } else if (tab === 'script') {
    el.exportBtn.hidden = false;
    el.exportLabel.textContent = '下载 JS';
    el.exportBtn.title = '把脚本代码导出为 .js 文件';
  } else {
    el.exportBtn.hidden = true;
  }
  /* 校验面板没有可复制的文本 */
  el.copyBtn.hidden = tab === 'issues';
  /* 复写语法只影响 .plugin 输出，别的页签下藏着 */
  el.previewFoot.hidden = tab !== 'plugin';
}

/* ========================= 渲染：预览 ========================= */

function renderPreview() {
  state.view = buildOutput();
  const { text, scripts, issues } = state.view;

  const errors = issues.filter((i) => i.level === 'error');
  const warns = issues.filter((i) => i.level === 'warn');
  el.issueCount.textContent = String(issues.length);
  el.issueCount.classList.toggle('is-err', errors.length > 0);

  el.issuesPanel.innerHTML = issues.length
    ? issues
        .map(
          (issue) => `
        <div class="issue ${issue.level === 'error' ? 'is-error' : 'is-warn'}">
          <span class="issue-ico">${ICONS.alert}</span>
          <div class="issue-body">
            <p>${issue.msg}</p>
            ${issue.blockId ? `<button class="issue-jump" type="button" data-act="jump" data-id="${issue.blockId}">定位到区块</button>` : ''}
          </div>
        </div>`
        )
        .join('') +
      `<div class="issue is-ok">
         <span class="issue-ico">${ICONS.check}</span>
         <div class="issue-body"><p>${errors.length ? `还有 ${errors.length} 个错误需要修正` : '没有错误，可以导出到 Loon 试试'}${warns.length ? `（另有 ${warns.length} 条提示）` : ''}。</p></div>
       </div>`
    : `<div class="issue is-ok">
         <span class="issue-ico">${ICONS.check}</span>
         <div class="issue-body"><p>语法检查通过，没有发现问题。</p></div>
       </div>`;

  if (state.tab === 'issues') {
    el.codePreview.hidden = true;
    el.issuesPanel.hidden = false;
  } else {
    el.issuesPanel.hidden = true;
    el.codePreview.hidden = false;
    const isJs = state.tab === 'script';
    const body = isJs
      ? scripts
          .map((s, i) => `${scripts.length > 1 ? `// ===== ${s.file} =====\n` : ''}${s.code}`)
          .join('\n\n')
      : text;
    el.codePreview.innerHTML = `<code>${
      isJs ? highlightJs(body || '// 先在「脚本」区块里写代码，导出后上传到可访问的地址。') : highlightPlugin(body)
    }</code>`;
  }

  updateExportButton();
  updateChrome(errors, warns);
}

function updateChrome(errors, warns) {
  const plugin = currentPlugin();
  if (!plugin) return;
  el.blockCount.textContent = `${plugin.blocks.length} 个区块`;
  if (document.activeElement !== el.nameInput) el.nameInput.value = plugin.name || '';

  const errCount = errors ? errors.length : state.view.issues.filter((i) => i.level === 'error').length;
  const warnCount = warns ? warns.length : state.view.issues.filter((i) => i.level === 'warn').length;
  el.statusHint.classList.remove('is-ok', 'is-warn', 'is-err');
  if (errCount) {
    el.statusHint.textContent = `${errCount} 个语法错误`;
    el.statusHint.classList.add('is-err');
  } else if (warnCount) {
    el.statusHint.textContent = `${warnCount} 条提示`;
    el.statusHint.classList.add('is-warn');
  } else {
    el.statusHint.textContent = '语法检查通过';
    el.statusHint.classList.add('is-ok');
  }
}

function renderAll() {
  renderSidebar();
  renderCanvas();
  renderPreview();
}

/* ========================= 事件 ========================= */

function bindEvents() {
  /* --- 侧栏 --- */
  el.pluginList.addEventListener('click', (event) => {
    const delBtn = event.target.closest('[data-act="del-plugin"]');
    if (delBtn) {
      const id = delBtn.dataset.pluginId;
      const plugin = state.plugins.find((p) => p.id === id);
      if (state.plugins.length === 1) {
        toast('至少保留一个插件', 'warn');
        return;
      }
      if (!window.confirm(`删除插件「${plugin ? plugin.name : ''}」？此操作不可撤销。`)) return;
      state.plugins = state.plugins.filter((p) => p.id !== id);
      if (state.selectedId === id) state.selectedId = state.plugins[0].id;
      renderAll();
      scheduleSave();
      return;
    }
    const item = event.target.closest('.plugin-item');
    if (!item) return;
    state.selectedId = item.dataset.pluginId;
    renderAll();
    scheduleSave();
  });

  el.newPluginBtn.addEventListener('click', () => {
    const plugin = createPlugin(`未命名插件 ${state.plugins.length + 1}`);
    state.plugins.push(plugin);
    state.selectedId = plugin.id;
    renderAll();
    scheduleSave();
    el.nameInput.focus();
    el.nameInput.select();
  });

  el.resetBtn.addEventListener('click', () => {
    if (!window.confirm('将用示例插件覆盖当前所有草稿，确定吗？')) return;
    state.plugins = [createDemoPlugin()];
    state.selectedId = state.plugins[0].id;
    renderAll();
    scheduleSave();
    toast('已恢复示例插件', 'success');
  });

  /* --- 插件名 --- */
  el.nameInput.addEventListener('input', () => {
    const plugin = currentPlugin();
    if (!plugin) return;
    plugin.name = el.nameInput.value;
    const label = el.pluginList.querySelector(`[data-plugin-id="${plugin.id}"] .p-name`);
    if (label) label.textContent = plugin.name || '未命名插件';
    renderPreview();
    scheduleSave();
  });

  /* --- 添加区块浮层 --- */
  el.palette.innerHTML = Object.keys(BLOCK_META)
    .map(
      (type) => `
      <button class="palette-item palette-item--${type}" type="button" data-act="add-block" data-type="${type}">
        <span class="palette-ico" aria-hidden="true">${BLOCK_META[type].badge}</span>
        <span class="palette-text"><strong>${BLOCK_META[type].title}</strong><span>${BLOCK_META[type].desc}</span></span>
      </button>`
    )
    .join('');

  const togglePalette = (show) => {
    /* 无参调用 = 取反；传布尔 = 显式开(true)/关(false) */
    el.palette.hidden = typeof show === 'boolean' ? !show : !el.palette.hidden;
    el.addBlockBtn.setAttribute('aria-expanded', String(!el.palette.hidden));
  };

  el.addBlockBtn.addEventListener('click', (event) => {
    event.stopPropagation();
    togglePalette();
  });

  document.addEventListener('click', (event) => {
    if (!el.palette.hidden && !el.palette.contains(event.target) && event.target !== el.addBlockBtn) {
      togglePalette(false);
    }
  });

  document.addEventListener('keydown', (event) => {
    if (event.key === 'Escape' && !el.palette.hidden) togglePalette(false);
  });

  document.addEventListener('click', (event) => {
    const btn = event.target.closest('[data-act="add-block"]');
    if (!btn) return;
    addBlock(btn.dataset.type);
    togglePalette(false);
  });

  /* --- 画布：委托事件 --- */
  el.canvas.addEventListener('click', onCanvasClick);
  el.canvas.addEventListener('input', onCanvasField);
  el.canvas.addEventListener('change', (event) => onCanvasField(event, true));
  bindDragAndDrop();

  /* --- 预览区：复制 / 导出 / 折叠 / 拖拽尺寸 --- */
  el.exportBtn.addEventListener('click', () => {
    /* 导出按钮跟着页签走，点它永远导出「当前正在看的东西」 */
    if (state.tab === 'script') downloadScripts();
    else downloadPlugin();
  });
  el.copyBtn.addEventListener('click', copyCurrent);
  el.previewToggle.addEventListener('click', () => setPreviewCollapsed(true));
  el.previewExpand.addEventListener('click', () => setPreviewCollapsed(false));
  el.sidebarToggle.addEventListener('click', () => setSideCollapsed(true));
  el.sidebarExpand.addEventListener('click', () => setSideCollapsed(false));
  bindPreviewResizer();

  /* --- Tabs --- */
  el.tabs.addEventListener('click', (event) => {
    const tab = event.target.closest('.tab');
    if (!tab) return;
    state.tab = tab.dataset.tab;
    el.tabs.querySelectorAll('.tab').forEach((t) => t.classList.toggle('is-active', t === tab));
    renderPreview();
  });

  /* --- 复写语法切换 --- */
  el.rewriteSyntax.value = state.rewriteSyntax;
  el.rewriteSyntax.addEventListener('change', () => {
    state.rewriteSyntax = el.rewriteSyntax.value;
    renderPreview();
    scheduleSave();
    toast(state.rewriteSyntax === 'rewrite' ? '已切换到 [Rewrite]（pattern 类型 目标）' : '已切换到 [URL Rewrite]（pattern 目标 类型）');
  });
}

/* ---------- 画布点击 ---------- */
function onCanvasClick(event) {
  const btn = event.target.closest('[data-act]');
  if (!btn) return;
  const plugin = currentPlugin();
  const action = btn.dataset.act;
  const blockId = btn.dataset.id || event.target.closest('.card')?.dataset.id;
  const block = blockId ? getBlock(blockId) : null;

  if (action === 'jump') {
    const card = el.canvas.querySelector(`.card[data-id="${btn.dataset.id}"]`);
    if (card) {
      card.scrollIntoView({ behavior: 'smooth', block: 'center' });
      card.style.transition = 'box-shadow .2s ease';
      card.style.boxShadow = '0 0 0 3px rgba(76,110,245,.35)';
      window.setTimeout(() => {
        card.style.boxShadow = '';
      }, 1400);
    }
    return;
  }

  if (action === 'del') {
    plugin.blocks = plugin.blocks.filter((b) => b.id !== blockId);
    afterStructureChange();
    return;
  }

  if (action === 'dup') {
    const copy = clone(block);
    copy.id = uid();
    plugin.blocks.splice(plugin.blocks.findIndex((b) => b.id === blockId) + 1, 0, copy);
    afterStructureChange();
    return;
  }

  if (action === 'collapse') {
    block.collapsed = !block.collapsed;
    renderCanvas();
    scheduleSave();
    return;
  }

  if (action === 'up' || action === 'down') {
    const index = plugin.blocks.findIndex((b) => b.id === blockId);
    const next = action === 'up' ? index - 1 : index + 1;
    if (next < 0 || next >= plugin.blocks.length) return;
    const tmp = plugin.blocks[index];
    plugin.blocks[index] = plugin.blocks[next];
    plugin.blocks[next] = tmp;
    afterStructureChange();
    return;
  }

  if (action === 'add-cond') {
    const path = btn.dataset.path || 'root';
    const target = resolveCondition(block.data.root, path);
    if (!target) return;
    const list = ensureConditionList(target);
    list.push(createCondition(path === 'root' ? 'DOMAIN-SUFFIX' : 'DOMAIN-SUFFIX'));
    afterStructureChange();
    return;
  }

  if (action === 'del-cond') {
    removeConditionAt(block.data.root, btn.dataset.path);
    afterStructureChange();
    return;
  }

  if (action === 'add-rewrite') {
    block.data.list.push({ from: '', to: '', type: '302' });
    afterStructureChange();
    return;
  }

  if (action === 'del-rewrite') {
    block.data.list.splice(Number(btn.dataset.idx), 1);
    afterStructureChange();
  }
}

function ensureConditionList(node) {
  if (Array.isArray(node.conditions)) return node.conditions;
  if (Array.isArray(node.children)) return node.children;
  node.children = [];
  return node.children;
}

function afterStructureChange() {
  renderCanvas();
  renderPreview();
  updateChrome();
  scheduleSave();
}

/* ---------- 画布字段输入 ---------- */
function onCanvasField(event, isChange) {
  const input = event.target.closest('[data-field]');
  if (!input) return;
  const card = input.closest('.card');
  const block = card ? getBlock(card.dataset.id) : null;
  if (!block) return;

  const field = input.dataset.field;
  const value = input.value;

  /* 结构性变更：需要重绘画布 */
  if (field === 'type' && block.type === 'rules') {
    const cond = resolveCondition(block.data.root, input.dataset.path || 'root');
    if (!cond) return;
    const wasLogical = isLogical(cond.type);
    cond.type = value;
    if (isLogical(value)) {
      if (!wasLogical) {
        cond.children = [createCondition('DOMAIN-SUFFIX')];
        cond.value = '';
        toast('已切换为逻辑规则，子规则可在下方编辑');
      }
    } else if (wasLogical) {
      cond.children = [];
      if (!cond.value) cond.value = 'example.com';
      toast('已切回普通规则，子规则已清空');
    }
    afterStructureChange();
    return;
  }

  if (field === 'scriptType') {
    block.data.scriptType = value;
    afterStructureChange();
    return;
  }

  if (field === 'type' && block.type === 'rewrite') {
    /* 切到 reject* 后目标地址输入框要跟着隐藏，所以这里需要重绘；
       但重绘前必须先把新类型写回数据，否则选择会丢 */
    const rwRow = input.closest('[data-idx]');
    const rwItem = block.data.list[Number(rwRow ? rwRow.dataset.idx : -1)];
    if (rwItem) rwItem.type = value;
    afterStructureChange();
    return;
  }

  /* 普通字段：只更新数据 + 预览，避免输入框失焦 */
  if (block.type === 'details' || block.type === 'hostnames' || block.type === 'script') {
    block.data[field] = value;
  } else if (block.type === 'rules') {
    const cond = resolveCondition(block.data.root, input.dataset.path || 'root');
    if (!cond) return;
    cond[field] = value;
  } else if (block.type === 'rewrite') {
    const row = input.closest('[data-idx]');
    const item = block.data.list[Number(row ? row.dataset.idx : -1)];
    if (!item) return;
    item[field] = value;
  }

  renderPreview();
  scheduleSave();
}

/* ---------- 拖拽排序 ---------- */
function bindDragAndDrop() {
  el.canvas.addEventListener('mousedown', (event) => {
    const handle = event.target.closest('.drag-handle');
    const card = event.target.closest('.card');
    if (card) card.draggable = Boolean(handle);
  });

  el.canvas.addEventListener('dragstart', (event) => {
    const card = event.target.closest('.card');
    if (!card) return;
    state.dragId = card.dataset.id;
    card.classList.add('is-dragging');
    if (event.dataTransfer) {
      event.dataTransfer.effectAllowed = 'move';
      event.dataTransfer.setData('text/plain', card.dataset.id);
    }
  });

  el.canvas.addEventListener('dragover', (event) => {
    const card = event.target.closest('.card');
    if (!card || !state.dragId) return;
    event.preventDefault();
    const rect = card.getBoundingClientRect();
    const isAfter = event.clientY > rect.top + rect.height / 2;
    card.classList.toggle('drop-before', !isAfter);
    card.classList.toggle('drop-after', isAfter);
  });

  el.canvas.addEventListener('dragleave', (event) => {
    const card = event.target.closest('.card');
    if (card) card.classList.remove('drop-before', 'drop-after');
  });

  el.canvas.addEventListener('drop', (event) => {
    const card = event.target.closest('.card');
    if (!card || !state.dragId) return;
    event.preventDefault();
    card.classList.remove('drop-before', 'drop-after');
    const rect = card.getBoundingClientRect();
    const isAfter = event.clientY > rect.top + rect.height / 2;
    moveBlock(state.dragId, card.dataset.id, isAfter);
  });

  el.canvas.addEventListener('dragend', () => {
    state.dragId = null;
    el.canvas.querySelectorAll('.card').forEach((card) => {
      card.classList.remove('is-dragging', 'drop-before', 'drop-after');
      card.draggable = false;
    });
  });
}

function moveBlock(fromId, toId, isAfter) {
  const plugin = currentPlugin();
  if (!fromId || !toId || fromId === toId) return;
  const from = plugin.blocks.findIndex((b) => b.id === fromId);
  if (from < 0) return;
  const [moved] = plugin.blocks.splice(from, 1);
  let to = plugin.blocks.findIndex((b) => b.id === toId);
  if (to < 0) to = plugin.blocks.length - 1;
  plugin.blocks.splice(isAfter ? to + 1 : to, 0, moved);
  afterStructureChange();
}

/* ========================= 导出 / 复制 ========================= */

function downloadFile(filename, content) {
  const blob = new Blob([content], { type: 'text/plain;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function safeName() {
  return (currentPlugin().name || 'loon-plugin').trim().replace(/[\\/:*?"<>|\s]+/g, '-');
}

function downloadPlugin() {
  const { text, issues } = state.view;
  const errors = issues.filter((i) => i.level === 'error');
  if (errors.length) {
    toast(`还有 ${errors.length} 个错误，已导出但 Loon 可能加载失败`, 'error');
  }
  downloadFile(`${safeName()}.plugin`, text);
  toast(`已导出 ${safeName()}.plugin`, 'success');
}

function downloadScripts() {
  const { scripts } = state.view;
  if (!scripts.length) {
    toast('没有可导出的脚本代码', 'warn');
    return;
  }
  scripts.forEach((script, index) => {
    window.setTimeout(() => downloadFile(script.file, script.code + '\n'), index * 300);
  });
  toast(`已导出 ${scripts.length} 个脚本文件`, 'success');
}

function copyCurrent() {
  const { text, scripts } = state.view;
  const content =
    state.tab === 'script'
      ? scripts.map((s) => `${scripts.length > 1 ? `// ===== ${s.file} =====\n` : ''}${s.code}`).join('\n\n')
      : text;
  if (!content.trim()) {
    toast('没有可复制的内容', 'warn');
    return;
  }
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(content).then(
      () => toast('已复制到剪贴板', 'success'),
      () => toast('复制失败，请手动选择文本', 'error')
    );
  } else {
    const ta = document.createElement('textarea');
    ta.value = content;
    document.body.appendChild(ta);
    ta.select();
    try {
      document.execCommand('copy');
      toast('已复制到剪贴板', 'success');
    } catch (err) {
      toast('复制失败，请手动选择文本', 'error');
    }
    ta.remove();
  }
}

/* ========================= Toast ========================= */

let toastTimer = null;

function toast(message, level = 'info') {
  const conf = TOAST_LEVELS[level] || TOAST_LEVELS.info;
  /* 连续调用时保留显示态，避免重建结构导致闪一下 */
  const wasShown = !el.toast.hidden && el.toast.classList.contains('is-show');

  /* 图标来自常量可安全注入；文案走 textContent，避免内容里的尖括号被解析 */
  el.toast.className = `toast ${conf.cls}${wasShown ? ' is-show' : ''}`;
  el.toast.innerHTML = `<span class="toast-ico">${conf.icon}</span><span class="toast-text"></span>`;
  el.toast.querySelector('.toast-text').textContent = message;
  el.toast.hidden = false;

  if (!wasShown) {
    const show = () => el.toast.classList.add('is-show');
    if (typeof window.requestAnimationFrame === 'function') window.requestAnimationFrame(show);
    else window.setTimeout(show, 16);
  }

  window.clearTimeout(toastTimer);
  toastTimer = window.setTimeout(() => {
    el.toast.classList.remove('is-show');
    window.setTimeout(() => {
      /* 期间可能又有新 toast 进来，只在确实没内容要显示时才真正隐藏 */
      if (!el.toast.classList.contains('is-show')) el.toast.hidden = true;
    }, 220);
  }, 2400);
}

/* ========================= 启动 ========================= */

loadState();
loadUi();
bindEvents();
applyPreviewSize();
setPreviewCollapsed(state.ui.collapsed);
setSideCollapsed(state.ui.sideCollapsed);
renderAll();
