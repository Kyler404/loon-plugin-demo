/* =============================================================================
 * Loon Plugin Studio
 * -----------------------------------------------------------------------------
 * 语法依据（官方文档 https://nsloon.app/docs/Plugin/）：
 *
 *   插件共 8 个区块，顺序与文档一致：
 *     详情(#!) / [Argument] / [General] / [Rule] / [Rewrite] / [Host] / [Script] / [Mitm]
 *
 *   复写统一使用 Loon 3.5.1 (978) 新语法：
 *     <phase> if <condition> then <action>[ | <action> ...]
 *
 *   脚本统一使用 Loon 3.5.1 (983) 新语法：
 *     HTTP            <request|response> if <condition> then script(<path>[, <argument>]) [with <options>]
 *     Cron            cron <expr> then script(...) [with <options>]
 *     Network Changed network-changed then script(...) [with <options>]
 *     Generic         generic then script(...) [with <options>]
 *
 *   插件参数：Rewrite / Script 条件里写 ${name}；脚本 $argument 对象写 {${a}, ${b}}
 *   插件规则策略：只能用 DIRECT / PROXY / REJECT 系列
 * ========================================================================== */
'use strict';

/* ========================= 常量 ========================= */

/* v1 存的是 8 区块改造前的旧结构（hostnames 区块、旧复写/脚本数据形状），
   升 key 直接丢弃旧草稿，避免迁移逻辑把半兼容数据带进来 */
const STORE_KEY = 'loon-plugin-studio.v2';
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

/** 脚本类型（Loon 3.5.1 (983) 新语法）
 *  cond: true=HTTP 条件表达式 | 'cron'=Cron 表达式 | false=无需条件
 *  body: 是否支持 requires_body / binary_body_mode */
const SCRIPT_KINDS = [
  { v: 'request', label: 'request · 请求发出前', cond: true, body: true },
  { v: 'response', label: 'response · 响应返回后', cond: true, body: true },
  { v: 'cron', label: 'cron · 定时执行', cond: 'cron', body: false },
  { v: 'network-changed', label: 'network-changed · 网络变化', cond: false, body: false },
  { v: 'generic', label: 'generic · 手动触发', cond: false, body: false }
];

/** 脚本 $argument 的传参方式 */
const ARG_MODES = [
  { v: 'none', label: '不传参（$argument 为 null）' },
  { v: 'string', label: '字符串 · "a=1&b=2"' },
  { v: 'raw', label: '原始字符串 · `{"a":1}`' },
  { v: 'object', label: '插件对象 · {${a}, ${b}}' }
];

/** 复写 Action 参数类型：S=字符串（自动加引号）N=数字 R=正则 A=任意值（原样） */
const REWRITE_PHASES = [
  { v: 'request', label: 'request · 请求发出前' },
  { v: 'response', label: 'response · 响应返回后' }
];

/** 生成 request / response 两组同名 Action，避免手写 20 条重复定义 */
function scopeActions(scope) {
  return [
    { v: `${scope}.header.add`, phase: scope, args: [{ n: 'Header 名', t: 'S', ph: 'X-Loon' }, { n: 'Header 值', t: 'S', ph: 'true' }] },
    { v: `${scope}.header.set`, phase: scope, args: [{ n: 'Header 名', t: 'S', ph: 'Cache-Control' }, { n: 'Header 值', t: 'S', ph: 'no-cache' }] },
    { v: `${scope}.header.del`, phase: scope, args: [{ n: 'Header 名', t: 'S', ph: 'Set-Cookie' }] },
    { v: `${scope}.header.replace`, phase: scope, args: [{ n: 'Header 名', t: 'S', ph: 'Content-Type' }, { n: '正则', t: 'R', ph: '^(.+); charset=.+$' }, { n: '替换内容', t: 'S', ph: '$1' }] },
    { v: `${scope}.body.replace`, phase: scope, args: [{ n: '正则', t: 'R', ph: '"vip":\\s*false' }, { n: '替换内容', t: 'S', ph: '"vip":true' }] },
    { v: `${scope}.json.add`, phase: scope, args: [{ n: 'JSON 路径', t: 'S', ph: 'data.extra' }, { n: '值', t: 'A', ph: 'true' }] },
    { v: `${scope}.json.delete`, phase: scope, args: [{ n: 'JSON 路径', t: 'S', ph: 'data.ads' }] },
    { v: `${scope}.json.replace`, phase: scope, args: [{ n: 'JSON 路径', t: 'S', ph: 'data.vip' }, { n: '值', t: 'A', ph: 'true' }] },
    { v: `${scope}.json.jq`, phase: scope, args: [{ n: 'jq 表达式', t: 'S', ph: '.data | del(.ads)' }] },
    { v: `${scope}.json.jq_file`, phase: scope, args: [{ n: 'jq 文件路径', t: 'S', ph: 'filters/clean.jq' }] }
  ];
}

/** 复写 Action 速查表（方法签名与官方文档一致，位置参数按顺序） */
const REWRITE_ACTIONS = [
  { v: 'url.replace', phase: 'request', args: [{ n: '替换内容', t: 'S', ph: 'https://new.example.com${m.1}' }] },
  { v: 'redirect', phase: 'request', args: [{ n: '状态码', t: 'N', ph: '302' }, { n: '目标 URL', t: 'S', ph: 'https://api.example.com' }] },
  { v: 'reject', phase: 'both', args: [{ n: '状态码', t: 'N', ph: '200' }, { n: '响应体', t: 'S', opt: true, ph: '可选，UTF-8 文本' }] },
  { v: 'reject_img', phase: 'both', args: [{ n: '状态码', t: 'N', ph: '200' }] },
  { v: 'reject_dict', phase: 'both', args: [{ n: '状态码', t: 'N', ph: '200' }] },
  { v: 'reject_array', phase: 'both', args: [{ n: '状态码', t: 'N', ph: '200' }] },
  { v: 'reject_video', phase: 'both', args: [{ n: '状态码', t: 'N', ph: '200' }] },
  ...scopeActions('request'),
  ...scopeActions('response'),
  { v: 'request.body.mock', phase: 'request', args: [{ n: '类型', t: 'S', ph: 'json' }, { n: '内容', t: 'S', ph: '{"code":0}' }, { n: '是否继续请求', t: 'A', opt: true, ph: 'false' }] },
  { v: 'request.body.mock_file', phase: 'request', args: [{ n: '类型', t: 'S', ph: 'json' }, { n: '文件路径', t: 'S', ph: 'mock/user.json' }, { n: '是否继续请求', t: 'A', opt: true, ph: 'false' }] },
  { v: 'response.body.mock', phase: 'response', args: [{ n: '类型', t: 'S', ph: 'json' }, { n: '内容', t: 'S', ph: '{"code":0}' }, { n: '状态码', t: 'N', opt: true, ph: '200' }, { n: '是否继续请求', t: 'A', opt: true, ph: 'false' }] },
  { v: 'response.body.mock_file', phase: 'response', args: [{ n: '类型', t: 'S', ph: 'json' }, { n: '文件路径', t: 'S', ph: 'mock/user.json' }, { n: '状态码', t: 'N', opt: true, ph: '200' }, { n: '是否继续请求', t: 'A', opt: true, ph: 'false' }] }
];

/** [General] 里插件可用的字段 */
const GENERAL_FIELDS = [
  { k: 'bypassTun', out: 'bypass-tun', label: 'bypass-tun · 绕开 TUN 的地址', ph: '192.168.0.0/16, 10.0.0.0/8' },
  { k: 'skipProxy', out: 'skip-proxy', label: 'skip-proxy · 不经过代理的地址', ph: '192.168.1.1' },
  { k: 'realIp', out: 'real-ip', label: 'real-ip · 真实出口 IP', ph: '1.2.3.4' },
  { k: 'dnsServer', out: 'dns-server', label: 'dns-server · DNS 服务器', ph: '223.5.5.5, 119.29.29.29' }
];

/** 区块元信息（顺序 = 插件文件中的输出顺序，与官方文档一致） */
const BLOCK_META = {
  details: { title: '详情', desc: '#!name / #!desc / #!icon 等元信息', badge: '信息' },
  argument: { title: '参数', desc: '[Argument] 让用户在 Loon 里填写', badge: 'ARG' },
  general: { title: '通用', desc: '[General] 绕开 TUN / DNS 等设置', badge: 'GEN' },
  rules: { title: '规则', desc: '[Rule] 分流 / 拦截策略', badge: 'RULE' },
  rewrite: { title: '复写', desc: '[Rewrite] 条件 → Action', badge: 'RW' },
  host: { title: 'Host', desc: '[Host] 域名到 IP / DNS 映射', badge: 'HOST' },
  script: { title: '脚本', desc: '[Script] 挂载 JS 脚本', badge: 'JS' },
  mitm: { title: 'MITM', desc: '[Mitm] 需要解密的主机名', badge: 'MITM' }
};

/** [Argument] 的控件类型 */
const ARG_CONTROL_TYPES = [
  { v: 'input', label: 'input · 文本输入' },
  { v: 'select', label: 'select · 单选列表' },
  { v: 'switch', label: 'switch · 开关' }
];

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
  argument: {
    type: 'argument',
    data: {
      items: [
        { name: 'token', type: 'input', value: '默认令牌', options: '', tag: '令牌', desc: '用于脚本鉴权的令牌', num: false }
      ]
    }
  },
  general: {
    type: 'general',
    data: { bypassTun: '192.168.0.0/16, 10.0.0.0/8', skipProxy: '', realIp: '', dnsServer: '' }
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
      list: [
        {
          phase: 'request',
          cond: '^https?:\\/\\/(www\\.)?example\\.cn\\/path',
          capture: '',
          actions: [{ v: 'url.replace', args: ['https://example.com/path'] }]
        },
        {
          phase: 'response',
          cond: '^https?:\\/\\/ads\\.example\\.com',
          capture: '',
          actions: [{ v: 'reject_dict', args: ['200'] }]
        }
      ]
    }
  },
  host: {
    type: 'host',
    data: {
      items: [{ name: 'example.com', value: 'server:223.5.5.5' }]
    }
  },
  script: {
    type: 'script',
    data: {
      kind: 'response',
      match: '^https?:\\/\\/api\\.example\\.com\\/v1\\/user',
      path: 'https://raw.githubusercontent.com/kyler404/loon-plugin-demo/main/scripts/demo.js',
      file: 'demo.js',
      tag: 'DemoUser',
      timeout: '10',
      enable: 'true',
      requiresBody: 'true',
      argMode: 'object',
      argValue: 'token',
      code: [
        'const body = JSON.parse($response.body || "{}");',
        'const { token } = $argument || {};',
        '',
        'if (!body || typeof body !== "object") {',
        '  $done({});',
        '} else {',
        '  body.data = body.data || {};',
        '  body.data.demo = true;',
        '  body.data.message = "Hello from Loon Plugin Studio";',
        '  body.data.token = token || "";',
        '  $done({ status: 200, body: JSON.stringify(body) });',
        '}'
      ].join('\n')
    }
  },
  mitm: {
    type: 'mitm',
    data: { hosts: 'api.example.com\napi2.example.com' }
  }
};

/* ========================= 状态 ========================= */

const state = {
  plugins: [],
  selectedId: null,
  tab: 'plugin',
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
  saveHint: $('#saveHint'),
  toast: $('#toast'),
  /* 面板折叠 */
  app: $('#app'),
  sidebar: $('#sidebar'),
  sidebarToggle: $('#sidebarToggle'),
  sidebarExpand: $('#sidebarExpand'),
  preview: $('#preview'),
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
          selectedId: state.selectedId
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
    /* 示例插件带上全部 8 个区块，作为新语法的活样例 */
    blocks: ['details', 'argument', 'general', 'rules', 'rewrite', 'host', 'script', 'mitm'].map((type) =>
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
 * 这里是整个项目最容易出错的地方，所有规则都按官方文档序列化：
 * 区块顺序 = #! 元信息 → [Argument] → [General] → [Rule] → [Rewrite] → [Host] → [Script] → [Mitm]
 */
function buildOutput() {
  const plugin = currentPlugin();
  const issues = [];
  const add = (level, msg, blockId) => issues.push({ level, msg, blockId });
  const lines = [];
  const scripts = [];

  if (!plugin) return { text: '', scripts: [], issues: [] };

  /* 先收集 [Argument] 声明的参数名，供复写 / 脚本里的 ${name} 引用校验 */
  const argNames = new Set();
  blocksOfType('argument').forEach((block) => {
    (block.data.items || []).forEach((item) => {
      const name = (item.name || '').trim();
      if (!name) return;
      if (argNames.has(name)) {
        add('error', `参数 <code>${escapeHtml(name)}</code> 重名，Loon 加载时会拒绝整份插件。`, block.id);
      } else {
        argNames.add(name);
      }
    });
  });

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

  /* ---------- [Argument] ---------- */
  const argLines = [];
  blocksOfType('argument').forEach((block) => {
    (block.data.items || []).forEach((item) => {
      const line = serializeArgument(item, add, block.id);
      if (line) argLines.push(line);
    });
  });
  if (argLines.length) {
    lines.push('[Argument]');
    argLines.forEach((line) => lines.push(line));
    lines.push('');
  }

  /* ---------- [General] ---------- */
  const generalLines = [];
  blocksOfType('general').forEach((block) => {
    GENERAL_FIELDS.forEach((f) => {
      const value = String(block.data[f.k] || '').trim();
      if (value) generalLines.push(`${f.out} = ${value}`);
    });
  });
  if (generalLines.length) {
    lines.push('[General]');
    generalLines.forEach((line) => lines.push(line));
    lines.push('');
  }

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

  /* ---------- [Rewrite]（Loon 3.5.1 (978) 新语法） ---------- */
  const rewriteLines = [];
  blocksOfType('rewrite').forEach((block) => {
    (block.data.list || []).forEach((item) => {
      const line = serializeRewrite(item, argNames, add, block.id);
      if (line) rewriteLines.push(line);
    });
  });
  if (rewriteLines.length) {
    lines.push('[Rewrite]');
    rewriteLines.forEach((line) => lines.push(line));
    lines.push('');
  }

  /* ---------- [Host] ---------- */
  const hostLines = [];
  blocksOfType('host').forEach((block) => {
    (block.data.items || []).forEach((item) => {
      const host = (item.name || '').trim();
      const value = (item.value || '').trim();
      if (!host || !value) {
        add('error', 'Host 条目需要同时填写域名和映射值，该行不会生成。', block.id);
        return;
      }
      if (/[\s,]/.test(host)) {
        add('error', `Host 域名 <code>${escapeHtml(host)}</code> 不能包含空格或逗号，该行不会生成。`, block.id);
        return;
      }
      hostLines.push(`${host} = ${value}`);
    });
  });
  if (hostLines.length) {
    lines.push('[Host]');
    hostLines.forEach((line) => lines.push(line));
    lines.push('');
  }

  /* ---------- [Script]（Loon 3.5.1 (983) 新语法） ---------- */
  const scriptLines = [];
  blocksOfType('script').forEach((block) => {
    const line = serializeScript(block.data, argNames, add, block.id);
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

  /* ---------- [Mitm] ---------- */
  const hosts = [];
  blocksOfType('mitm').forEach((block) => {
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
    lines.push('[Mitm]');
    lines.push(`hostname = ${hosts.join(', ')}`);
    lines.push('');
  }

  const needMitm =
    blocksOfType('script').some((b) => /^(request|response)$/.test(b.data.kind || '')) ||
    rewriteLines.length > 0;
  if (needMitm && !hosts.length) {
    add('warn', '脚本要改写 HTTPS 内容 / 复写要生效，必须配置 <code>[Mitm]</code> 主机名，否则不会被执行。');
  }
  if (hosts.length && !needMitm) {
    add('warn', '配置了 <code>[Mitm]</code> 主机名，但插件没有需要解密的脚本或复写，通常可以去掉。');
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

/* ---------- 序列化工具 ---------- */

/** Loon 双引号字符串转义（官方转义表：\" \\ \n \r \t）。
 *  注意：${name} 是模板变量（如捕获引用 ${item.1}），这里刻意不转义——
 *  要输出字面量 ${ 时用户可自己写 \$ 。 */
function quoteLoonString(value) {
  return String(value)
    .replace(/\\/g, '\\\\')
    .replace(/"/g, '\\"')
    .replace(/\r/g, '\\r')
    .replace(/\n/g, '\\n')
    .replace(/\t/g, '\\t');
}

/** 把用户输入的正则规范成 /pattern/flags；extraFlags 会并入（如脚本沿用的 i） */
function wrapRegex(pattern, extraFlags = '') {
  let p = String(pattern).trim();
  let flags = '';
  if (p.startsWith('/')) {
    const last = p.lastIndexOf('/');
    if (last <= 0) return null;
    flags = p.slice(last + 1);
    p = p.slice(1, last);
  }
  if (!p) return null;
  /* 未转义的 / 自动补转义（URL 正则里极其常见），已转义的不动 */
  p = p
    .replace(/\\[\s\S]/g, (m) => `\u0000${m}`)
    .replace(/\//g, '\\/')
    .replace(/\u0000/g, '');
  try {
    new RegExp(p);
  } catch (err) {
    return null;
  }
  const all = new Set((flags + extraFlags).split('').filter((f) => 'ims'.includes(f)));
  return `/${p}/${[...all].join('')}`;
}

const PLUGIN_REF_RE = /\$\{([A-Za-z_]\w*)/g;

/** 扫描 ${name} 引用；返回 true 表示发现未声明的参数（错误已记录） */
function checkPluginRefs(text, argNames, captureName, add, blockId, what) {
  const known = new Set(['url', 'request', 'response', ...argNames]);
  if (captureName) known.add(captureName);
  const unknown = new Set();
  let m;
  PLUGIN_REF_RE.lastIndex = 0;
  while ((m = PLUGIN_REF_RE.exec(text))) {
    if (!known.has(m[1])) unknown.add(m[1]);
  }
  if (!unknown.size) return false;
  unknown.forEach((ident) => {
    add('error', `${what}引用了未声明的参数 <code>\${${ident}}</code>，请在「参数」区块声明或修正拼写。`, blockId);
  });
  return true;
}

/* ---------- [Argument] ---------- */

/** 序列化单个参数：参数名 = 控件类型,值...,type=number,tag=标题,desc=说明 */
function serializeArgument(item, add, blockId) {
  const argName = (item.name || '').trim();
  if (!argName) {
    add('error', '参数缺少参数名，该行不会生成。', blockId);
    return null;
  }
  if (!/^[A-Za-z_]\w*$/.test(argName)) {
    add('error', `参数名 <code>${escapeHtml(argName)}</code> 只能由字母 / 数字 / 下划线组成且不以数字开头，该行不会生成。`, blockId);
    return null;
  }
  const type = ARG_CONTROL_TYPES.some((t) => t.v === item.type) ? item.type : 'input';
  const parts = [type];

  if (type === 'switch') {
    parts.push(item.value === 'false' ? 'false' : 'true');
  } else if (type === 'select') {
    const opts = String(item.options || '').split(',').map((s) => s.trim()).filter(Boolean);
    if (!opts.length) {
      add('error', `参数 <code>${escapeHtml(argName)}</code> 是 select 类型，至少要填一个可选值。`, blockId);
      return null;
    }
    opts.forEach((opt) => {
      parts.push(item.num && /^-?\d+(\.\d+)?$/.test(opt) ? opt : `"${quoteLoonString(opt)}"`);
    });
  } else {
    const value = (item.value || '').trim();
    if (value) {
      if (item.num && !/^-?\d+(\.\d+)?$/.test(value)) {
        add('warn', `参数 <code>${escapeHtml(argName)}</code> 勾选了「数字」但默认值不是数字，Loon 会按 String 解析。`, blockId);
      }
      parts.push(item.num && /^-?\d+(\.\d+)?$/.test(value) ? value : `"${quoteLoonString(value)}"`);
    }
  }

  if (item.num && type !== 'switch') parts.push('type=number');
  const label = (item.tag || '').trim();
  if (/[,=]/.test(label)) add('warn', `参数 <code>${escapeHtml(argName)}</code> 的标题里不要用逗号或等号，会被当成属性分隔。`, blockId);
  if (label) parts.push(`tag=${label}`);
  const desc = (item.desc || '').trim();
  if (desc) parts.push(`desc=${desc}`);

  return `${argName} = ${parts.join(', ')}`;
}

/* ---------- [Rewrite]（978 新语法） ---------- */

/** 序列化一条复写：<phase> if <cond>[ as <name>] then <action>(...) | <action>(...) */
function serializeRewrite(item, argNames, add, blockId) {
  const phase = item.phase === 'response' ? 'response' : 'request';
  const pattern = (item.cond || '').trim();
  if (!pattern) {
    add('error', '复写缺少 URL 匹配正则，该行不会生成。', blockId);
    return null;
  }
  const regex = wrapRegex(pattern);
  if (!regex) {
    add('error', `复写正则 <code>${escapeHtml(pattern)}</code> 无法编译，请检查语法。`, blockId);
    return null;
  }

  const capture = (item.capture || '').trim();
  if (capture) {
    if (!/^[A-Za-z_]\w*$/.test(capture)) {
      add('error', `捕获名 <code>${escapeHtml(capture)}</code> 只能由字母 / 数字 / 下划线组成且不以数字开头。`, blockId);
      return null;
    }
    if (argNames.has(capture)) {
      add('error', `捕获名 <code>${escapeHtml(capture)}</code> 与插件参数重名，Loon 加载时会拒绝。`, blockId);
      return null;
    }
  }

  const list = item.actions || [];
  if (!list.length) {
    add('error', '复写没有任何 Action，该行不会生成。', blockId);
    return null;
  }
  const actions = [];
  list.forEach((action, index) => {
    const text = serializeRewriteAction(action, phase, index, add, blockId);
    if (text) actions.push(text);
  });
  if (actions.length !== list.length) return null;

  /* 官方限制：一条复写最多一个 response.body.mock(_file)，且除它之外只能组合 response.header.* */
  const mocks = list.filter((a) => /^response\.body\.mock(_file)?$/.test(a.v || ''));
  if (mocks.length > 1) {
    add('error', '一条复写只能包含一个 <code>response.body.mock(_file)</code>，该行不会生成。', blockId);
    return null;
  }
  if (mocks.length === 1) {
    const bad = list.find((a) => !/^response\.body\.mock(_file)?$/.test(a.v || '') && !/^response\.header\./.test(a.v || ''));
    if (bad) {
      add('error', `包含响应 Mock 的复写只能搭配 <code>response.header.*</code> Action（当前还含 <code>${escapeHtml(bad.v)}</code>），该行不会生成。`, blockId);
      return null;
    }
  }

  const head = `${phase} if \${url} ~= ${regex}${capture ? ` as ${capture}` : ''} then `;
  const body = actions.join(' | ');
  /* 条件由本工具固定生成（不会引用参数），只需要校验 Action 里的 ${name} */
  if (checkPluginRefs(body, argNames, capture, add, blockId, '这条复写')) return null;
  return head + body;
}

/** 序列化单个 Action：按 REWRITE_ACTIONS 的参数表做类型化输出 */
function serializeRewriteAction(action, phase, index, add, blockId) {
  const meta = REWRITE_ACTIONS.find((a) => a.v === action.v);
  if (!meta) {
    add('error', `复写第 ${index + 1} 个 Action 无效，该行不会生成。`, blockId);
    return null;
  }
  if (meta.phase !== 'both' && meta.phase !== phase) {
    add('error', `<code>${meta.v}</code> 只能用于 ${meta.phase} 阶段，当前复写是 ${phase}，该行不会生成。`, blockId);
    return null;
  }

  const values = [];
  for (let i = 0; i < meta.args.length; i += 1) {
    const spec = meta.args[i];
    const raw = String((action.args || [])[i] || '').trim();
    if (!raw) {
      if (spec.opt) break;
      add('error', `<code>${meta.v}</code> 缺少参数「${spec.n}」，该行不会生成。`, blockId);
      return null;
    }
    if (spec.t === 'N') {
      if (!/^\d+$/.test(raw)) {
        add('error', `<code>${meta.v}</code> 的「${spec.n}」应为数字，当前是 <code>${escapeHtml(raw)}</code>。`, blockId);
        return null;
      }
      if (meta.v === 'redirect' && raw !== '302' && raw !== '307') {
        add('error', `<code>redirect</code> 当前只支持 302 / 307 状态码，该行不会生成。`, blockId);
        return null;
      }
      if (/^reject/.test(meta.v) && (Number(raw) < 100 || Number(raw) > 599)) {
        add('error', `<code>${meta.v}</code> 的状态码必须在 100–599 之间，该行不会生成。`, blockId);
        return null;
      }
      values.push(raw);
    } else if (spec.t === 'R') {
      const regex = wrapRegex(raw);
      if (!regex) {
        add('error', `<code>${meta.v}</code> 的「${spec.n}」不是合法正则，该行不会生成。`, blockId);
        return null;
      }
      values.push(regex);
    } else if (spec.t === 'S') {
      values.push(`"${quoteLoonString(raw)}"`);
    } else {
      values.push(raw);
    }
  }

  return `${meta.v}(${values.join(', ')})`;
}

/* ---------- [Script]（983 新语法） ---------- */

/** 序列化脚本：<kind> [if <cond>] then script("path"[, <argument>]) [with <options>] */
function serializeScript(data, argNames, add, blockId) {
  const meta = SCRIPT_KINDS.find((s) => s.v === data.kind) || SCRIPT_KINDS[1];
  const kind = meta.v;
  const path = (data.path || '').trim();
  if (!path) {
    add('error', '脚本缺少路径，Loon 无法加载脚本，该行不会生成。', blockId);
    return null;
  }

  const match = (data.match || '').trim();
  let head = kind;
  if (meta.cond === true) {
    if (!match) {
      add('error', `<code>${kind}</code> 脚本缺少 URL 匹配正则（response 脚本必需的 URL Guard），该行不会生成。`, blockId);
      return null;
    }
    const regex = wrapRegex(match, 'i');
    if (!regex) {
      add('error', `脚本的 URL 正则 <code>${escapeHtml(match)}</code> 无法编译，请检查语法。`, blockId);
      return null;
    }
    head = `${kind} if \${url} ~= ${regex}`;
  } else if (meta.cond === 'cron') {
    if (!match) {
      add('error', 'cron 脚本缺少 Cron 表达式，该行不会生成。', blockId);
      return null;
    }
    const dynamic = /^\$\{([A-Za-z_]\w*)\}$/.test(match);
    if (dynamic) {
      const ref = match.slice(2, -1);
      if (!argNames.has(ref)) {
        add('error', `动态 Cron 引用了未声明的参数 <code>\${${ref}}</code>，该行不会生成。`, blockId);
        return null;
      }
      head = `cron \${${ref}}`;
    } else {
      const fields = match.split(/\s+/);
      if (fields.length < 5 || fields.length > 6) {
        add('warn', `Cron 表达式 <code>${escapeHtml(match)}</code> 应为 5 段（分 时 日 月 周）或 6 段（秒 分 时 日 月 周）。`, blockId);
      }
      head = `cron "${match.replace(/"/g, '')}"`;
    }
  }

  /* script(...) 第二个参数决定 $argument 类型：省略 / 字符串 / 原始字符串 / 插件对象 */
  const argMode = ARG_MODES.some((m) => m.v === data.argMode) ? data.argMode : 'none';
  let argPart = '';
  if (argMode === 'string' || argMode === 'raw') {
    const value = String(data.argValue || '').trim();
    if (value) {
      argPart = argMode === 'raw'
        ? `, \`${value.replace(/`/g, '``')}\``
        : `, "${quoteLoonString(value)}"`;
    }
  } else if (argMode === 'object') {
    const names = String(data.argValue || '').split(',').map((s) => s.trim()).filter(Boolean);
    if (!names.length) {
      add('error', '对象传参不能为空：至少填一个已在「参数」区块声明的参数名，该行不会生成。', blockId);
      return null;
    }
    const unknown = names.find((n) => !argNames.has(n));
    if (unknown) {
      add('error', `对象传参引用了未声明的参数 <code>${escapeHtml(unknown)}</code>，请在「参数」区块声明，该行不会生成。`, blockId);
      return null;
    }
    if (new Set(names).size !== names.length) {
      add('error', '对象传参里同一个参数被引用了多次，该行不会生成。', blockId);
      return null;
    }
    argPart = `, {${names.map((n) => `\${${n}}`).join(', ')}}`;
  }

  /* with 属性（官方字段：enable / tag / img_url / timeout / debug / requires_body / binary_body_mode） */
  const opts = [];
  const label = (data.tag || '').trim();
  if (label) opts.push(`tag="${quoteLoonString(label)}"`);
  const timeout = String(data.timeout || '').trim();
  if (timeout) {
    if (/^\d+$/.test(timeout) && Number(timeout) > 0) opts.push(`timeout=${timeout}`);
    else add('warn', `脚本的 timeout 应为正整数，当前是 <code>${escapeHtml(timeout)}</code>，已跳过。`, blockId);
  }
  if (meta.body) {
    if (data.requiresBody === 'true') opts.push('requires_body=true');
    if (data.binaryMode === 'true') opts.push('binary_body_mode=true');
  }
  if (data.enable === 'false') opts.push('enable=false');

  const line = `${head} then script("${quoteLoonString(path)}"${argPart})${opts.length ? ` with ${opts.join(', ')}` : ''}`;
  if (checkPluginRefs(line, argNames, null, add, blockId, '这条脚本')) return null;
  return line;
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
      if (/^hostname\s*=/.test(line)) return hlHostLine(line);
      /* 983 脚本行都带 then script(；978 复写行是 phase if ... then action(...) */
      if (/\bthen\s+script\(/.test(line)) return hlScriptLine(line);
      if (/^(request|response)\s+if\s/.test(line)) return hlRewriteLine(line);
      if (/^(AND|OR|NOT),/.test(line)) return hlRuleLine(line);
      if (/^(bypass-tun|skip-proxy|real-ip|dns-server)\s*=/i.test(line)) return hlHostLine(line);
      if (/^[A-Za-z_]\w*\s*=\s*(input|select|switch)\b/.test(line)) return hlHostLine(line);
      if (/^[\w.*-]+\s*=\s*\S+$/.test(line)) return hlHostLine(line);
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

/** key = value 行（Host / General / hostname 等） */
function hlHostLine(line) {
  const idx = line.indexOf('=');
  if (idx < 0) return escapeHtml(line);
  return (
    span('tk-key', escapeHtml(line.slice(0, idx).trim())) +
    span('tk-dim', ' = ') +
    span('tk-str', escapeHtml(line.slice(idx + 1).trim()))
  );
}

/** 高亮 Action 调用串：方法名 + 双引号字符串（先上色字符串，再识别方法名） */
function hlActionList(text) {
  return escapeHtml(text)
    .replace(/&quot;(?:[^&]|&(?!quot;))*&quot;/g, (m) => span('tk-str', m))
    .replace(/(^|[|\s(])(script|[a-z_]+(?:\.[a-z_]+)+)\(/g, (m, pre, name) => `${pre}${span('tk-key', name)}(`);
}

/** with 属性区：k=v 形式 */
function hlOptions(text) {
  return escapeHtml(text).replace(
    /([a-z_]+)=([^,]*)/g,
    (_, key, value) => `${span('tk-key', key)}${span('tk-dim', '=')}${span('tk-str', value)}`
  );
}

/** 978 复写行：<phase> if <cond>[ as <name>] then <actions> */
function hlRewriteLine(line) {
  const ti = line.indexOf(' then ');
  if (ti < 0) return escapeHtml(line);
  const head = line.slice(0, ti);
  const actions = line.slice(ti + 6);
  const m = head.match(/^(request|response)\s+if\s+([\s\S]+?)(?:\s+as\s+([A-Za-z_]\w*))?$/);
  let html = span('tk-type', escapeHtml(m ? m[1] : head));
  if (m) {
    html += span('tk-dim', ' if ') + span('tk-str', escapeHtml(m[2]));
    if (m[3]) html += span('tk-dim', ' as ') + span('tk-key', escapeHtml(m[3]));
  }
  return html + span('tk-dim', ' then ') + hlActionList(actions);
}

/** 983 脚本行：<kind> [if <cond>] then script(...)[ with <options>] */
function hlScriptLine(line) {
  const wi = line.indexOf(' with ');
  const main = wi >= 0 ? line.slice(0, wi) : line;
  const opts = wi >= 0 ? line.slice(wi + 6) : '';
  const ti = main.indexOf(' then ');
  if (ti < 0) return escapeHtml(line);
  const head = main.slice(0, ti);
  const call = main.slice(ti + 6);
  const m = head.match(/^(request|response|cron|network-changed|generic)(?:\s+if\s+([\s\S]+))?$/);
  let html = span('tk-type', escapeHtml(m ? m[1] : head));
  if (m && m[2]) html += span('tk-dim', ' if ') + span('tk-str', escapeHtml(m[2]));
  html = html + span('tk-dim', ' then ') + hlActionList(call);
  if (opts) html += span('tk-dim', ' with ') + hlOptions(opts);
  return html;
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
  if (block.type === 'argument') return renderArgument(block);
  if (block.type === 'general') return renderGeneral(block);
  if (block.type === 'rules') return renderRules(block);
  if (block.type === 'rewrite') return renderRewrite(block);
  if (block.type === 'host') return renderHost(block);
  if (block.type === 'script') return renderScript(block);
  if (block.type === 'mitm') return renderMitm(block);
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

/** [Argument]：name = input,值,tag=标题,desc=说明 / select / switch */
function renderArgument(block) {
  const items = block.data.items || [];
  return `
    <div class="rows">
      ${items
        .map(
          (item, idx) => `
        <div class="row is-argument" data-idx="${idx}">
          <div class="field">
            <label>参数名</label>
            <input type="text" data-field="name" value="${escapeHtml(item.name || '')}" placeholder="token" />
          </div>
          <div class="field">
            <label>控件类型</label>
            <select data-field="type">${optionsHtml(ARG_CONTROL_TYPES, item.type || 'input')}</select>
          </div>
          <div class="field">
            <label>${item.type === 'select' ? '可选值（第一个为默认）' : '默认值'}</label>
            ${
              item.type === 'switch'
                ? `<select data-field="value">${optionsHtml([{ v: 'true', label: 'true' }, { v: 'false', label: 'false' }], item.value === 'false' ? 'false' : 'true')}</select>`
                : `<input type="text" data-field="${item.type === 'select' ? 'options' : 'value'}" value="${escapeHtml(item.type === 'select' ? item.options || '' : item.value || '')}" placeholder="${item.type === 'select' ? 'CN, US, JP' : '默认内容，可留空'}" />`
            }
          </div>
          <div class="field">
            <label>标题 · tag</label>
            <input type="text" data-field="tag" value="${escapeHtml(item.tag || '')}" placeholder="参数标题" />
          </div>
          <div class="row-actions">
            ${item.type !== 'switch' ? `<label class="check" title="加 type=number，条件里按数字比较"><input type="checkbox" data-field="num" ${item.num ? 'checked' : ''} />数字</label>` : ''}
            <button class="btn-icon is-danger" type="button" data-act="del-arg" data-idx="${idx}" title="删除参数" aria-label="删除参数">${ICONS.trash}</button>
          </div>
          <div class="field span-all">
            <label>说明 · desc（可选）</label>
            <input type="text" data-field="desc" value="${escapeHtml(item.desc || '')}" placeholder="显示给用户看的参数说明" />
          </div>
        </div>`
        )
        .join('')}
    </div>
    <button class="btn btn-sm add-row" type="button" data-act="add-arg" data-id="${block.id}">＋ 添加参数</button>
    <div class="note-box">参数会在 Loon 里生成设置界面；在复写 / 脚本的条件或 <code>with</code> 属性里用 <code>\${name}</code> 引用。select 的第一个值为默认值；勾选「数字」会输出 <code>type=number</code>。</div>`;
}

/** [General]：只有 bypass-tun / skip-proxy / real-ip / dns-server 四个字段 */
function renderGeneral(block) {
  return `
    <div class="grid">
      ${GENERAL_FIELDS.map(
        (f) => `
      <div class="field span-all">
        <label>${escapeHtml(f.label)}</label>
        <input type="text" data-field="${f.k}" value="${escapeHtml(block.data[f.k] || '')}" placeholder="${escapeHtml(f.ph)}" />
      </div>`
      ).join('')}
    </div>
    <div class="note-box">留空的字段不会输出；插件里 <code>[General]</code> 只支持这四个字段。</div>`;
}

/** [Host]：域名 = IP / 别名 / server:DNS / ip-mode:... */
function renderHost(block) {
  const items = block.data.items || [];
  return `
    <div class="rows">
      ${items
        .map(
          (item, idx) => `
        <div class="row is-host" data-idx="${idx}">
          <div class="field">
            <label>域名</label>
            <input type="text" data-field="name" value="${escapeHtml(item.name || '')}" placeholder="example.com 或 *.example.com" />
          </div>
          <div class="field grow">
            <label>映射值</label>
            <input type="text" data-field="value" value="${escapeHtml(item.value || '')}" placeholder="192.168.1.20 / server:8.8.4.4" />
          </div>
          <div class="row-actions">
            <button class="btn-icon is-danger" type="button" data-act="del-host" data-idx="${idx}" title="删除映射" aria-label="删除映射">${ICONS.trash}</button>
          </div>
        </div>`
        )
        .join('')}
    </div>
    <button class="btn btn-sm add-row" type="button" data-act="add-host" data-id="${block.id}">＋ 添加映射</button>
    <div class="note-box">值支持固定 IP、别名域名、<code>server:8.8.4.4</code>（指定 DNS）、<code>server:system</code>、<code>ip-mode:ipv4-only</code>，以及 <code>ssid:名称</code> 作为域名。</div>`;
}

function renderMitm(block) {
  return `
    <div class="field">
      <label>解密主机名 · hostname =</label>
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

/** [Rewrite]（978 新语法）：一条复写 = 阶段 + URL 正则 + 可选捕获名 + 多个 Action */
function renderRewrite(block) {
  const list = block.data.list || [];
  return `
    <div class="rows">
      ${list
        .map((item, idx) => {
          const phase = item.phase === 'response' ? 'response' : 'request';
          const compatible = REWRITE_ACTIONS.filter((a) => a.phase === 'both' || a.phase === phase);
          const actions = item.actions || [];
          return `
        <div class="rewrite-item" data-idx="${idx}">
          <div class="row is-rewrite">
            <div class="field">
              <label>阶段</label>
              <select data-field="phase">${optionsHtml(REWRITE_PHASES, phase)}</select>
            </div>
            <div class="field grow">
              <label>URL 匹配正则</label>
              <input type="text" data-field="cond" value="${escapeHtml(item.cond || '')}" placeholder="^https?:\\/\\/api\\.example\\.com" />
            </div>
            <div class="field">
              <label>捕获名 as（可选）</label>
              <input type="text" data-field="capture" value="${escapeHtml(item.capture || '')}" placeholder="item" />
            </div>
            <div class="row-actions">
              <button class="btn-icon is-danger" type="button" data-act="del-rewrite" data-idx="${idx}" title="删除复写" aria-label="删除复写">${ICONS.trash}</button>
            </div>
          </div>
          <div class="action-list">
            ${actions
              .map((action, aidx) => {
                const meta = REWRITE_ACTIONS.find((a) => a.v === action.v);
                const opts = compatible.some((a) => a.v === action.v)
                  ? compatible
                  : [{ v: action.v, label: `${action.v} · 阶段不符` }, ...compatible];
                return `
              <div class="row is-action" data-aidx="${aidx}">
                <div class="field">
                  <label>Action</label>
                  <select data-field="action-v">${optionsHtml(opts, action.v)}</select>
                </div>
                ${((meta && meta.args) || [])
                  .map(
                    (arg, gidx) => `
                <div class="field">
                  <label>${escapeHtml(arg.n)}${arg.opt ? '（可选）' : ''}</label>
                  <input type="text" data-field="action-arg" data-argidx="${gidx}" value="${escapeHtml((action.args || [])[gidx] || '')}" placeholder="${escapeHtml(arg.ph || '')}" />
                </div>`
                  )
                  .join('')}
                <div class="row-actions">
                  <button class="btn-icon is-danger" type="button" data-act="del-action" data-idx="${idx}" data-aidx="${aidx}" title="删除 Action" aria-label="删除 Action">${ICONS.trash}</button>
                </div>
              </div>`;
              })
              .join('')}
            <button class="btn btn-sm add-row" type="button" data-act="add-action" data-idx="${idx}">＋ 添加 Action</button>
          </div>
        </div>`;
        })
        .join('')}
    </div>
    <button class="btn btn-sm add-row" type="button" data-act="add-rewrite" data-id="${block.id}">＋ 添加复写</button>
    <div class="note-box">输出形如 <code>request if \${url} ~= /正则/ as item then Action(参数) | Action(参数)</code>。字符串参数自动加引号，正则参数包进 /…/；<code>url.replace</code> / <code>redirect</code> 替换 URL 正则命中的部分，可用 <code>\${捕获名.1}</code> 引用捕获。含响应 Mock 的复写只能搭配 <code>response.header.*</code>。</div>`;
}

/** [Script]（983 新语法）：kind [if 条件] then script(path[, argument]) [with ...] */
function renderScript(block) {
  const d = block.data;
  const meta = SCRIPT_KINDS.find((s) => s.v === d.kind) || SCRIPT_KINDS[1];
  const isHttp = meta.cond === true;
  const argMode = ARG_MODES.some((m) => m.v === d.argMode) ? d.argMode : 'none';
  return `
    <div class="grid">
      <div class="field">
        <label>脚本类型</label>
        <select data-field="kind">${optionsHtml(SCRIPT_KINDS, meta.v)}</select>
      </div>
      <div class="field">
        <label>${meta.cond === 'cron' ? 'Cron 表达式（可写 ${参数名} 动态取值）' : isHttp ? 'URL 匹配正则' : '（该类型无需条件）'}</label>
        <input type="text" data-field="match" value="${escapeHtml(d.match || '')}" ${meta.cond ? '' : 'disabled'} placeholder="${meta.cond === 'cron' ? '0 8 * * *' : '^https?:\\/\\/api\\.example\\.com\\/v1\\/user'}" />
      </div>
      <div class="field">
        <label>标签 · tag</label>
        <input type="text" data-field="tag" value="${escapeHtml(d.tag || '')}" placeholder="DemoUser" />
      </div>
      <div class="field">
        <label>超时（秒，可留空）</label>
        <input type="number" min="1" data-field="timeout" value="${escapeHtml(d.timeout || '')}" />
      </div>
      <div class="field">
        <label>脚本文件名（导出用）</label>
        <input type="text" data-field="file" value="${escapeHtml(d.file || 'script.js')}" placeholder="demo.js" />
      </div>
      <div class="field">
        <label>启用 · enable</label>
        <select data-field="enable">${optionsHtml([{ v: 'true', label: 'true · 启用' }, { v: 'false', label: 'false · 停用' }], d.enable || 'true')}</select>
      </div>
      ${isHttp ? `
      <div class="field">
        <label>requires_body</label>
        <select data-field="requiresBody">${optionsHtml([{ v: 'true', label: 'true · 等待完整 Body' }, { v: 'false', label: 'false' }], d.requiresBody || 'true')}</select>
      </div>
      <div class="field">
        <label>binary_body_mode</label>
        <select data-field="binaryMode">${optionsHtml([{ v: 'false', label: 'false' }, { v: 'true', label: 'true · 二进制 Body' }], d.binaryMode || 'false')}</select>
      </div>` : ''}
      <div class="field">
        <label>$argument 传参方式</label>
        <select data-field="argMode">${optionsHtml(ARG_MODES, argMode)}</select>
      </div>
      ${argMode === 'none' ? '' : `
      <div class="field span-all">
        <label>${argMode === 'object' ? '对象参数（逗号分隔的参数名，需已在「参数」区块声明）' : argMode === 'raw' ? '原始字符串内容（按反引号原始字符串输出）' : '字符串参数内容'}</label>
        <input type="text" data-field="argValue" value="${escapeHtml(d.argValue || '')}" placeholder="${argMode === 'object' ? 'token, region' : argMode === 'raw' ? '{"a":1}' : 'a=1&b=2'}" />
      </div>`}
      <div class="field span-all">
        <label>script 路径</label>
        <input type="text" data-field="path" value="${escapeHtml(d.path || '')}" placeholder="https://.../scripts/demo.js 或 demo.js" />
        <span class="hint">远程脚本填完整 https 链接；本地脚本填文件名，并把 .js 放到 Loon 的脚本目录。</span>
      </div>
      <div class="field span-all">
        <label>脚本代码（不写入 .plugin，需单独导出为 .js）</label>
        <textarea data-field="code" rows="8">${escapeHtml(d.code || '')}</textarea>
      </div>
    </div>
    <div class="note-box">输出形如 <code>response if \${url} ~= /正则/i then script("path", {\${token}}) with tag="…", timeout=10, requires_body=true</code>。response 脚本必须带 URL 正则（URL Guard）；对象传参会把参数打包成 <code>$argument</code> 对象。</div>`;
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
  el.canvas.addEventListener('change', onCanvasField);
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

  if (action === 'add-arg') {
    (block.data.items = block.data.items || []).push({ name: '', type: 'input', value: '', options: '', tag: '', desc: '', num: false });
    afterStructureChange();
    return;
  }

  if (action === 'del-arg') {
    block.data.items.splice(Number(btn.dataset.idx), 1);
    afterStructureChange();
    return;
  }

  if (action === 'add-host') {
    (block.data.items = block.data.items || []).push({ name: '', value: '' });
    afterStructureChange();
    return;
  }

  if (action === 'del-host') {
    block.data.items.splice(Number(btn.dataset.idx), 1);
    afterStructureChange();
    return;
  }

  if (action === 'add-rewrite') {
    const phase = 'request';
    (block.data.list = block.data.list || []).push({
      phase,
      cond: '',
      capture: '',
      actions: [{ v: 'request.header.add', args: ['', ''] }]
    });
    afterStructureChange();
    return;
  }

  if (action === 'del-rewrite') {
    block.data.list.splice(Number(btn.dataset.idx), 1);
    afterStructureChange();
    return;
  }

  if (action === 'add-action') {
    const item = block.data.list[Number(btn.dataset.idx)];
    if (!item) return;
    /* 新 Action 默认选 header.add（与所在阶段匹配），参数位按方法签名补空 */
    const preferred = REWRITE_ACTIONS.find((a) => a.v === (item.phase === 'response' ? 'response.header.add' : 'request.header.add'));
    const meta = preferred || REWRITE_ACTIONS.find((a) => a.phase === 'both' || a.phase === (item.phase || 'request'));
    item.actions.push({ v: meta.v, args: meta.args.map(() => '') });
    afterStructureChange();
    return;
  }

  if (action === 'del-action') {
    const item = block.data.list[Number(btn.dataset.idx)];
    if (!item) return;
    item.actions.splice(Number(btn.dataset.aidx), 1);
    afterStructureChange();
    return;
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
function onCanvasField(event) {
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

  /* ---------- [Argument] ---------- */
  if (block.type === 'argument') {
    const row = input.closest('[data-idx]');
    const item = block.data.items[Number(row ? row.dataset.idx : -1)];
    if (!item) return;
    if (field === 'type') {
      item.type = value;
      if (value === 'switch' && item.value !== 'false') item.value = 'true';
      afterStructureChange();
      return;
    }
    if (field === 'num') {
      item.num = input.checked;
      afterStructureChange();
      return;
    }
    item[field] = value;
    renderPreview();
    scheduleSave();
    return;
  }

  /* ---------- [General] / [Mitm]：平铺字段 ---------- */
  if (block.type === 'general' || block.type === 'mitm') {
    block.data[field] = value;
    renderPreview();
    scheduleSave();
    return;
  }

  /* ---------- [Host] ---------- */
  if (block.type === 'host') {
    const row = input.closest('[data-idx]');
    const item = block.data.items[Number(row ? row.dataset.idx : -1)];
    if (!item) return;
    item[field] = value;
    renderPreview();
    scheduleSave();
    return;
  }

  /* ---------- [Script] ---------- */
  if (block.type === 'script') {
    /* 类型 / 传参方式会改变表单结构，重绘；其余只更新数据，避免输入框失焦 */
    if (field === 'kind' || field === 'argMode') {
      block.data[field] = value;
      afterStructureChange();
      return;
    }
    block.data[field] = value;
    renderPreview();
    scheduleSave();
    return;
  }

  /* ---------- [Rewrite]：嵌套的 Action 列表 ---------- */
  if (block.type === 'rewrite') {
    const row = input.closest('[data-idx]');
    const item = block.data.list[Number(row ? row.dataset.idx : -1)];
    if (!item) return;
    if (field === 'phase') {
      item.phase = value;
      afterStructureChange();
      return;
    }
    if (field === 'action-v') {
      const arow = input.closest('[data-aidx]');
      const act = item.actions[Number(arow ? arow.dataset.aidx : -1)];
      if (!act) return;
      const meta = REWRITE_ACTIONS.find((a) => a.v === value);
      if (!meta) return;
      act.v = value;
      /* 参数位数量随新 Action 的方法签名变化，已有的输入尽量保留 */
      act.args = meta.args.map((_, i) => act.args[i] || '');
      afterStructureChange();
      return;
    }
    if (field === 'action-arg') {
      const arow = input.closest('[data-aidx]');
      const act = item.actions[Number(arow ? arow.dataset.aidx : -1)];
      if (!act) return;
      act.args[Number(input.dataset.argidx)] = value;
      renderPreview();
      scheduleSave();
      return;
    }
    item[field] = value;
    renderPreview();
    scheduleSave();
    return;
  }

  /* ---------- 其余：details / rules ---------- */
  if (block.type === 'details') {
    block.data[field] = value;
  } else if (block.type === 'rules') {
    const cond = resolveCondition(block.data.root, input.dataset.path || 'root');
    if (!cond) return;
    cond[field] = value;
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
