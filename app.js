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

/* ========================= [Rewrite]（978 新语法） =========================
 * 依据官方 Rewrite 配置生成器 https://nsloon.app/rewrite-builder
 *   一条复写：<phase> if <条件树> then <Action>(…) | <Action>(…)
 *   条件树：group{logic, items[]}，item 可是 condition 或嵌套 group，AND=&& / OR=||
 *   Action：同一 Action 可填多组参数，多组时自动生成数组批量语法
 */

/** 复写阶段 */
const REWRITE_PHASES = [
  { v: 'request', label: 'request · 请求发出前', hint: '请求发出前' },
  { v: 'response', label: 'response · 收到响应 Header 后', hint: '收到响应 Header 后' }
];

/** 条件字段：phases 限定该字段可用于哪些阶段；header=需填 Header 名；variable=需填参数名 */
const REWRITE_FIELDS = [
  { v: 'url', label: 'URL', phases: ['request', 'response'] },
  { v: 'request.method', label: '请求方法', phases: ['request', 'response'] },
  { v: 'request.header', label: '请求 Header', phases: ['request', 'response'], header: true },
  { v: 'response.status', label: '响应状态码', phases: ['response'] },
  { v: 'response.header', label: '响应 Header', phases: ['response'], header: true },
  { v: 'plugin', label: '插件参数', phases: ['request', 'response'], variable: true }
];

/** 条件操作符 */
const REWRITE_OPS = [
  { v: '==', label: '等于 ==' },
  { v: '~=', label: '正则匹配 ~=' }
];

/** URL 构建器的协议选项：any → https?（同时匹配 http / https） */
const URL_SCHEMES = [
  { v: 'https', label: 'https' },
  { v: 'http', label: 'http' },
  { v: 'any', label: 'http(s)' }
];

/** 比较值类型：ops 限定可用操作符；regex 只用于正则匹配 */
const REWRITE_VALUE_TYPES = [
  { v: 'regex', label: '正则', ops: ['~='] },
  { v: 'variable', label: '插件参数', ops: ['==', '~='] },
  { v: 'string', label: '字符串', ops: ['=='] },
  { v: 'number', label: '数字', ops: ['=='] },
  { v: 'boolean', label: '布尔值', ops: ['=='] },
  { v: 'null', label: 'null', ops: ['=='] },
  { v: 'template', label: '模板字符串', ops: ['=='] },
  { v: 'raw', label: 'Raw 反引号', ops: ['=='] },
  { v: 'syntax', label: 'Raw Syntax 原样', ops: ['=='] }
];

/** reject 的响应类型 → 实际方法名 */
const REJECT_MODES = [
  { v: 'empty', label: '空 Body' },
  { v: 'custom', label: '自定义文本' },
  { v: 'image', label: '1×1 GIF' },
  { v: 'json-object', label: 'JSON 对象 {}' },
  { v: 'json-array', label: 'JSON 数组 []' },
  { v: 'video', label: '空白视频' }
];
const REJECT_MODE_MAP = {
  image: 'reject_img',
  'json-object': 'reject_dict',
  'json-array': 'reject_array',
  video: 'reject_video'
};

/** Mock Body 的类型 */
const MOCK_TYPES = ['json', 'text', 'css', 'html', 'javascript', 'plain', 'png', 'gif', 'jpeg', 'tiff', 'svg', 'mp4', 'form-data'].map((v) => ({
  v,
  label: v
}));
/** Mock / jq 的数据来源：直接填写 → mock(…)，插件文件 → mock_file(…) / jq_file(…) */
const MOCK_SOURCES = [
  { v: 'data', label: '直接填写' },
  { v: 'file', label: '插件文件' }
];
const JQ_SOURCES = [
  { v: 'filter', label: 'jq 表达式' },
  { v: 'file', label: '插件文件' }
];

/**
 * 生成 request / response 同构的 Action，避免手写 16 条重复定义
 * @param {string} scope request | response
 * @param {Object} overrides 按 key 覆盖官网默认值
 */
function scopedActions(scope, overrides) {
  const zh = scope === 'response' ? '响应' : '请求';
  const table = {
    'header.add': { label: `添加${zh} Header`, group: `${zh} Header`, fields: ['name', 'value'], batch: true, defaults: { name: 'X-Loon', value: 'true' } },
    'header.set': { label: `设置${zh} Header`, group: `${zh} Header`, fields: ['name', 'value'], batch: true, defaults: { name: 'X-Loon', value: 'true' } },
    'header.del': { label: `删除${zh} Header`, group: `${zh} Header`, fields: ['name'], batch: true, defaults: { name: 'Cookie' } },
    'header.replace': {
      label: `正则替换${zh} Header`,
      group: `${zh} Header`,
      fields: ['name', 'pattern', 'replacement'],
      batch: true,
      defaults: { name: 'User-Agent', pattern: 'iPhone OS \\d+', flags: '', replacement: 'iPhone OS 18' }
    },
    'body.replace': {
      label: `正则替换${zh} Body`,
      group: `${zh} Body / JSON`,
      fields: ['pattern', 'replacement'],
      batch: true,
      defaults: { pattern: '"price":\\s*[0-9.]+', flags: '', replacement: '"price":9.99' }
    },
    'json.add': {
      label: `添加${zh} JSON 字段`,
      group: `${zh} Body / JSON`,
      fields: ['path', 'value'],
      batch: true,
      jsonValue: true,
      defaults: { path: 'data.price', valueType: 'number', value: '9.99' }
    },
    'json.delete': { label: `删除${zh} JSON 字段`, group: `${zh} Body / JSON`, fields: ['path'], batch: true, defaults: { path: 'data.ads' } },
    'json.replace': {
      label: `替换${zh} JSON 字段`,
      group: `${zh} Body / JSON`,
      fields: ['path', 'value'],
      batch: true,
      jsonValue: true,
      defaults: { path: 'data.vip', valueType: 'boolean', value: 'true' }
    }
  };
  const out = {};
  Object.keys(table).forEach((key) => {
    const meta = table[key];
    out[`${scope}.${key}`] = {
      phase: scope,
      label: meta.label,
      group: meta.group,
      fields: meta.fields,
      batch: meta.batch,
      jsonValue: meta.jsonValue,
      defaults: Object.assign({}, meta.defaults, overrides[key] || {})
    };
  });
  return out;
}

/**
 * Action 速查表（方法签名与官方生成器一致）
 * v: 方法名 / label: 中文名 / phase: 所属阶段 / group: 下拉分组
 * fields: 表单字段顺序 / batch: 支持多组参数（批量语法）/ defaults: 新建时的默认值
 */
const REWRITE_ACTIONS = {
  'url.replace': { label: '替换 URL', phase: 'request', group: '请求控制', fields: ['replacement'], defaults: { replacement: 'https://example.com' } },
  redirect: { label: '返回重定向', phase: 'request', group: '请求控制', fields: ['status', 'location'], defaults: { status: '302', location: 'https://new.example.com' } },
  reject: { label: '拒绝请求', phase: 'request', group: '请求控制', fields: ['mode', 'status', 'body'], defaults: { mode: 'json-object', status: '200', body: '' } },
  ...scopedActions('request', {
    'json.replace': { path: 'data.price', valueType: 'variable', value: 'price' }
  }),
  ...scopedActions('response', {
    'header.set': { name: 'Cache-Control', value: 'no-cache' },
    'header.del': { name: 'Set-Cookie' },
    'header.replace': { name: 'Content-Type', pattern: '; charset=.+$', flags: 'i', replacement: '' },
    'body.replace': { pattern: '"enabled":\\s*false', flags: '', replacement: '"enabled":true' },
    'json.add': { path: 'data.rewritten', valueType: 'boolean', value: 'true' },
    'json.replace': { path: 'data.vip', valueType: 'boolean', value: 'true' }
  }),
  'request.json.jq': {
    label: '使用 jq 修改请求 JSON',
    phase: 'request',
    group: '请求 Body / JSON',
    fields: ['source', 'filter', 'file'],
    defaults: { source: 'filter', filter: '.data.ads = []', file: 'request-filter.jq' }
  },
  'response.json.jq': {
    label: '使用 jq 修改响应 JSON',
    phase: 'response',
    group: '响应 Body / JSON',
    fields: ['source', 'filter', 'file'],
    defaults: { source: 'filter', filter: '.data.ads = []', file: 'response-filter.jq' }
  },
  'request.body.mock': {
    label: 'Mock 请求 Body',
    phase: 'request',
    group: '请求 Body / JSON',
    fields: ['type', 'source', 'data', 'file', 'raw', 'base64'],
    defaults: { type: 'json', source: 'data', data: '{"price":9.99}', file: 'request_body.json', raw: true, base64: false }
  },
  'response.body.mock': {
    label: 'Mock 响应 Body',
    phase: 'response',
    group: '响应 Body / JSON',
    fields: ['type', 'source', 'data', 'file', 'raw', 'base64', 'status'],
    defaults: { type: 'json', source: 'data', data: '{"code":0,"message":"ok"}', file: 'response_body.json', raw: true, base64: false, status: '200' }
  }
};

/** Action 下拉分组（与官方生成器一致） */
const REWRITE_ACTION_GROUPS = [
  { label: '请求控制', actions: ['url.replace', 'redirect', 'reject'] },
  { label: '请求 Header', actions: ['request.header.add', 'request.header.set', 'request.header.del', 'request.header.replace'] },
  { label: '请求 Body / JSON', actions: ['request.body.replace', 'request.json.add', 'request.json.delete', 'request.json.replace', 'request.json.jq', 'request.body.mock'] },
  { label: '响应 Header', actions: ['response.header.add', 'response.header.set', 'response.header.del', 'response.header.replace'] },
  { label: '响应 Body / JSON', actions: ['response.body.replace', 'response.json.add', 'response.json.delete', 'response.json.replace', 'response.json.jq', 'response.body.mock'] }
];

/** 官方生成器的三套默认示例（照抄，作为「载入官方示例」与新建插件的默认模板） */
function rewritePreset(kind) {
  const presets = {
    request: {
      label: '请求 Header 清理',
      phase: 'request',
      conditions: { logic: '&&', items: [
        { kind: 'condition', field: 'url', operator: '~=', valueType: 'regex', value: '^https:\\/\\/api\\.example\\.com', flags: '', headerName: '', variableName: '', captureName: '' },
        { kind: 'condition', field: 'request.method', operator: '==', valueType: 'string', value: 'POST', flags: '', headerName: '', variableName: '', captureName: '' }
      ] },
      actions: [
        { type: 'request.header.set', groups: [{ name: 'X-Loon', value: 'true' }] },
        { type: 'request.header.del', groups: [{ name: 'Cookie' }] }
      ]
    },
    response: {
      label: '修改 JSON 响应',
      phase: 'response',
      conditions: { logic: '&&', items: [
        { kind: 'condition', field: 'url', operator: '~=', valueType: 'regex', value: '^https:\\/\\/api\\.example\\.com\\/profile$', flags: '', headerName: '', variableName: '', captureName: '' },
        { kind: 'condition', field: 'response.status', operator: '==', valueType: 'number', value: '200', flags: '', headerName: '', variableName: '', captureName: '' },
        { kind: 'condition', field: 'response.header', operator: '~=', valueType: 'regex', value: '^application\\/json(?:;|$)', flags: 'i', headerName: 'Content-Type', variableName: '', captureName: '' }
      ] },
      actions: [
        { type: 'response.json.replace', groups: [{ path: 'data.vip', valueType: 'boolean', value: 'true' }] },
        { type: 'response.header.set', groups: [{ name: 'X-Rewritten', value: 'true' }] }
      ]
    },
    mock: {
      label: 'Mock JSON 响应',
      phase: 'response',
      conditions: { logic: '&&', items: [
        { kind: 'condition', field: 'url', operator: '~=', valueType: 'regex', value: '^https:\\/\\/api\\.example\\.com\\/mock$', flags: '', headerName: '', variableName: '', captureName: '' }
      ] },
      actions: [
        { type: 'response.body.mock', groups: [{ type: 'json', source: 'data', data: '{"code":0,"message":"ok"}', file: 'response_body.json', raw: true, base64: false, status: '200' }] }
      ]
    }
  };
  return presets[kind];
}

/** 新建一条空白复写：只含 IF（空条件树）+ THEN（空 Action 列表）。
 *  复写区块固定为单条结构，不再支持「添加复写」「载入官方示例」。 */
function emptyRewriteItem() {
  return {
    phase: 'request',
    conditions: { logic: '&&', items: [] },
    actions: []
  };
}

/** 递归统计条件树中的叶子条件数（用于头部摘要展示） */
function countRewriteConds(node) {
  if (!node || !Array.isArray(node.items)) return 0;
  return node.items.reduce((sum, child) => sum + (child && child.kind === 'group' ? countRewriteConds(child) : 1), 0);
}

/** 新建条件时的默认值（照抄官方生成器） */
function newCondition(overrides) {
  return Object.assign(
    { kind: 'condition', field: 'url', operator: '~=', valueType: 'regex', value: '^https:\\/\\/example\\.com', flags: '', headerName: '', variableName: '', captureName: '' },
    overrides
  );
}

/** URL 构建器的默认部件 */
function defaultUrlParts() {
  return { scheme: 'https', host: 'example.com', port: '', path: '', query: '', exact: false };
}

/** 已转义的字符保持不动，未转义的补上反斜杠（避免把 \. \/ 二次转义成 \\. \\/） */
function escapeRegexChar(text, ch) {
  return String(text).replace(new RegExp(`\\\\?\\${ch}`, 'g'), (m) => (m.length === 2 ? m : `\\${ch}`));
}

/** 把 URL 部件拼成正则源（不含 / 分隔符与 flags；输出时再经 wrapRegex 兜底） */
function buildUrlRegex(parts) {
  const p = parts || {};
  const scheme = p.scheme === 'http' ? 'http' : p.scheme === 'any' ? 'https?' : 'https';
  const host = escapeRegexChar(String(p.host || '').trim(), '.');
  let src = `^${scheme}:\\/\\/${host}`;
  const port = String(p.port || '').trim();
  if (port) src += `:${port}`;
  const path = escapeRegexChar(String(p.path || '').trim().replace(/^\/+/, ''), '/');
  if (path) src += `\\/${path}`;
  const query = escapeRegexChar(String(p.query || '').trim().replace(/^\?+/, ''), '/');
  if (query) src += `\\?${query}`;
  if (p.exact) src += '$';
  return src;
}

/** 尝试把正则源解析回 URL 部件；无法识别（手写复杂正则）时返回 null，回退到手写输入 */
function parseUrlRegex(src) {
  let p = String(src || '').trim();
  if (!p) return null;
  /* 用户可能把 /…/ 分隔符也写了进来 */
  if (p.charAt(0) === '/') {
    const last = p.lastIndexOf('/');
    if (last > 0) p = p.slice(1, last);
  }
  const exact = p.charAt(p.length - 1) === '$';
  if (p.charAt(0) === '^') p = p.slice(1);
  if (exact) p = p.slice(0, -1);

  let scheme;
  if (p.startsWith('https?')) {
    scheme = 'any';
    p = p.slice(6);
  } else if (p.startsWith('https')) {
    scheme = 'https';
    p = p.slice(5);
  } else if (p.startsWith('http')) {
    scheme = 'http';
    p = p.slice(4);
  } else {
    return null;
  }
  /* :// 分隔符可能已转义成 :\/\/ */
  if (p.startsWith(':\\/\\/')) p = p.slice(5);
  else if (p.startsWith('://')) p = p.slice(3);
  else return null;

  let host = '';
  let port = '';
  let path = '';
  let query = '';
  let stage = 'host';
  let i = 0;
  while (i < p.length) {
    const c = p[i];
    const two = p.slice(i, i + 2);
    const isPathSep = two === '\\/' || c === '/';
    const isQuerySep = two === '\\?' || c === '?';
    if (stage === 'host' && c === ':') {
      stage = 'port';
      i += 1;
      continue;
    }
    /* 注意：path 阶段内的 \/ 是路径内容（转义斜杠），只有从 host/port 切入时才是分隔符 */
    if (isPathSep && (stage === 'host' || stage === 'port')) {
      stage = 'path';
      i += two === '\\/' ? 2 : 1;
      continue;
    }
    if (isQuerySep && stage !== 'query') {
      stage = 'query';
      i += two === '\\?' ? 2 : 1;
      continue;
    }
    if (stage === 'host') host += c;
    else if (stage === 'port') port += c;
    else if (stage === 'path') path += c;
    else query += c;
    i += 1;
  }
  if (!host) return null;
  return {
    scheme,
    host: host.replace(/\\\./g, '.'),
    port,
    path: path.replace(/\\\//g, '/'),
    query: query.replace(/\\\//g, '/'),
    exact
  };
}

/** 取条件的 URL 部件：优先用已存部件，否则尝试从正则值解析；解析失败返回 null */
function ensureUrlParts(cond) {
  if (cond.urlParts && typeof cond.urlParts === 'object') return cond.urlParts;
  const parsed = parseUrlRegex(cond.value);
  if (!parsed) return null;
  cond.urlParts = parsed;
  return cond.urlParts;
}

/** 新建一个 Action（参数组默认取官方默认值） */
function newAction(type) {
  const meta = REWRITE_ACTIONS[type] || REWRITE_ACTIONS['request.header.set'];
  return { type: meta.phase ? type : 'request.header.set', groups: [Object.assign({}, meta.defaults)] };
}

/** 官方示例的键与中文名 */
const REWRITE_PRESET_KEYS = [
  { v: 'request', label: '请求 Header 清理' },
  { v: 'response', label: '修改 JSON 响应' },
  { v: 'mock', label: 'Mock JSON 响应' }
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

/** 区块默认数据（内容对齐官方示例插件：https://nsloon.app/docs/Plugin/） */
const BLOCK_TEMPLATES = {
  details: {
    type: 'details',
    data: {
      name: 'Demo Plugin',
      desc: '展示插件信息和用户参数',
      author: 'kyler404',
      homepage: 'https://github.com/kyler404/loon-plugin-demo',
      icon: 'https://raw.githubusercontent.com/kyler404/loon-plugin-demo/main/assets/icon.png',
      system: 'iOS,iPadOS,tvOS,macOS',
      systemVersion: '15',
      loonVersion: '3.4.0(962)',
      tag: '示例,工具',
      pluginType: 'normal'
    }
  },
  argument: {
    type: 'argument',
    data: {
      items: [
        { name: 'name',    type: 'input',  value: 'Loon',        options: '',         tag: '名称', desc: '输入一个名称', num: false },
        { name: 'region',  type: 'select', value: 'CN',          options: 'CN,US,JP', tag: '地区', desc: '',              num: false },
        { name: 'enabled', type: 'switch', value: 'true',        options: '',         tag: '启用', desc: '',              num: false }
      ]
    }
  },
  general: {
    type: 'general',
    data: { bypassTun: '', skipProxy: '', realIp: '', dnsServer: '' }
  },
  rules: {
    type: 'rules',
    data: {
      root: { conditions: [] }
    }
  },
  /* 复写区块：固定单条结构（IF + THEN），不再支持「添加复写」「载入官方示例」 */
  rewrite: {
    type: 'rewrite',
    data: { list: [emptyRewriteItem()] }
  },
  host: {
    type: 'host',
    data: { items: [] }
  },
  script: {
    type: 'script',
    data: {
      syntax: 'legacy',
      kind: 'response',
      match: '^https?:\\/\\/example\\.com\\/conf\\/server-mapping',
      path: 'https://raw.githubusercontent.com/kyler404/loon-plugin-demo/main/scripts/demo.js',
      file: 'demo.js',
      tag: '移除广告',
      timeout: '',
      enable: 'true',
      requiresBody: 'true',
      binaryMode: 'false',
      argMode: 'object',
      argValue: 'name,region,enabled',
      code: ''
    }
  },
  mitm: {
    type: 'mitm',
    data: { hosts: 'example.com' }
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

/* ---------- 旧版草稿迁移：v2 初版复写条目 → 官网 rewrite-builder 结构 ---------- */

/** 推断 JSON 值类型（旧版把值存成纯字符串） */
function inferLoonValueType(v) {
  const s = String(v);
  if (/^-?\d+(\.\d+)?$/.test(s)) return 'number';
  if (s === 'true' || s === 'false') return 'boolean';
  if (s === 'null') return 'null';
  return 'string';
}

/** 旧版位置参数（actions[i].args）→ 新参数组对象；旧 reject 家族统一为 reject + mode */
function migrateRewriteAction(old) {
  const v = old && old.v;
  const args = Array.isArray(old && old.args) ? old.args : [];
  const pick = (i) => (args[i] == null ? '' : String(args[i]));
  if (/^reject(_img|_dict|_array|_video)?$/.test(v)) {
    const mode = { reject: 'empty', reject_img: 'image', reject_dict: 'json-object', reject_array: 'json-array', reject_video: 'video' }[v];
    const group = { mode, status: pick(0) || '200', body: '' };
    if (v === 'reject' && pick(1)) group.body = pick(1);
    return { type: 'reject', groups: [group] };
  }
  if (v === 'url.replace') return { type: v, groups: [{ replacement: pick(0) }] };
  if (v === 'redirect') return { type: v, groups: [{ status: pick(0) || '302', location: pick(1) }] };
  if (/\.header\.(add|set)$/.test(v)) return { type: v, groups: [{ name: pick(0), value: pick(1) }] };
  if (/\.header\.del$/.test(v)) return { type: v, groups: [{ name: pick(0) }] };
  if (/\.header\.replace$/.test(v)) return { type: v, groups: [{ name: pick(0), pattern: pick(1), flags: '', replacement: pick(2) }] };
  if (/\.body\.replace$/.test(v)) return { type: v, groups: [{ pattern: pick(0), flags: '', replacement: pick(1) }] };
  if (/\.json\.(add|replace)$/.test(v)) {
    const value = pick(1);
    return { type: v, groups: [{ path: pick(0), valueType: inferLoonValueType(value), value }] };
  }
  if (/\.json\.delete$/.test(v)) return { type: v, groups: [{ path: pick(0) }] };
  if (/\.json\.jq$/.test(v)) return { type: v, groups: [{ source: 'filter', filter: pick(0) || '.data.ads = []', file: '' }] };
  if (/\.body\.mock$/.test(v)) {
    const group = { type: pick(0) || 'json', source: 'data', data: pick(1), raw: true, base64: false };
    if (v === 'response.body.mock') group.status = pick(2) || '200';
    return { type: v, groups: [group] };
  }
  return REWRITE_ACTIONS[v] ? { type: v, groups: [clone(REWRITE_ACTIONS[v].defaults)] } : null;
}

/** 旧版复写条目（cond 字符串 + actions[].args）→ 新条件树 + 参数组；无法迁移的条目返回 null */
function migrateRewriteItem(item) {
  if (!item || typeof item !== 'object') return null;
  /* 已是新结构：条件树是带 items 数组的分组对象（模板里组无 kind，运行时创建的组才有 kind:'group'） */
  if (item.conditions && Array.isArray(item.conditions.items)) return item;
  const phase = item.phase === 'response' ? 'response' : 'request';
  /* 阶段不匹配的 Action 保留原样，交给校验面板提示（比静默丢弃更透明） */
  const actions = (Array.isArray(item.actions) ? item.actions : [])
    .map(migrateRewriteAction)
    .filter((a) => a && REWRITE_ACTIONS[a.type]);
  if (!actions.length) return null;
  const condValue = String(item.cond || '');
  const cond = newCondition({
    field: 'url',
    operator: '~=',
    valueType: 'regex',
    value: condValue,
    flags: ''
  });
  if (item.capture) cond.captureName = String(item.capture);
  return {
    phase,
    conditions: { logic: '&&', items: [cond] },
    actions
  };
}

/* 草稿迁移：旧结构 plugin.name → 新结构 plugin.filename；详情区补上 #!name */
function migratePlugin(p) {
  if (!p || typeof p !== 'object') return p;
  if (!p.filename) {
    const legacyName = String(p.name || '').trim();
    p.filename = legacyName
      ? legacyName.replace(/[\\/:*?"<>|\s]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 80) || 'loon-plugin'
      : 'loon-plugin';
  }
  if (!Array.isArray(p.blocks)) p.blocks = [];
  p.blocks.forEach((b) => {
    if (!b || typeof b !== 'object') return;
    if (!b.id) b.id = uid();
    if (b.type === 'details' && b.data && !b.data.name && p.name) {
      b.data.name = String(p.name).trim() || b.data.name || '未命名插件';
    }
  });
  delete p.name;
  return p;
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
        state.plugins = parsed.plugins
          .filter((p) => p && Array.isArray(p.blocks))
          .map(migratePlugin);
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
  state.plugins.forEach((p) => {
    p.blocks.forEach((b) => {
      if (!b.id) b.id = uid();
      /* 旧版复写草稿迁移到官网 rewrite-builder 结构；
         复写区块固定为单条结构，确保 list 至少有一条（空则补空白项） */
      if (b.type === 'rewrite' && b.data) {
        const arr = Array.isArray(b.data.list) ? b.data.list.map(migrateRewriteItem).filter(Boolean) : [];
        b.data.list = arr.length ? arr : [emptyRewriteItem()];
      }
    });
  });
}

/* ========================= 插件 / 区块操作 ========================= */

function createDemoPlugin() {
  return {
    id: uid(),
    filename: 'demo',
    /* 示例插件带上全部 8 个区块，作为新语法的活样例 */
    blocks: ['details', 'argument', 'general', 'rules', 'rewrite', 'host', 'script', 'mitm'].map((type) =>
      Object.assign({ id: uid() }, clone(BLOCK_TEMPLATES[type]))
    )
  };
}

function createPlugin(filename) {
  const safe = String(filename || '').trim().replace(/[\\/:*?"<>|\s]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 80) || 'loon-plugin';
  const details = Object.assign({ id: uid() }, clone(BLOCK_TEMPLATES.details));
  details.data = details.data || {};
  details.data.name = safe;
  return {
    id: uid(),
    filename: safe,
    blocks: [details]
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
    add('warn', '没有「详情」区块，插件缺少 #!desc / #!icon / #!name 等元信息。');
  }

  const displayName = String((d && d.name) || plugin.filename || 'Untitled Plugin').trim();
  if (!displayName) add('error', '插件显示名为空。<code>#!name</code> 是 Loon 插件的必需字段（可在详情区块填写）。');

  lines.push(`#!name=${displayName}`);
  lines.push(`#!desc=${(d.desc || '').trim() || 'Loon plugin'}`);

  const author = (d.author || '').trim();
  if (author) lines.push(`#!author=${author}`);

  const homepage = (d.homepage || '').trim();
  if (homepage) {
    if (/^https?:\/\//i.test(homepage)) lines.push(`#!homepage=${homepage}`);
    else add('warn', `<code>#!homepage</code> 需要以 http:// 或 https:// 开头，已跳过。`, detailsBlocks[0] && detailsBlocks[0].id);
  }

  const icon = (d.icon || '').trim();
  if (icon) lines.push(`#!icon=${icon}`);
  else add('warn', '未填写 <code>#!icon</code>，Loon 的插件列表会显示默认图标。', detailsBlocks[0] && detailsBlocks[0].id);

  const system = (d.system || '').trim();
  if (system) lines.push(`#!system=${system}`);

  const systemVersion = (d.systemVersion || '').trim();
  if (systemVersion) lines.push(`#!system_version=${systemVersion}`);

  const loonVersion = (d.loonVersion || '').trim();
  if (loonVersion) lines.push(`#!loon_version=${loonVersion}`);

  const tag = (d.tag || '').trim();
  if (tag) lines.push(`#!tag=${tag}`);

  const pluginType = (d.pluginType || '').trim();
  if (pluginType) lines.push(`#!type=${pluginType}`);

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
      // 官方示例中 [General] 的四个字段即使留空也要显示（方便用户填入）
      const value = String(block.data[f.k] || '').trim();
      generalLines.push(`${f.out} = ${value}`);
    });
  });
  if (generalLines.length) {
    lines.push('[General]');
    generalLines.forEach((line) => lines.push(line));
    lines.push('');
  }

  /* ---------- [Rule] ---------- */
  const ruleBlocks = blocksOfType('rules');
  const ruleLines = [];
  ruleBlocks.forEach((block) => {
    const root = block.data.root || { conditions: [] };
    const conditions = root.conditions || [];
    if (!conditions.length) add('hint', '「规则」区块目前为空，可以在左侧添加 DOMAIN / IP 等规则。', block.id);
    conditions.forEach((cond) => {
      const line = serializeCondition(cond, true, add, block.id);
      if (line) ruleLines.push(line);
    });
  });
  if (ruleBlocks.length) {
    lines.push('[Rule]');
    ruleLines.forEach((line) => lines.push(line));
    lines.push('');
  }

  /* ---------- [Rewrite]（Loon 3.5.1 (978) 新语法） ---------- */
  const rewriteBlocks = blocksOfType('rewrite');
  const rewriteLines = [];
  rewriteBlocks.forEach((block) => {
    (block.data.list || []).forEach((item) => {
      const line = serializeRewrite(item, argNames, add, block.id);
      if (line) rewriteLines.push(line);
    });
  });
  if (rewriteBlocks.length) {
    lines.push('[Rewrite]');
    rewriteLines.forEach((line) => lines.push(line));
    lines.push('');
  }

  /* ---------- [Host] ---------- */
  const hostBlocks = blocksOfType('host');
  const hostLines = [];
  hostBlocks.forEach((block) => {
    (block.data.items || []).forEach((item) => {
      const host = (item.name || '').trim();
      const value = (item.value || '').trim();
      if (!host || !value) {
        // 空条目只提示不报错，允许示例插件以空 Host 存在
        if (host || value) add('error', 'Host 条目需要同时填写域名和映射值，该行不会生成。', block.id);
        return;
      }
      if (/[\s,]/.test(host)) {
        add('error', `Host 域名 <code>${escapeHtml(host)}</code> 不能包含空格或逗号，该行不会生成。`, block.id);
        return;
      }
      hostLines.push(`${host} = ${value}`);
    });
  });
  if (hostBlocks.length) {
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
  /* 未转义的 / 自动补转义（URL 正则里极其常见），已转义的不动。
     先把已有的转义序列整段换成占位符，否则里面的 / 会被二次转义成 \\/ */
  const escaped = [];
  p = p
    .replace(/\\[\s\S]/g, (m) => {
      escaped.push(m);
      return `\u0000${escaped.length - 1}\u0000`;
    })
    .replace(/\//g, '\\/')
    .replace(/\u0000(\d+)\u0000/g, (m, i) => escaped[Number(i)]);
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
  /* captureName 可以是单个捕获名，也可以是条件树里收集到的一组 */
  [].concat(captureName || []).forEach((name) => name && known.add(name));
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

  return `${argName} = ${parts.join(',')}`;
}

/* ---------- [Rewrite]（978 新语法） ---------- */

/** Loon 字符串字面量：双引号 + 转义 */
function loonStr(value) {
  return `"${quoteLoonString(value)}"`;
}

/** Loon 反引号原始字符串：内部反引号加倍 */
function loonRaw(value) {
  return `\`${String(value).replace(/`/g, '``')}\``;
}

/** Header 名放进单引号里的转义 */
function loonHeaderName(value) {
  return String(value)
    .replace(/\\/g, '\\\\')
    .replace(/'/g, "\\'");
}

/** 状态码是否合法（100–599） */
function isStatus(value) {
  const text = String(value).trim();
  return /^\d+$/.test(text) && Number(text) >= 100 && Number(text) <= 599;
}

/** 按值类型序列化比较值（与官方生成器一致） */
function loonValue(valueType, value) {
  switch (valueType) {
    case 'number': {
      const text = String(value).trim();
      return text || '0';
    }
    case 'boolean':
      return value === 'false' ? 'false' : 'true';
    case 'null':
      return 'null';
    case 'variable':
      return `\${${String(value).trim()}}`;
    case 'raw':
      return loonRaw(value);
    case 'syntax':
      return String(value).trim();
    default:
      /* string / template */
      return loonStr(value);
  }
}

/** 条件左侧的内置变量 */
function condVariable(cond) {
  if (cond.field === 'request.header') return `\${request.header['${loonHeaderName(cond.headerName)}']}`;
  if (cond.field === 'response.header') return `\${response.header['${loonHeaderName(cond.headerName)}']}`;
  if (cond.field === 'plugin') return `\${${String(cond.variableName).trim()}}`;
  return `\${${cond.field}}`;
}

/** 序列化单个条件：<变量> <操作符> <值>[ as <捕获名>] */
function serializeRewriteCond(cond, add, blockId) {
  const left = condVariable(cond);
  let right;
  if (cond.operator === '~=') {
    right = cond.valueType === 'variable' ? `\${${String(cond.value).trim()}}` : wrapRegex(cond.value, cond.flags || '');
    if (!right) {
      add('error', `复写条件的正则 <code>${escapeHtml(cond.value)}</code> 为空或无法编译，该行不会生成。`, blockId);
      return null;
    }
  } else {
    right = loonValue(cond.valueType, cond.value);
  }
  const capture = String(cond.captureName || '').trim();
  const as = cond.operator === '~=' && capture ? ` as ${capture}` : '';
  return `${left} ${cond.operator} ${right}${as}`;
}

/** 序列化条件组：组内用 && / || 连接，子组含多项时加括号 */
function serializeRewriteGroup(group, add, blockId, isRoot) {
  const items = (group && group.items) || [];
  if (!items.length) {
    add('error', '复写的条件组不能为空，该行不会生成。', blockId);
    return null;
  }
  const parts = items.map((child) =>
    child.kind === 'group' ? serializeRewriteGroup(child, add, blockId, false) : serializeRewriteCond(child, add, blockId)
  );
  if (parts.some((part) => part === null)) return null;
  const logic = group.logic === '||' ? '||' : '&&';
  const text = parts.join(` ${logic} `);
  return !isRoot && items.length > 1 ? `(${text})` : text;
}

/** 实际输出的方法名：reject 按响应类型换名；jq / mock 用插件文件时加 _file 后缀 */
function rewriteActionName(type, fields) {
  if (type === 'reject') return REJECT_MODE_MAP[fields.mode] || 'reject';
  if ((type.endsWith('.json.jq') || type.endsWith('.body.mock')) && fields.source === 'file') return `${type}_file`;
  return type;
}

/** 多组参数 → 数组批量语法 */
function serializeRewriteBatch(type, name, groups) {
  const arr = (list) => `[${list.join(', ')}]`;
  if (type.endsWith('.header.add') || type.endsWith('.header.set')) {
    return `${name}(${arr(groups.map((g) => loonStr(g.name)))}, ${arr(groups.map((g) => loonStr(g.value)))})`;
  }
  if (type.endsWith('.header.del')) return `${name}(${arr(groups.map((g) => loonStr(g.name)))})`;
  if (type.endsWith('.header.replace')) {
    return `${name}(${arr(groups.map((g) => loonStr(g.name)))}, ${arr(groups.map((g) => wrapRegex(g.pattern, g.flags || '')))}, ${arr(
      groups.map((g) => loonStr(g.replacement))
    )})`;
  }
  if (type.endsWith('.body.replace')) {
    return `${name}(${arr(groups.map((g) => wrapRegex(g.pattern, g.flags || '')))}, ${arr(groups.map((g) => loonStr(g.replacement)))})`;
  }
  if (type.endsWith('.json.delete')) return `${name}(${arr(groups.map((g) => loonStr(g.path)))})`;
  if (type.endsWith('.json.add') || type.endsWith('.json.replace')) {
    return `${name}(${arr(groups.map((g) => loonStr(g.path)))}, ${arr(groups.map((g) => loonValue(g.valueType, g.value)))})`;
  }
  return `${name}()`;
}

/** 序列化一个 Action（含参数组） */
function serializeRewriteAction(action, phase, index, add, blockId) {
  const meta = REWRITE_ACTIONS[action.type];
  if (!meta) {
    add('error', `复写第 ${index + 1} 个 Action 无效，该行不会生成。`, blockId);
    return null;
  }
  if (meta.phase !== phase) {
    add('error', `<code>${action.type}</code> 只能用于 ${meta.phase} 阶段，当前复写是 ${phase}，该行不会生成。`, blockId);
    return null;
  }
  const groups = action.groups && action.groups.length ? action.groups : [meta.defaults];
  const g = groups[0];
  const name = rewriteActionName(action.type, g);

  if (action.type === 'url.replace') return `${name}(${loonStr(g.replacement)})`;
  if (action.type === 'redirect') return `${name}(${g.status || '302'}, ${loonStr(g.location)})`;
  if (action.type === 'reject') {
    const args = [g.status || '200'];
    if (g.mode === 'custom' && g.body) args.push(loonStr(g.body));
    return `${name}(${args.join(', ')})`;
  }
  if (groups.length > 1 && meta.batch) return serializeRewriteBatch(action.type, name, groups);

  if (action.type.endsWith('.header.add') || action.type.endsWith('.header.set')) {
    return `${name}(${loonStr(g.name)}, ${loonStr(g.value)})`;
  }
  if (action.type.endsWith('.header.del')) return `${name}(${loonStr(g.name)})`;
  if (action.type.endsWith('.header.replace')) {
    return `${name}(${loonStr(g.name)}, ${wrapRegex(g.pattern, g.flags || '')}, ${loonStr(g.replacement)})`;
  }
  if (action.type.endsWith('.body.replace')) {
    return `${name}(${wrapRegex(g.pattern, g.flags || '')}, ${loonStr(g.replacement)})`;
  }
  if (action.type.endsWith('.json.delete')) return `${name}(${loonStr(g.path)})`;
  if (action.type.endsWith('.json.add') || action.type.endsWith('.json.replace')) {
    return `${name}(${loonStr(g.path)}, ${loonValue(g.valueType, g.value)})`;
  }
  if (action.type.endsWith('.json.jq')) {
    return `${name}(${loonStr(g.source === 'file' ? g.file : g.filter)})`;
  }
  if (action.type.endsWith('.body.mock')) {
    const key = g.source === 'file' ? 'file' : 'data';
    const content = g.source === 'data' && g.raw ? loonRaw(g.data) : loonStr(g[key]);
    const args = [loonStr(g.type), content];
    if (action.type === 'response.body.mock') args.push(g.status || '200');
    if (g.base64) args.push('true');
    return `${name}(${args.join(', ')})`;
  }
  return `${name}()`;
}

/** 校验条件组内的字段（规则与官方生成器一致） */
function validateRewriteGroup(group, phase, add, blockId) {
  const items = (group && group.items) || [];
  if (!items.length) {
    add('error', '复写的条件组不能为空，该行不会生成。', blockId);
    return true;
  }
  let failed = false;
  const err = (msg) => {
    add('error', msg, blockId);
    failed = true;
  };
  items.forEach((child) => {
    if (child.kind === 'group') {
      if (validateRewriteGroup(child, phase, add, blockId)) failed = true;
      return;
    }
    const meta = REWRITE_FIELDS.find((f) => f.v === child.field);
    if (meta && meta.phases && !meta.phases.includes(phase)) {
      err(`<code>${child.field}</code> 不能用于 ${phase} 阶段的条件，该行不会生成。`);
    }
    if ((child.field === 'request.header' || child.field === 'response.header') && !String(child.headerName || '').trim()) {
      err('复写条件的 Header 名称不能为空，该行不会生成。');
    }
    if (child.field === 'plugin' && !/^[A-Za-z_]\w*$/.test(String(child.variableName || '').trim())) {
      err('复写条件的插件参数名格式不正确，该行不会生成。');
    }
    if (child.operator === '~=' && child.valueType === 'regex' && !String(child.value || '').trim()) {
      err('复写条件的正则内容不能为空，该行不会生成。');
    }
    if (child.valueType === 'variable' && !/^[A-Za-z_]\w*(?:\.\d+)?$/.test(String(child.value || '').trim())) {
      err('复写条件右侧的变量名格式不正确，该行不会生成。');
    }
    if (child.valueType === 'syntax' && !String(child.value || '').trim()) {
      err('复写条件的 Raw Syntax 不能为空，该行不会生成。');
    }
    if (child.operator === '==' && child.valueType === 'number') {
      const text = String(child.value || '').trim();
      if (text === '' || !Number.isFinite(Number(text))) err('复写条件的数字值格式不正确，该行不会生成。');
    }
    const capture = String(child.captureName || '').trim();
    if (capture && !/^[A-Za-z_]\w*$/.test(capture)) {
      err(`捕获名 <code>${escapeHtml(capture)}</code> 格式不正确，该行不会生成。`);
    }
  });
  return failed;
}

/** 收集条件树的结构信息（捕获名 / 插件参数 / 响应引用 / 必选 URL 正则数） */
function collectRewriteInfo(group, mandatory, info) {
  const out =
    info || { captures: [], optionalCaptures: [], pluginRefs: [], responseRefs: [], urlRegexCount: 0 };
  const items = (group && group.items) || [];
  const childMandatory = mandatory && (group.logic !== '||' || items.length === 1);
  items.forEach((child) => {
    if (child.kind === 'group') {
      collectRewriteInfo(child, childMandatory, out);
      return;
    }
    if (child.field === 'plugin') out.pluginRefs.push(String(child.variableName || '').trim());
    if (child.field.startsWith('response.')) out.responseRefs.push(child.field);
    const capture = String(child.captureName || '').trim();
    if (capture) {
      out.captures.push(capture);
      if (!childMandatory) out.optionalCaptures.push(capture);
    }
    if (childMandatory && child.field === 'url' && child.operator === '~=') out.urlRegexCount += 1;
  });
  return out;
}

/** 收集条件树里所有捕获名（用于 ${…} 引用校验） */
function collectCaptures(group, list) {
  const out = list || [];
  ((group && group.items) || []).forEach((child) => {
    if (child.kind === 'group') collectCaptures(child, out);
    else if (String(child.captureName || '').trim()) out.push(String(child.captureName).trim());
  });
  return out;
}

/** 校验 Action 的每组参数（规则与官方生成器一致） */
function validateRewriteAction(action, add, blockId) {
  const meta = REWRITE_ACTIONS[action.type];
  if (!meta) return true;
  let failed = false;
  const groups = action.groups && action.groups.length ? action.groups : [meta.defaults];
  groups.forEach((g, gi) => {
    const prefix = groups.length > 1 ? `第 ${gi + 1} 组参数：` : '';
    const err = (msg) => {
      add('error', `${prefix}${msg}`, blockId);
      failed = true;
    };
    if (action.type === 'url.replace') {
      if (!String(g.replacement || '').trim()) err('URL 替换内容不能为空。');
      if (/\$\d+/.test(String(g.replacement || ''))) err('URL 替换内容不能使用 $n，请在条件里用 as 捕获，再以 ${名称.n} 引用。');
    }
    if (action.type === 'redirect') {
      if (!String(g.location || '').trim()) err('重定向地址不能为空。');
      if (/\$\d+/.test(String(g.location || ''))) err('重定向地址不能使用 $n，请在条件里用 as 捕获，再以 ${名称.n} 引用。');
    }
    if (action.type === 'reject' && !isStatus(g.status)) err('Reject 状态码必须是 100 到 599 的整数。');
    if (action.type.includes('.header.') && !String(g.name || '').trim()) err('Header 名称不能为空。');
    if ((action.type.endsWith('.header.add') || action.type.endsWith('.header.set')) && g.value === undefined) {
      err('Header 值不能为空。');
    }
    if ((action.type.endsWith('.header.replace') || action.type.endsWith('.body.replace')) && !String(g.pattern || '').trim()) {
      err('替换正则不能为空。');
    }
    if (action.type.includes('.json.') && !action.type.endsWith('.json.jq')) {
      if (!String(g.path || '').trim()) err('JSON Key Path 不能为空。');
      if (action.type.endsWith('.json.add') || action.type.endsWith('.json.replace')) {
        const text = String(g.value || '').trim();
        if (g.valueType === 'number' && (text === '' || !Number.isFinite(Number(text)))) err('JSON 数字值格式不正确。');
        if (g.valueType === 'variable' && !/^[A-Za-z_]\w*(?:\.\d+)?$/.test(text)) err('JSON 变量名格式不正确。');
      }
    }
    if (action.type.endsWith('.json.jq')) {
      const source = g.source === 'file' ? g.file : g.filter;
      if (!String(source || '').trim()) err(g.source === 'file' ? 'jq 文件名不能为空。' : 'jq 表达式不能为空。');
    }
    if (action.type.endsWith('.body.mock')) {
      if (g.source === 'file' && !String(g.file || '').trim()) err('Mock 文件名不能为空。');
      if (action.type === 'response.body.mock' && !isStatus(g.status)) err('Mock 响应状态码必须是 100 到 599 的整数。');
    }
  });
  return failed;
}

/** 整条复写的结构级校验（规则与官方生成器一致） */
function validateRewriteItem(item, phase, argNames, add, blockId) {
  let failed = false;
  if (validateRewriteGroup(item.conditions, phase, add, blockId)) failed = true;

  const actions = item.actions || [];
  actions.forEach((action) => {
    if (validateRewriteAction(action, add, blockId)) failed = true;
  });

  const info = collectRewriteInfo(item.conditions, true);
  const dup = [...new Set(info.captures.filter((name, i) => info.captures.indexOf(name) !== i))];
  if (dup.length) {
    add('error', `捕获名称不能重复：${escapeHtml(dup.join('、'))}，该行不会生成。`, blockId);
    failed = true;
  }
  const clash = [...new Set(info.captures.filter((name) => argNames.has(name)))];
  if (clash.length) {
    add('error', `捕获名称不能与插件参数重名：${escapeHtml(clash.join('、'))}，该行不会生成。`, blockId);
    failed = true;
  }
  const optional = [...new Set(info.optionalCaptures)];
  if (optional.length) {
    add('warn', `捕获 ${escapeHtml(optional.join('、'))} 位于 OR 的可选分支中，可能取不到值。`, blockId);
  }

  /* URL 修改必须有且只有一个「必选」的 URL 正则条件 */
  if (actions.some((a) => a.type === 'url.replace' || a.type === 'redirect')) {
    if (info.urlRegexCount === 0) {
      add('error', 'URL 修改需要一个必选的 URL 正则条件（<code>${url} ~= /…/</code>），该行不会生成。', blockId);
      failed = true;
    } else if (info.urlRegexCount > 1) {
      add('error', 'URL 修改只能对应一个必选的 URL 正则条件，该行不会生成。', blockId);
      failed = true;
    }
  }

  /* Response Mock 的组合限制：它是在请求发出前生成的，拿不到真实响应 */
  const mocks = actions.filter((a) => a.type === 'response.body.mock');
  if (mocks.length > 1) {
    add('error', '一条复写只能包含一个 Response Mock，该行不会生成。', blockId);
    failed = true;
  }
  if (mocks.length) {
    if (actions.some((a) => a.type !== 'response.body.mock' && !a.type.startsWith('response.header.'))) {
      add('error', 'Response Mock 只能与响应 Header Action 组合，该行不会生成。', blockId);
      failed = true;
    }
    if (info.responseRefs.length) {
      add('error', 'Response Mock 的条件不能引用响应状态码或响应 Header，该行不会生成。', blockId);
      failed = true;
    }
    const bad = mocks.some((action) => {
      const g = (action.groups && action.groups[0]) || {};
      const text = g.source === 'file' ? g.file : g.raw ? '' : g.data;
      return String(text).includes('${response.');
    });
    if (bad) {
      add('error', 'Response Mock 的参数不能引用尚未生成的响应变量，该行不会生成。', blockId);
      failed = true;
    }
  }
  return failed;
}

/** 序列化一条复写：<phase> if <条件树> then <Action>(…) | <Action>(…) */
function serializeRewrite(item, argNames, add, blockId) {
  const phase = item.phase === 'response' ? 'response' : 'request';
  const conditions = serializeRewriteGroup(item.conditions, add, blockId, true);
  if (conditions === null) return null;

  const actions = item.actions || [];
  if (!actions.length) {
    add('error', '复写没有任何 Action，该行不会生成。', blockId);
    return null;
  }

  const parts = [];
  for (let i = 0; i < actions.length; i += 1) {
    const text = serializeRewriteAction(actions[i], phase, i, add, blockId);
    if (text === null) return null;
    parts.push(text);
  }

  if (validateRewriteItem(item, phase, argNames, add, blockId)) return null;

  const line = `${phase} if ${conditions} then ${parts.join(' | ')}`;
  if (checkPluginRefs(line, argNames, collectCaptures(item.conditions), add, blockId, '这条复写')) return null;
  return line;
}

/* ---------- [Script]（983 新语法） ---------- */

/** 序列化脚本：<kind> [if <cond>] then script("path"[, <argument>]) [with <options>] */
/** 旧式脚本序列化（pre-978 语法）：http-response <url> script-path=<path>,<attrs> */
function serializeScriptLegacy(data, argNames, add, blockId) {
  const path = (data.path || '').trim();
  if (!path) {
    add('error', '脚本缺少路径，Loon 无法加载脚本，该行不会生成。', blockId);
    return null;
  }
  const kind = data.kind;
  const match = (data.match || '').trim();

  /* 前缀 */
  let head = '';
  if (kind === 'request') head = 'http-request';
  else if (kind === 'response') head = 'http-response';
  else if (kind === 'cron') head = 'cron';
  else if (kind === 'network-changed') head = 'network-changed';
  else head = 'http-response';

  /* URL 匹配（response / request 必需） */
  if (kind === 'request' || kind === 'response') {
    if (!match) {
      add('error', `<code>${head}</code> 脚本缺少 URL 匹配正则，该行不会生成。`, blockId);
      return null;
    }
    head = `${head} ${match}`;
  } else if (kind === 'cron') {
    if (!match) {
      add('error', 'cron 脚本缺少 Cron 表达式，该行不会生成。', blockId);
      return null;
    }
    head = `${head} ${match}`;
  }

  const params = [`script-path=${path}`];

  /* requires-body / binary-body-mode */
  if (data.requiresBody === 'true') params.push('requires-body=true');
  if (data.binaryMode === 'true') params.push('binary-body-mode=true');

  /* tag (不加引号) */
  const label = (data.tag || '').trim();
  if (label) params.push(`tag=${label}`);

  /* timeout */
  const timeout = String(data.timeout || '').trim();
  if (timeout) {
    if (/^\d+$/.test(timeout) && Number(timeout) > 0) params.push(`timeout=${timeout}`);
    else add('warn', `脚本的 timeout 应为正整数，当前是 <code>${escapeHtml(timeout)}</code>，已跳过。`, blockId);
  }

  /* enable（默认 true 就不写，除非 false） */
  if (data.enable === 'false') params.push('enable=false');

  /* argument */
  const argMode = ARG_MODES.some((m) => m.v === data.argMode) ? data.argMode : 'none';
  if (argMode === 'string') {
    const value = String(data.argValue || '').trim();
    if (value) params.push(`argument="${quoteLoonString(value)}"`);
  } else if (argMode === 'raw') {
    const value = String(data.argValue || '').trim();
    if (value) params.push(`argument=\`${value.replace(/`/g, '``')}\``);
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
    params.push(`argument=[{${names.join('},{')}}]`);
  }

  const line = `${head} ${params.join(',')}`;
  if (checkPluginRefs(line, argNames, null, add, blockId, '这条脚本')) return null;
  return line;
}

function serializeScript(data, argNames, add, blockId) {
  /* 旧式语法分支（官方示例插件采用 pre-978 格式） */
  if (data && data.syntax === 'legacy') {
    return serializeScriptLegacy(data, argNames, add, blockId);
  }
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
        <span class="p-name"><span class="p-base">${escapeHtml(plugin.filename || '未命名')}</span><span class="p-ext">.plugin</span></span>
        <button class="btn-icon is-danger p-del" data-act="del-plugin" data-plugin-id="${plugin.id}" title="删除插件" aria-label="删除插件 ${escapeHtml(plugin.filename || '未命名')}.plugin">${ICONS.trash}</button>
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
        <label>插件显示名 · #!name</label>
        <input type="text" data-field="name" value="${escapeHtml(d.name || '')}" placeholder="Demo Plugin" />
        <span class="hint">Loon 插件列表里展示的标题（对应 <code>#!name</code>），与文件名独立。</span>
      </div>
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
      <div class="field">
        <label>支持系统 · #!system</label>
        <input type="text" data-field="system" value="${escapeHtml(d.system || '')}" placeholder="iOS,iPadOS,tvOS,macOS" />
      </div>
      <div class="field">
        <label>插件类型 · #!type</label>
        <input type="text" data-field="pluginType" value="${escapeHtml(d.pluginType || '')}" placeholder="normal 或 Jacob" />
      </div>
      <div class="field">
        <label>系统版本 · #!system_version</label>
        <input type="text" data-field="systemVersion" value="${escapeHtml(d.systemVersion || '')}" placeholder="如 15" />
      </div>
      <div class="field">
        <label>最低 Loon 版本 · #!loon_version</label>
        <input type="text" data-field="loonVersion" value="${escapeHtml(d.loonVersion || '')}" placeholder="如 3.4.0(962)" />
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
/* ---------- [Rewrite] 区块渲染（978 新语法） ---------- */

/** 表单小控件：单行文本 */
function fieldText(label, field, value, ph) {
  return `<div class="field"><label>${escapeHtml(label)}</label><input type="text" data-field="${field}" value="${escapeHtml(value || '')}" placeholder="${escapeHtml(
    ph || ''
  )}" /></div>`;
}

/** 表单小控件：下拉 */
function fieldSelect(label, field, options, selected) {
  return `<div class="field"><label>${escapeHtml(label)}</label><select data-field="${field}">${optionsHtml(options, selected)}</select></div>`;
}

/** 表单小控件：复选框 */
function fieldBool(label, field, checked) {
  return `<label class="field is-checkbox"><input type="checkbox" data-field="${field}"${checked ? ' checked' : ''} /><span>${escapeHtml(label)}</span></label>`;
}

/** 表单小控件：正则 + i/m/s flags */
function fieldRegex(label, field, value, flags) {
  const active = String(flags || '');
  return `<div class="field"><label>${escapeHtml(label)}</label><div class="composite-input">
      <span class="input-affix">/</span>
      <input type="text" data-field="${field}" value="${escapeHtml(value || '')}" placeholder="正则" />
      <span class="input-affix">/</span>
      <div class="flag-group" role="group" aria-label="正则 flags">${['i', 'm', 's']
        .map(
          (f) =>
            `<button type="button" class="btn btn-xs${active.includes(f) ? ' is-active' : ''}" data-act="toggle-flag" data-flag="${f}">${f}</button>`
        )
        .join('')}</div>
    </div></div>`;
}

/** Action 字段的中文名与占位提示 */
const ACTION_FIELD_UI = {
  name: { label: 'Header 名称', ph: 'X-Loon' },
  value: { label: 'Header 值', ph: '支持 ${...}' },
  location: { label: '重定向地址', ph: 'https://new.example.com' },
  path: { label: 'JSON Key Path', ph: 'data.vip' },
  filter: { label: 'jq 表达式', ph: '.data.ads = []' },
  file: { label: '插件文件', ph: 'response_body.json' },
  data: { label: 'Body 内容', ph: '{"code":0}' },
  status: { label: '响应状态码', ph: '200' },
  body: { label: '响应文本', ph: '可选' },
  raw: { label: '使用反引号原始字符串', type: 'bool' },
  base64: { label: '数据为 Base64', type: 'bool' }
};

/** JSON Action 的值类型 */
const JSON_VALUE_TYPES = [
  { v: 'string', label: '字符串' },
  { v: 'number', label: '数字' },
  { v: 'boolean', label: '布尔值' },
  { v: 'null', label: 'null' },
  { v: 'variable', label: '插件参数' }
];

/** 渲染 Action 的单个字段（按官方生成器的字段顺序） */
function renderActionField(type, key, g) {
  const meta = REWRITE_ACTIONS[type] || {};
  const ui = ACTION_FIELD_UI[key] || { label: key };

  if (key === 'source') {
    return fieldSelect('数据来源', 'f-source', type.endsWith('.json.jq') ? JQ_SOURCES : MOCK_SOURCES, g.source);
  }
  /* 数据来源决定显示「内容输入」还是「文件路径」 */
  if (key === 'filter' && g.source !== 'filter') return '';
  if (key === 'file' && g.source !== 'file') return '';
  if (key === 'data' && g.source !== 'data') return '';
  if (key === 'type') return fieldSelect('Body 类型', 'f-type', MOCK_TYPES, g.type);
  if (key === 'mode') return fieldSelect('响应类型', 'f-mode', REJECT_MODES, g.mode);
  if (key === 'body') return g.mode === 'custom' ? fieldText(ui.label, 'f-body', g.body, ui.ph) : '';
  if (key === 'status') return fieldText(type === 'redirect' ? '状态码' : ui.label, 'f-status', g.status, ui.ph);
  if (key === 'pattern') return fieldRegex('正则', 'f-pattern', g.pattern, g.flags);
  if (key === 'raw' || key === 'base64') return fieldBool(ui.label, `f-${key}`, Boolean(g[key]));
  if (key === 'value' && meta.jsonValue) {
    return `${fieldSelect('值类型', 'f-valueType', JSON_VALUE_TYPES, g.valueType || 'string')}
      ${fieldText('值', 'f-value', g.value, g.valueType === 'variable' ? '变量名' : 'true')}`;
  }
  if (key === 'replacement') {
    return fieldText(type === 'url.replace' ? '替换 URL（使用 IF 正则）' : '替换内容', 'f-replacement', g.replacement, '支持 ${...}');
  }
  return fieldText(ui.label, `f-${key}`, g[key], ui.ph);
}

/** 渲染 Action 的一组参数 */
function renderActionFields(type, g) {
  const meta = REWRITE_ACTIONS[type];
  if (!meta) return '';
  return (meta.fields || []).map((key) => renderActionField(type, key, g)).join('');
}

/** Action 下拉：按阶段过滤，并按官方分组 */
function rewriteActionOptions(phase, selected) {
  return REWRITE_ACTION_GROUPS.map((group) => {
    const items = group.actions.filter((v) => REWRITE_ACTIONS[v] && REWRITE_ACTIONS[v].phase === phase);
    if (!items.length) return '';
    return `<optgroup label="${escapeHtml(group.label)}">${optionsHtml(
      items.map((v) => ({ v, label: REWRITE_ACTIONS[v].label })),
      selected
    )}</optgroup>`;
  }).join('');
}

/** 渲染一个 Action 卡片（含参数组） */
function renderRewriteActionCard(block, idx, action, aidx, phase) {
  const meta = REWRITE_ACTIONS[action.type] || REWRITE_ACTIONS['request.header.set'];
  const groups = action.groups && action.groups.length ? action.groups : [meta.defaults];
  return `
    <div class="action-card" data-aidx="${aidx}">
      <div class="action-head">
        <div class="field">
          <label>Action</label>
          <select data-field="action-type">${rewriteActionOptions(phase, action.type)}</select>
        </div>
        <code class="action-sig">${escapeHtml(rewriteActionName(action.type, groups[0]))}</code>
        <div class="row-actions">
          <button class="btn-icon is-danger" type="button" data-act="del-action" data-id="${block.id}" data-idx="${idx}" data-aidx="${aidx}" title="删除 Action" aria-label="删除 Action">${ICONS.trash}</button>
        </div>
      </div>
      ${groups
        .map(
          (g, gi) => `
        <div class="param-group" data-gidx="${gi}">
          <div class="param-group-head">
            <strong>参数组 ${gi + 1}</strong>
            ${
              groups.length > 1
                ? `<button class="btn-icon is-danger" type="button" data-act="del-param" data-id="${block.id}" data-idx="${idx}" data-aidx="${aidx}" data-gidx="${gi}" title="删除参数组" aria-label="删除参数组">${ICONS.trash}</button>`
                : ''
            }
          </div>
          <div class="param-fields">${renderActionFields(action.type, g)}</div>
        </div>`
        )
        .join('')}
      ${
        meta.batch
          ? `<div class="action-foot">
        <button class="btn btn-xs add-row" type="button" data-act="add-param" data-id="${block.id}" data-idx="${idx}" data-aidx="${aidx}">＋ 添加一组参数</button>
        ${groups.length > 1 ? '<span class="value-hint">多组参数会生成数组批量语法。</span>' : ''}
      </div>`
          : ''
      }
    </div>`;
}

/** 渲染单个条件：配置栏（字段/操作符/值类型/捕获/删除）+ 值区域（URL构建器/手写正则/普通输入） */
function renderRewriteCond(block, idx, cond, path, phase) {
  const fields = REWRITE_FIELDS.filter((f) => f.phases.includes(phase));
  const fieldMeta = REWRITE_FIELDS.find((f) => f.v === cond.field) || fields[0];
  const isRegex = cond.operator === '~=';
  const valueTypes = REWRITE_VALUE_TYPES.filter((t) => t.ops.includes(cond.operator));
  const valueType = valueTypes.some((t) => t.v === cond.valueType) ? cond.valueType : valueTypes[0].v;
  const showRegex = isRegex && valueType === 'regex';
  /* URL 正则默认走分段构建器（协议://主机:端口/路径?查询），解析不了的手写正则回退到手写模式 */
  const isUrl = cond.field === 'url';
  let useUrlBuilder = showRegex && isUrl && cond.urlMode !== 'raw';
  let parts = null;
  if (useUrlBuilder) {
    parts = ensureUrlParts(cond);
    if (!parts) {
      cond.urlMode = 'raw';
      useUrlBuilder = false;
    }
  }
  const valueLabel = useUrlBuilder ? 'URL 匹配' : valueType === 'regex' ? '正则内容' : valueType === 'variable' ? '参数名' : '比较值';
  const flagButtons = `
          <div class="flag-group" role="group" aria-label="正则 flags">${['i', 'm', 's']
            .map(
              (f) =>
                `<button type="button" class="btn btn-xs${String(cond.flags || '').includes(f) ? ' is-active' : ''}" data-act="toggle-flag" data-flag="${f}">${f}</button>`
            )
            .join('')}</div>`;
  /* 配置栏：字段 / Header名 / 参数名 / 操作符 / 值类型 / 捕获as / 删除 */
  const configBar = `
      <div class="cond-bar">
        <div class="field">
          <label>字段</label>
          <select data-field="cond-field">${optionsHtml(fields, cond.field)}</select>
        </div>
        ${
          fieldMeta.header
            ? `<div class="field"><label>Header 名称</label><input type="text" data-field="cond-header-name" value="${escapeHtml(
                cond.headerName || ''
              )}" placeholder="Content-Type" /></div>`
            : ''
        }
        ${
          fieldMeta.variable
            ? `<div class="field"><label>参数名</label><input type="text" data-field="cond-var-name" value="${escapeHtml(
                cond.variableName || ''
              )}" placeholder="token" /></div>`
            : ''
        }
        <div class="field">
          <label>操作符</label>
          <select data-field="cond-op">${optionsHtml(REWRITE_OPS, cond.operator)}</select>
        </div>
        <div class="field">
          <label>${isRegex ? '匹配值' : '值类型'}</label>
          <select data-field="cond-vtype">${optionsHtml(valueTypes, valueType)}</select>
        </div>
        ${
          isRegex
            ? `<div class="field"><label>捕获 as</label><input type="text" data-field="cond-capture" value="${escapeHtml(
                cond.captureName || ''
              )}" placeholder="item" /></div>`
            : ''
        }
        <div class="row-actions">
          <button class="btn-icon is-danger" type="button" data-act="del-cond" data-id="${block.id}" data-idx="${idx}" data-path="${path}" title="删除条件" aria-label="删除条件">${ICONS.trash}</button>
        </div>
      </div>`;
  /* 值区域：URL 构建器 / 手写正则 / 普通输入 */
  const valueBody = useUrlBuilder
    ? `<div class="cond-value">
        <div class="url-builder">
          <div class="grid">
            <div class="field col-2">
              <label>协议</label>
              <select data-field="url-scheme">${optionsHtml(URL_SCHEMES, parts.scheme || 'https')}</select>
            </div>
            <div class="field col-2">
              <label>端口（可留空）</label>
              <input type="text" data-field="url-port" value="${escapeHtml(parts.port || '')}" placeholder="如 443" />
            </div>
            <div class="field col-2">
              <label>主机（域名 / IP）</label>
              <input type="text" data-field="url-host" value="${escapeHtml(parts.host || '')}" placeholder="如 api.example.com" />
            </div>
            <div class="field col-3">
              <label>路径（开头无需 /）</label>
              <input type="text" data-field="url-path" value="${escapeHtml(parts.path || '')}" placeholder="如 v1/user" />
            </div>
            <div class="field col-3">
              <label>查询参数（开头无需 ?）</label>
              <input type="text" data-field="url-query" value="${escapeHtml(parts.query || '')}" placeholder="如 page=1&amp;limit=10" />
            </div>
          </div>
          <div class="url-foot">
            <label class="url-check"><input type="checkbox" data-field="url-exact"${parts.exact ? ' checked' : ''} /> 完整匹配（结尾自动加 $）</label>
            ${flagButtons}
            <button type="button" class="btn btn-xs url-mode-btn" data-act="url-mode" data-mode="raw">手写正则</button>
          </div>
        </div>
      </div>`
    : showRegex
    ? `<div class="cond-value">
        <label class="cond-value-label">${valueLabel}</label>
        <div class="composite-input">
          <span class="input-affix">/</span>
          <input type="text" data-field="cond-value" value="${escapeHtml(cond.value || '')}" placeholder="^https:\\/\\/example\\.com" />
          <span class="input-affix">/</span>
          ${flagButtons}
          ${isUrl ? `<button type="button" class="btn btn-xs url-mode-btn" data-act="url-mode" data-mode="builder">URL 构建器</button>` : ''}
        </div>
      </div>`
    : `<div class="cond-value">
        <label class="cond-value-label">${valueLabel}</label>
        <input type="text" data-field="cond-value" value="${escapeHtml(cond.value || '')}" placeholder="${
          valueType === 'variable' ? 'urlPattern' : '输入比较值'
        }" />
      </div>`;
  return `
    <div class="row is-cond" data-path="${path}">
      ${configBar}
      ${valueBody}
    </div>`;
}

/** 渲染条件组（可嵌套） */
function renderRewriteGroup(block, idx, group, path, depth, phase) {
  const items = (group && group.items) || [];
  const logic = group.logic === '||' ? '||' : '&&';
  const childPath = (i) => (path ? `${path}.${i}` : String(i));
  return `
    <div class="cond-group" data-depth="${depth}">
      <div class="cond-group-head">
        <span class="cond-group-title">${
          items.length > 1 ? (logic === '||' ? '满足以下任一条件' : '满足以下全部条件') : '条件'
        }</span>
        <div class="logic-toggle" role="group" aria-label="条件关系">
          <button type="button" class="btn btn-xs${logic === '&&' ? ' is-active' : ''}" data-act="set-logic" data-id="${block.id}" data-idx="${idx}" data-path="${path}" data-logic="&&">AND</button>
          <button type="button" class="btn btn-xs${logic === '||' ? ' is-active' : ''}" data-act="set-logic" data-id="${block.id}" data-idx="${idx}" data-path="${path}" data-logic="||">OR</button>
        </div>
        ${
          depth > 0
            ? `<button class="btn-icon is-danger" type="button" data-act="del-cond" data-id="${block.id}" data-idx="${idx}" data-path="${path}" title="删除条件组" aria-label="删除条件组">${ICONS.trash}</button>`
            : ''
        }
      </div>
      ${items
        .map((child, i) =>
          child.kind === 'group'
            ? renderRewriteGroup(block, idx, child, childPath(i), depth + 1, phase)
            : renderRewriteCond(block, idx, child, childPath(i), phase)
        )
        .join('')}
      <div class="cond-group-actions">
        <button class="btn btn-xs add-row" type="button" data-act="add-cond" data-id="${block.id}" data-idx="${idx}" data-path="${path}">＋ 条件</button>
        <button class="btn btn-xs add-row" type="button" data-act="add-cond-group" data-id="${block.id}" data-idx="${idx}" data-path="${path}">＋ 条件组</button>
      </div>
    </div>`;
}

/** 渲染一条复写：阶段切换 + IF · 匹配条件 + THEN · 执行动作（固定两段，不可重复添加） */
function renderRewriteItem(block, item, idx) {
  const phase = item.phase === 'response' ? 'response' : 'request';
  const actions = item.actions || [];
  const condCount = countRewriteConds(item.conditions);
  return `
    <div class="rewrite-item" data-idx="${idx}">
      <div class="rewrite-head">
        <span class="rewrite-phase-tag" data-phase="${phase}">${phase === 'response' ? 'Response' : 'Request'}</span>
        <div class="field rewrite-phase-field">
          <label>阶段</label>
          <select data-field="phase">${optionsHtml(REWRITE_PHASES, phase)}</select>
        </div>
        <span class="rewrite-stat is-cond"><strong>${condCount}</strong> 条件</span>
        <span class="rewrite-stat is-action"><strong>${actions.length}</strong> 动作</span>
      </div>
      <div class="rewrite-section is-if">
        <div class="rewrite-section-title"><span class="step-no">IF</span> 匹配条件</div>
        ${renderRewriteGroup(block, idx, item.conditions, '', 0, phase)}
      </div>
      <div class="rewrite-section is-then">
        <div class="rewrite-section-title"><span class="step-no">THEN</span> 执行动作</div>
        <div class="action-list">
          ${actions.map((action, aidx) => renderRewriteActionCard(block, idx, action, aidx, phase)).join('')}
        </div>
        <button class="btn btn-sm add-row" type="button" data-act="add-action" data-id="${block.id}" data-idx="${idx}">＋ 添加 Action</button>
      </div>
    </div>`;
}

/** [Rewrite]（978 新语法）：固定单条复写结构 = IF · 匹配条件 + THEN · 执行动作 */
function renderRewrite(block) {
  const list = block.data.list || [];
  /* 单条结构：始终只渲染首项；旧草稿多余项静默忽略，避免数据丢失 */
  const item = list[0] || emptyRewriteItem();
  return `
    <div class="rows">
      ${renderRewriteItem(block, item, 0)}
    </div>
    <div class="note-box">输出形如 <code>request if \${url} ~= /正则/ &amp;&amp; \${request.method} == "POST" then request.header.set("X-Loon", "true")</code>。条件支持 AND / OR 嵌套分组；用 <code>as 捕获名</code> 保存匹配结果后可用 <code>\${捕获名.1}</code> 引用。同一 Action 填多组参数会自动生成数组批量语法。含 Response Mock 的复写只能搭配响应 Header Action。</div>`;
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
  if (document.activeElement !== el.nameInput) el.nameInput.value = plugin.filename || '';

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
      if (!window.confirm(`删除插件「${plugin ? plugin.filename + '.plugin' : ''}」？此操作不可撤销。`)) return;
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
    const plugin = createPlugin(`untitled-plugin-${state.plugins.length + 1}`);
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

  /* --- 插件文件名（不含 .plugin 后缀）--- */
  el.nameInput.addEventListener('input', () => {
    const plugin = currentPlugin();
    if (!plugin) return;
    const raw = el.nameInput.value;
    const cleaned = raw
      .replace(/[\\/:*?"<>|]+/g, '-')      // 文件系统非法字符 → 连字符
      .replace(/\s+/g, '-')                  // 空白 → 连字符
      .replace(/^-+|-+$/g, '')               // 去掉首尾连字符
      .slice(0, 80);
    if (cleaned !== raw) {
      // 视觉上给用户瞬间反馈为清洗后的值，避免显示的和存的不一样
      const pos = el.nameInput.selectionStart;
      const delta = cleaned.length - raw.length;
      el.nameInput.value = cleaned;
      try {
        el.nameInput.setSelectionRange(Math.max(0, pos + delta), Math.max(0, pos + delta));
      } catch (_) {}
    }
    plugin.filename = cleaned || 'loon-plugin';
    const label = el.pluginList.querySelector(`[data-plugin-id="${plugin.id}"] .p-base`);
    if (label) label.textContent = plugin.filename;
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

  /* 旧规则树的条件增删（仅 [Rule] 区块）；[Rewrite] 的同名操作带 data-idx，走下方新分支 */
  if (action === 'add-cond' && block.type === 'rules') {
    const path = btn.dataset.path || 'root';
    const target = resolveCondition(block.data.root, path);
    if (!target) return;
    const list = ensureConditionList(target);
    list.push(createCondition(path === 'root' ? 'DOMAIN-SUFFIX' : 'DOMAIN-SUFFIX'));
    afterStructureChange();
    return;
  }

  if (action === 'del-cond' && block.type === 'rules') {
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

  /* ---------- [Rewrite]：单条复写 = IF 条件树 + THEN Action 列表 ----------
     不再有 add-rewrite / del-rewrite（区块固定单条结构） */
  if (action === 'add-cond' || action === 'add-cond-group') {
    const item = block.data.list[Number(btn.dataset.idx)];
    if (!item) return;
    const parent = resolveRewriteNode(item.conditions, btn.dataset.path || '');
    if (!parent || !Array.isArray(parent.items)) return;
    parent.items.push(
      action === 'add-cond-group' ? { kind: 'group', logic: '&&', items: [newCondition()] } : newCondition()
    );
    afterStructureChange();
    return;
  }

  if (action === 'del-cond') {
    const item = block.data.list[Number(btn.dataset.idx)];
    if (!item) return;
    removeRewriteNode(item.conditions, btn.dataset.path || '');
    afterStructureChange();
    return;
  }

  if (action === 'set-logic') {
    const item = block.data.list[Number(btn.dataset.idx)];
    if (!item) return;
    const group = resolveRewriteNode(item.conditions, btn.dataset.path || '');
    if (!group) return;
    group.logic = btn.dataset.logic === '||' ? '||' : '&&';
    afterStructureChange();
    return;
  }

  /* URL 正则条件：构建器 ↔ 手写正则 模式切换 */
  if (action === 'url-mode') {
    const wrap = btn.closest('.rewrite-item');
    const condRow = btn.closest('.row.is-cond');
    const item = wrap ? block.data.list[Number(wrap.dataset.idx)] : null;
    const cond = item && condRow ? resolveRewriteNode(item.conditions, condRow.dataset.path || '') : null;
    if (!cond || cond.kind === 'group') return;
    if (btn.dataset.mode === 'raw') {
      cond.urlMode = 'raw';
    } else {
      cond.urlMode = 'builder';
      cond.urlParts = parseUrlRegex(cond.value) || defaultUrlParts();
      cond.value = buildUrlRegex(cond.urlParts);
    }
    afterStructureChange();
    return;
  }

  /* 正则 flags：条件行的 flags 与 Action 参数组的 flags 用同一个按钮 */
  if (action === 'toggle-flag') {
    const flag = btn.dataset.flag || '';
    if (flag.length !== 1 || !'ims'.includes(flag)) return;
    const toggle = (holder) => {
      const current = String(holder.flags || '');
      holder.flags = current.includes(flag) ? current.split('').filter((f) => f !== flag).join('') : current + flag;
    };
    const condRow = btn.closest('.row.is-cond');
    const wrap = btn.closest('.rewrite-item');
    if (condRow && wrap) {
      const item = block.data.list[Number(wrap.dataset.idx)];
      const cond = item ? resolveRewriteNode(item.conditions, condRow.dataset.path || '') : null;
      if (!cond) return;
      toggle(cond);
      afterStructureChange();
      return;
    }
    const paramGroup = btn.closest('.param-group');
    const actionCard = btn.closest('.action-card');
    if (paramGroup && actionCard && wrap) {
      const item = block.data.list[Number(wrap.dataset.idx)];
      const act = item ? item.actions[Number(actionCard.dataset.aidx)] : null;
      const g = act && act.groups ? act.groups[Number(paramGroup.dataset.gidx)] : null;
      if (!g) return;
      toggle(g);
      afterStructureChange();
      return;
    }
    return;
  }

  if (action === 'add-action') {
    const item = block.data.list[Number(btn.dataset.idx)];
    if (!item) return;
    item.actions = item.actions || [];
    item.actions.push(newAction(item.phase === 'response' ? 'response.header.set' : 'request.header.set'));
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

  if (action === 'add-param') {
    const item = block.data.list[Number(btn.dataset.idx)];
    if (!item) return;
    const act = item.actions[Number(btn.dataset.aidx)];
    if (!act || !REWRITE_ACTIONS[act.type]) return;
    act.groups = act.groups && act.groups.length ? act.groups : [Object.assign({}, REWRITE_ACTIONS[act.type].defaults)];
    act.groups.push(Object.assign({}, REWRITE_ACTIONS[act.type].defaults));
    afterStructureChange();
    return;
  }

  if (action === 'del-param') {
    const item = block.data.list[Number(btn.dataset.idx)];
    if (!item) return;
    const act = item.actions[Number(btn.dataset.aidx)];
    if (!act || !act.groups) return;
    act.groups.splice(Number(btn.dataset.gidx), 1);
    afterStructureChange();
    return;
  }
}

/* ---------- [Rewrite] 条件树工具 ---------- */

/** 按路径取条件树里的节点（path 为空表示根组） */
function resolveRewriteNode(group, path) {
  if (!group) return null;
  if (!path) return group;
  let current = group;
  for (const index of String(path).split('.').filter(Boolean).map(Number)) {
    const list = current.items || [];
    current = list[index];
    if (!current) return null;
  }
  return current;
}

/** 删除条件树里某个路径上的节点 */
function removeRewriteNode(group, path) {
  const segments = String(path).split('.').filter(Boolean).map(Number);
  if (!segments.length) return;
  let parent = group;
  for (let i = 0; i < segments.length - 1; i += 1) {
    parent = (parent.items || [])[segments[i]];
    if (!parent) return;
  }
  (parent.items || []).splice(segments[segments.length - 1], 1);
}

/** 切换阶段后，把不适用于新阶段的条件字段重置为默认 URL 条件 */
function stripPhaseFields(group, phase) {
  if (!group) return group;
  (group.items || []).forEach((child, i) => {
    if (child.kind === 'group') {
      stripPhaseFields(child, phase);
      return;
    }
    const meta = REWRITE_FIELDS.find((f) => f.v === child.field);
    if (meta && meta.phases.indexOf(phase) === -1) group.items[i] = newCondition();
  });
  return group;
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

  /* ---------- [Rewrite]：条件树 + Action 参数组 ---------- */
  if (block.type === 'rewrite') {
    const wrap = input.closest('.rewrite-item');
    const item = wrap ? block.data.list[Number(wrap.dataset.idx)] : null;
    if (!item) return;

    /* 阶段切换：丢掉不属于新阶段的 Action，条件字段也一并降级（与官方生成器一致） */
    if (field === 'phase' && value !== item.phase) {
      const next = value === 'response' ? 'response' : 'request';
      item.phase = next;
      const kept = (item.actions || []).filter((a) => REWRITE_ACTIONS[a.type] && REWRITE_ACTIONS[a.type].phase === next);
      item.actions = kept.length ? kept : [newAction(next === 'response' ? 'response.header.set' : 'request.header.set')];
      stripPhaseFields(item.conditions, next);
      afterStructureChange();
      return;
    }

    /* 条件行字段 */
    if (field.indexOf('cond-') === 0) {
      const condRow = input.closest('.row.is-cond');
      const cond = condRow ? resolveRewriteNode(item.conditions, condRow.dataset.path || '') : null;
      if (!cond || cond.kind === 'group') return;
      if (field === 'cond-field') {
        cond.field = value;
        afterStructureChange();
        return;
      }
      if (field === 'cond-op') {
        cond.operator = value === '==' ? '==' : '~=';
        /* 操作符决定可用的值类型集合，切换后给一个合理默认值 */
        const types = REWRITE_VALUE_TYPES.filter((t) => t.ops.indexOf(cond.operator) !== -1);
        if (!types.some((t) => t.v === cond.valueType)) {
          cond.valueType = cond.operator === '~=' ? 'regex' : 'string';
          cond.value = cond.operator === '~=' ? '^https:\\/\\/example\\.com' : '';
        }
        afterStructureChange();
        return;
      }
      if (field === 'cond-vtype') {
        cond.valueType = value;
        if (value === 'regex' && !String(cond.value || '').trim()) cond.value = '^https:\\/\\/example\\.com';
        afterStructureChange();
        return;
      }
      if (field === 'cond-value') cond.value = value;
      else if (field === 'cond-header-name') cond.headerName = value;
      else if (field === 'cond-var-name') cond.variableName = value;
      else if (field === 'cond-capture') cond.captureName = value;
      renderPreview();
      scheduleSave();
      return;
    }

    /* URL 构建器字段：改部件后重新拼正则写回 cond.value（用户无需手写 \/ 转义） */
    if (field.indexOf('url-') === 0) {
      const condRow = input.closest('.row.is-cond');
      const cond = condRow ? resolveRewriteNode(item.conditions, condRow.dataset.path || '') : null;
      if (!cond || cond.kind === 'group') return;
      const parts = ensureUrlParts(cond) || defaultUrlParts();
      const key = field.slice(4);
      if (key === 'exact') parts.exact = input.checked;
      else if (key === 'scheme') parts.scheme = value;
      else parts[key] = value;
      cond.urlParts = parts;
      cond.value = buildUrlRegex(parts);
      renderPreview();
      scheduleSave();
      return;
    }

    /* Action 类型切换：按官方默认值重置参数组 */
    if (field === 'action-type') {
      const card = input.closest('.action-card');
      const act = card ? item.actions[Number(card.dataset.aidx)] : null;
      if (!act || !REWRITE_ACTIONS[value]) return;
      act.type = value;
      act.groups = [Object.assign({}, REWRITE_ACTIONS[value].defaults)];
      afterStructureChange();
      return;
    }

    /* Action 参数组里的字段（data-field="f-xxx"） */
    if (field.indexOf('f-') === 0) {
      const card = input.closest('.action-card');
      const groupRow = input.closest('.param-group');
      const act = card ? item.actions[Number(card.dataset.aidx)] : null;
      const g = act && groupRow && act.groups ? act.groups[Number(groupRow.dataset.gidx)] : null;
      if (!g) return;
      const key = field.slice(2);
      if (key === 'raw' || key === 'base64') {
        g[key] = input.checked;
        afterStructureChange();
        return;
      }
      /* 数据来源 / 响应类型 / 值类型会改变表单结构，重绘 */
      if (key === 'source' || key === 'mode' || key === 'valueType') {
        g[key] = value;
        afterStructureChange();
        return;
      }
      g[key] = value;
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
  const raw = String(currentPlugin().filename || 'loon-plugin').trim();
  const out = raw.replace(/[\\/:*?"<>|\s]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 80);
  return out || 'loon-plugin';
}

function downloadPlugin() {
  const { text, scripts, issues } = state.view;
  const errors = issues.filter((i) => i.level === 'error');
  if (errors.length) {
    toast(`还有 ${errors.length} 个错误，已导出但 Loon 可能加载失败`, 'error');
  }
  const base = safeName();
  downloadFile(`${base}.plugin`, text);

  /* 同名的 .js 脚手架/脚本：始终与 .plugin 文件一起导出，文件名严格同步 */
  let js = '';
  if (Array.isArray(scripts) && scripts.length) {
    js = scripts
      .map((s, i) => {
        const header = scripts.length > 1 ? `// ===== ${s.file || `${base}-${i + 1}.js`} =====` : '';
        const body = (s.code || '').trimEnd();
        return header ? `${header}\n${body}` : body;
      })
      .filter((chunk) => String(chunk).trim().length)
      .join('\n\n');
  }
  if (!js.trim()) {
    js = [
      `// ${base}.js`,
      `// 与 ${base}.plugin 配套使用的 Loon 脚本`,
      `// 在 [Script] 区块的「脚本代码」里填写实际内容，重新导出即可覆盖本文件。`,
      `// 常用入口：`,
      `//   $argument        → [Argument] 传过来的参数`,
      `//   $request/$response → HTTP 请求或响应对象`,
      `//   $done(result)   → 把修改结果返回给 Loon`,
      ``,
      `(async () => {`,
      `  try {`,
      `    const args = $argument || {};`,
      `    // TODO: 在这里实现你的逻辑`,
      `    $done({});`,
      `  } catch (err) {`,
      `    console.error('[${base}] 脚本出错：', err);`,
      `    $done({});`,
      `  }`,
      `})();`,
      ``
    ].join('\n');
  } else {
    js = js.trimEnd() + '\n';
  }
  window.setTimeout(() => downloadFile(`${base}.js`, js), 150);
  toast(`已导出 ${base}.plugin + ${base}.js`, 'success');
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
