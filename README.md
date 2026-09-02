# Loon Plugin Studio

一个纯静态的 Loon 插件可视化工作台 + 一份可直接使用的插件模板仓库。

打开 `index.html` 就能用，无需构建、无需后端。

## 目录结构

```text
loon-plugin-demo/
├── index.html            # 工作台页面
├── styles.css
├── app.js                # 生成器 + 语法校验 + 预览
├── plugins/
│   └── demo.plugin       # 已按官方语法修正的示例插件
├── scripts/
│   └── demo.js           # 示例脚本（被 demo.plugin 通过 script-path 引用）
└── assets/
    └── icon.png
```

## 在线使用

直接双击 `index.html` 即可，无需构建、无需后端。

若浏览器限制了 localStorage（部分浏览器直接双击打开时会），改用本地服务器：

```bash
python -m http.server 8000
# 然后访问 http://127.0.0.1:8000
```

### 部署到 GitHub Pages

工作台是纯静态的，可以直接托管：

1. 仓库 Settings → Pages → Source 选 `Deploy from a branch`
2. Branch 选 `main`，目录选 `/ (root)`
3. 保存后访问 `https://<用户名>.github.io/loon-plugin-demo/`

注意两点：

- 草稿存在**浏览器 localStorage**，换设备或换浏览器不会同步，重要插件记得导出 `.plugin` 备份
- 生成的插件里 `script-path` 要填 raw 远程链接，改完脚本**先 push** 再在 Loon 里重载，否则拉到的还是旧版本

## 工作台能做什么

- **多插件工作区**：左侧新建 / 切换 / 删除，草稿自动存在浏览器 localStorage
- **区块化组装**：参数、通用、规则、复写、Host、脚本、MITM 共 8 种区块（外加详情元信息），可拖拽排序、折叠、复制
- **规则树**：支持 `AND` / `OR` / `NOT` 逻辑规则与嵌套子规则
- **插件参数**：`[Argument]` 可视化声明 input / select / switch，复写与脚本里用 `${name}` 引用
- **实时预览**：右侧同步生成 `.plugin` 文本，带语法高亮
- **语法校验**：错误 / 警告清单，可一键定位到出问题的区块
- **导出**：一键下载 `.plugin`，脚本代码单独导出为 `.js`

## Loon 插件语法速查

以下全部按 Loon 3.5.1 官方文档（<https://nsloon.app/docs/Plugin/>）整理，语法依据为 Rewrite (978) 与 Script (983) 新写法。

### 元信息（`#!` 开头）

只有以下字段被 Loon 识别，**写错字段不会报错，但会被静默忽略**：

| 字段 | 说明 |
| --- | --- |
| `#!name` | 必需，插件名 |
| `#!desc` | 插件描述 |
| `#!icon` | 图标，http(s) 链接或 base64 |
| `#!author` | 作者 |
| `#!homepage` | 主页，必须以 `http://` 或 `https://` 开头 |
| `#!tag` | 分类标签，多个用英文逗号分隔 |
| `#!system` | 支持的系统，如 `iOS,iPadOS,tvOS,macOS` |

> ❌ `#!category` 和 `#!date` **不是**合法字段。

### 区块

插件按顺序支持这 8 个区块：

```text
[Argument]   插件参数（Loon 里生成设置界面）
[General]    bypass-tun / skip-proxy / real-ip / dns-server
[Rule]       分流规则
[Rewrite]    复写（978 新语法）
[Host]       域名映射
[Script]     脚本（983 新语法）
[Mitm]       需要解密的主机名（注意是 [Mitm]，不是 [MITM]）
```

### `[Argument]`

基本格式：`参数名 = 控件类型,默认值或可选值,tag=标题,desc=说明`。参数在复写 / 脚本条件与 `with` 属性里用 `${参数名}` 引用。

```text
[Argument]
token = input, "默认令牌", tag=令牌, desc=用于脚本鉴权的令牌
region = select, "CN", "US", "JP", tag=地区   ; 第一个值为默认值
enabled = switch, true, tag=启用
level = select, 1, 2, 3, type=number, tag=等级 ; 数字比较时加 type=number
```

### `[General]`

```text
[General]
bypass-tun = 192.168.0.0/16, 10.0.0.0/8
skip-proxy = 192.168.1.1
real-ip = 1.2.3.4
dns-server = 223.5.5.5, 119.29.29.29
```

### `[Rule]`

顶层规则每行 `类型,值,策略`。插件中**策略只能用** `DIRECT`、`PROXY` 和 `REJECT` 系列
（`REJECT` / `REJECT-DROP` / `REJECT-IMG` / `REJECT-DICT` / `REJECT-ARRAY` 及其 `-NO-DROP` 变体），
不能指向自己的策略组。规则未指定策略时默认 `DIRECT`。

逻辑规则 `AND` / `OR` / `NOT` 的子规则**写在括号里且不带策略**：

```text
AND,((DOMAIN-KEYWORD,ads),(USER-AGENT,*AdBot*)),REJECT
NOT,((DOMAIN-SUFFIX,example.com)),DIRECT
```

`NOT` 只接受一个子规则。

### `[Rewrite]`（978 新语法）

每行：`<request|response> if <条件> then <Action>(参数)[ | <Action>(参数) ...]`

- 条件用 `${url} ~= /正则/`（`~=` 是查找匹配，完整匹配要显式写 `^` `$`），条件后可用 `as 名字` 保存捕获，Action 里用 `${名字.1}` 引用
- 字符串参数加双引号，正则参数写 `/…/`，数字 / 布尔 / 变量原样；多个 Action 用 `|` 连接，从左到右执行

```text
[Rewrite]
request if ${url} ~= /^https?:\/\/(www\.)?example\.cn\/path/ then url.replace("https://example.com/path")
response if ${url} ~= /^https?:\/\/api\.example\.com\/profile$/ && ${response.status} == 200 then response.json.replace("data.vip", true)
request if ${url} ~= /^https:\/\/example\.com\/ads/ then reject_dict(200)
```

常用 Action：`url.replace(内容)`、`redirect(302|307, 目标)`、`reject(状态码[, 响应体])`、`reject_img / reject_dict / reject_array / reject_video(状态码)`、`request|response.header.add/set/del/replace`、`request|response.body.replace(正则, 替换)`、`request|response.json.add/delete/replace/jq/jq_file`、`request|response.body.mock/mock_file`。

包含 `response.body.mock(_file)` 的复写只能再搭配 `response.header.*`，且一条复写最多一个 Mock。

### `[Host]`

```text
[Host]
example.com = 192.168.1.20          ; 固定 IP
example.com = example.com.cn        ; 别名域名
*.testflight.apple.com = server:8.8.4.4   ; 指定 DNS 服务器
*.apple.com = server:system         ; 系统 DNS
example.com = ip-mode:ipv4-only     ; IP 模式
```

### `[Script]`（983 新语法）

```text
[Script]
# HTTP：request|response if <条件> then script(路径[, 参数]) [with 属性]
request if ${url} ~= /^https?:\/\/api\.example\.com/i && ${request.method} == "POST" then script("request.js", "source=profile") with tag="Request", timeout=20, requires_body=true

# 对象参数：花括号里只能引用 [Argument] 已声明的参数名，$argument 收到对象
response if ${url} ~= /^https?:\/\/api\.example\.com\/v1\/user/i then script("https://example.com/demo.js", {${token}}) with tag="DemoUser", timeout=10, requires_body=true

# 定时：Cron 表达式用引号包起来，支持 5 段或 6 段
cron "0 8 * * *" then script("cron.js") with timeout=300

# 网络变化 / 手动触发
network-changed then script("network.js") with tag="Network"
generic then script("tool.js", "region=CN") with tag="Tool", timeout=30
```

- `with` 属性：`enable`、`tag`、`img_url`、`timeout`、`debug`、`requires_body`、`binary_body_mode`（后两个仅限 request / response）
- **response 脚本必须带 URL 正则（URL Guard）**，且它是条件成立的必要条件
- 同一请求最多命中一条 Request / Response Script，按配置顺序取第一条完整命中的
- **`.plugin` 文件里不能内嵌 JS 代码**，只能通过 `script("...")` 引用；远程脚本填完整 https 链接，本地脚本填文件名并放到 Loon 的脚本目录

### `[Mitm]`

主机名写在**同一行、英文逗号分隔**，不能一行一个：

```text
[Mitm]
hostname = api.example.com, *.example.cn
```

支持 `*.example.com` 通配。**不要带 `https://` 协议头。**

只要用到改写 HTTPS 的 request / response 脚本或复写，就必须配置 MITM，否则不会生效。

## 用仓库里的模板

1. 把 `plugins/demo.plugin` 导入 Loon（需 Loon 3.5.1+）
2. 把 `scripts/demo.js` 上传到可公开访问的地址（如 GitHub Raw），或放进 Loon 的脚本目录
3. 修改 `demo.plugin` 里 `script(...)` 的脚本地址
4. 记得在 Loon 里开启该插件的 MITM

---

最小可用版本跑通之后再往上加规则和脚本，比一口气写一大坨再排查要快得多。
