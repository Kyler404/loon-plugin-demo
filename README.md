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

直接双击 `index.html` 即可。若浏览器限制了 localStorage，改用本地服务器：

```bash
python -m http.server 8000
# 然后访问 http://127.0.0.1:8000
```

## 工作台能做什么

- **多插件工作区**：左侧新建 / 切换 / 删除，草稿自动存在浏览器 localStorage
- **区块化组装**：详情、主机名、规则、复写、脚本五种区块，可拖拽排序、折叠、复制
- **规则树**：支持 `AND` / `OR` / `NOT` 逻辑规则与嵌套子规则
- **实时预览**：右侧同步生成 `.plugin` 文本，带语法高亮
- **语法校验**：错误 / 警告清单，可一键定位到出问题的区块
- **导出**：一键下载 `.plugin`，脚本代码单独导出为 `.js`

## Loon 插件语法速查

这一段是本仓库的**纠错重点**，之前版本踩过的坑都列在下面。

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

插件文件只支持这 4 个区块，其余（如配置里的 `[Host]`、`[General]`）不属于插件：

```text
[Rule]
[URL Rewrite]      ; Loon 3.5.1+ 也可写 [Rewrite]
[Script]
[MITM]
```

### `[MITM]`

主机名写在**同一行、英文逗号分隔**，不能一行一个：

```text
[MITM]
hostname = api.example.com, *.example.cn
```

支持 `*.example.com` 通配。**不要带 `https://` 协议头。**

只要用到 `http-request` / `http-response` 脚本或 URL 复写，就必须配置 MITM，否则不会生效。

### `[Rule]`

顶层规则每行 `类型,值,策略`。插件中**策略只能用** `DIRECT`、`PROXY` 和 `REJECT` 系列
（`REJECT` / `REJECT-DROP` / `REJECT-IMG` / `REJECT-DICT` / `REJECT-ARRAY` 及其 `-NO-DROP` 变体），
不能指向自己的策略组。

逻辑规则 `AND` / `OR` / `NOT` 的子规则**写在括号里且不带策略**：

```text
AND,((DOMAIN-KEYWORD,ads),(USER-AGENT,*AdBot*)),REJECT
NOT,((DOMAIN-SUFFIX,example.com)),DIRECT
```

`NOT` 只接受一个子规则。

### `[URL Rewrite]`

```text
[URL Rewrite]
^https?:\/\/example\.cn\/path https://example.com/path 302
^https?:\/\/ads\.example\.com\/.* reject-img
```

| 类型 | 需要目标地址 |
| --- | --- |
| `302` `301` `307` `308` `header` | 是 |
| `reject` `reject-200` `reject-img` `reject-dict` `reject-array` | 否 |

`[Rewrite]`（Loon 3.5.1+）字段顺序不同，是 `pattern 类型 目标`，工作台里可一键切换。

### `[Script]`

```text
[Script]
http-response ^https?:\/\/api\.example\.com\/v1\/user script-path=demo.js, requires-body=true, timeout=10, tag=DemoUser
cron "0 8 * * *" script-path=https://example.com/cron.js, timeout=300, tag=签到
```

- 脚本类型：`http-request` / `http-response` / `cron` / `network-changed` / `generic` / `dns`
- 参数：`script-path`（必需）、`requires-body`、`timeout`、`tag`、`enable`、`argument`、`binary-mode`
- `http-request` / `http-response` / `cron` 需要匹配项（URL 正则或 Cron 表达式），Cron 表达式用引号包起来
- **`.plugin` 文件里不能内嵌 JS 代码**，只能通过 `script-path` 引用；远程脚本填完整 https 链接，本地脚本填文件名并放到 Loon 的脚本目录

## 用仓库里的模板

1. 把 `plugins/demo.plugin` 导入 Loon
2. 把 `scripts/demo.js` 上传到可公开访问的地址（如 GitHub Raw），或放进 Loon 的脚本目录
3. 修改 `demo.plugin` 里的 `script-path` 指向你的脚本地址
4. 记得在 Loon 里开启该插件的 MITM

---

最小可用版本跑通之后再往上加规则和脚本，比一口气写一大坨再排查要快得多。
