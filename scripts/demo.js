/**
 * Loon JS 脚本示例（response Script · 983 新语法挂载）
 * 挂在：^https?:\/\/api\.example\.com\/v1\/user
 *
 * 关键点：
 *   1. 插件里 requires_body=true，否则 $response.body 为空
 *   2. 解析失败时一定要 $done({}) 把原始响应放回去，别让脚本抛异常
 *   3. .plugin 里通过 script("...", {${token}}) 传对象参数，$argument 是对象
 */

// $argument 由插件 [Argument] 的对象传参生成：{ token: "用户填的值" }
const { token } = $argument || {};

let body;
try {
  body = JSON.parse($response.body || '{}');
} catch (err) {
  console.log('demo.js: 响应不是合法 JSON，原样放行');
  $done({});
}

if (!body || typeof body !== 'object') {
  $done({});
} else {
  body.data = body.data || {};
  body.data.demo = true;
  body.data.message = 'Hello from Loon plugin demo';
  body.data.token = token || '';

  $done({
    status: $response.status || 200,
    headers: $response.headers,
    body: JSON.stringify(body)
  });
}
