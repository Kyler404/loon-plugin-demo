/**
 * Loon JS 脚本示例（http-response）
 * 挂在：^https?:\/\/api\.example\.com\/v1\/user
 *
 * 关键点：
 *   1. 必须 requires-body=true，否则 $response.body 为空
 *   2. 解析失败时一定要 $done({}) 把原始响应放回去，别让脚本抛异常
 *   3. 脚本写在 .js 文件里，.plugin 只能通过 script-path 引用，不能内嵌代码
 */

// 可选：读取 .plugin 里 argument= 传进来的参数
// const arg = Object.fromEntries(
//   ($argument || '').split('&').filter(Boolean).map((kv) => kv.split('='))
// );

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

  $done({
    status: $response.status || 200,
    headers: $response.headers,
    body: JSON.stringify(body)
  });
}
