//仅学习交流
let body = $response.body;

body = JSON.parse(body);

body.vnjoy.as = 1;
body.vnjoy.at = 1;
body.vnjoy.grade.level = 3;

body = JSON.stringify(body);

// 如果有 $done 回调
$done({body});