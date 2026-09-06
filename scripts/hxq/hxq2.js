//仅学习交流
let body = $response.body;

body = JSON.parse(body);

const lastQuality = body.qualities[body.qualities.length - 1];
body.quality = lastQuality.value;
body.qualityName = lastQuality.name;

body.vnjoy.as = 1;
body.vnjoy.grade.level = 3;

body = JSON.stringify(body);

// 如果有 $done 回调
$done({body});