let body = $response.body;

body = JSON.parse(body);

if (body.content.waterVipInfo === null) {
    // 为 null，添加默认值
    body.content.waterVipInfo = {"typeName": "By过客", "remainDays": 9999};
} else {
    // 有值，替换内容
        body.content.waterVipInfo.typeName = "By过客";
        body.content.waterVipInfo.remainDays = 9999;
}

body = JSON.stringify(body);

// 如果有 $done 回调
$done({body});