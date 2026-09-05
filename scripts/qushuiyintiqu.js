// 仅用于学习演示
function getRandomPhone() {
  const prefixes = [
    '138','139','150','151','152','158','159',
    '170','171','180','181','182','183','185'
  ]
  const prefix = prefixes[Math.floor(Math.random() * prefixes.length)]
  let suffix = ''
  for (let i = 0; i < 8; i++) {
    suffix += Math.floor(Math.random() * 10)
  }
  return prefix + suffix
}

let body = $response.body

body = body.replace(/"userPhone":"1[3-9]\d{9}"/g, () => {
  return `"userPhone":"${getRandomPhone()}"`
});

body = body.replace(/"vipState":\s*0/g, '"vipState":1');


$done({body});
