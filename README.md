一、TrojanSub（订阅器代码） 可部署订阅器参考vless订阅器部署，自行设置优选ip api

https://订阅器域名/sub?host=xxxx&password=xxxx&proxyip=true或者false（true即启用订阅器内设置proxyIP）


二、_worker.js（Trojan配置）部署更改password与sha244加密值

https://域名/token即为自适应订阅链接

base64格式 https://域名/token?base64（目前报错error code 1042）

clash格式 https://域名/token?clash

singbox格式 https://域名/token?singbox
