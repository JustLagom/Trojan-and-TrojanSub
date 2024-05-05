## 快速上手
一、TrojanSub（订阅器代码） 可部署订阅器参考vless订阅器部署，自行设置优选ip api

https://订阅器域名/sub?host=xxxx&password=xxxx&proxyip=true或者false（true即启用订阅器内设置proxyIP）。


二、_worker.js（Trojan配置）部署更改password与sha244加密值

使用你自己的password和sha224Password替换 `password`、`sha224Password`。你可以点击 [这里](https://www.atatus.com/tools/sha224-to-hash).获取sha224加密值。

https://[你的域名]/[设置的token]即为自适应订阅链接页面获取订阅链接。

## 未支持事项
- UDP

## 免责声明
该项目仅供学习/研究目的，用户对法律合规和道德行为负责，作者对任何滥用行为概不负责。

## 参考
[zizifn/edgetunnel](https://github.com/ca110us/epeius)

[ca110us/epeius](https://github.com/zizifn/edgetunnel)

[cmliu/WorkerVless2sub](https://github.com/cmliu/WorkerVless2sub)

