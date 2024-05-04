// src/worker.js
import { connect } from "cloudflare:sockets";
let sha224Password = '08f32643dbdacf81d0d511f1ee24b06de759e90f8edf742bbdc57d88';//sha224加密
let password= 'ca110us';//password
let proxydomain = 'www.bing.com';
let proxyIP = 'proxyip.fxxk.dedyn.io';//可留空使用订阅器内置proxyIP
let token= 'trojan';
let RproxyIP = 'true';
let sub = 'sub.xmm404.workers.dev';
let subconverter = 'apiurl.v1.mk';
let subconfig = 'https://raw.githubusercontent.com/JustLagom/test/main/urltestconfig.ini';
let fakePassword = generatePASSWORD();
let fakeHostName = generateRandomString();

const worker_default = {
    /**
     * @param {import("@cloudflare/workers-types").Request} request
     * @param {{UUID, TOKEN, PROXYIP, PROXYDOMAIN, PASSWORD, USENAME, RPROXYIP: string}} env
     * @param {import("@cloudflare/workers-types").ExecutionContext} ctx
     * @returns {Promise<Response>}
     */
    async fetch(request, env, ctx) {
        try {
            token = env.TOKEN || token;
            const UA = request.headers.get('User-Agent') || 'null';
            const userAgent = UA.toLowerCase();
            proxyIP = env.PROXYIP || proxyIP;
            password = env.PASSWORD || password;
            usename = env.USENAME || usename;
            proxydomain = env.PROXYDOMAIN || proxydomain;
            RproxyIP = env.RPROXYIP || !proxyIP ? 'true' : 'false';
            const upgradeHeader = request.headers.get("Upgrade");
            const url = new URL(request.url);
            if (!upgradeHeader || upgradeHeader !== "websocket") {
                // const url = new URL(request.url);
                switch (url.pathname.toLowerCase()) {
                    case `/${token}`:{
                        const trojanConfig = await getTrojanConfig(password, request.headers.get('Host'), sub, UA, RproxyIP, url);
                        const now = Date.now();
                        const timestamp = Math.floor(now / 1000);
                        const expire = 4102329600;//2099-12-31
                        const today = new Date(now);
                        today.setHours(0, 0, 0, 0);
                        const UD = Math.floor(((now - today.getTime())/86400000) * 24 * 1099511627776 / 2);
                        if (userAgent && userAgent.includes('mozilla')){
							return new Response(`${trojanConfig}`, {
								status: 200,
								headers: {
									"Content-Type": "text/plain;charset=utf-8",
									"Profile-Update-Interval": "6",
									"Subscription-Userinfo": `upload=${UD}; download=${UD}; total=${24 * 1099511627776}; expire=${expire}`,
								}
							});
						} else {
							return new Response(`${trojanConfig}`, {
								status: 200,
								headers: {
									"Content-Disposition": "attachment; filename=edgetunnel; filename*=utf-8''edgetunnel",
									"Content-Type": "text/plain;charset=utf-8",
									"Profile-Update-Interval": "6",
									"Subscription-Userinfo": `upload=${UD}; download=${UD}; total=${24 * 1099511627776}; expire=${expire}`,
								}
							});
						}
					}
                    default:
                            url.hostname = proxydomain;
                            url.protocol = 'https:';
                            request = new Request(url, request);
                            return await fetch(request);
                    }
            } else {
                proxyIP = url.searchParams.get('proxyip') || proxyIP;
				if (new RegExp('/proxyip=', 'i').test(url.pathname)) proxyIP = url.pathname.toLowerCase().split('/proxyip=')[1];
				else if (new RegExp('/proxyip.', 'i').test(url.pathname)) proxyIP = `proxyip.${url.pathname.toLowerCase().split("/proxyip.")[1]}`;
				else if (!proxyIP || proxyIP == '') proxyIP = 'proxyip.fxxk.dedyn.io';
				return await trojanOverWSHandler(request);
            }
        } catch (err) {
            let e = err;
            return new Response(e.toString());
        }
    }
};

async function trojanOverWSHandler(request) {
    const webSocketPair = new WebSocketPair();
    const [client, webSocket] = Object.values(webSocketPair);
    webSocket.accept();
    let address = "";
    let portWithRandomLog = "";
    const log = (info, event) => {
        console.log(`[${address}:${portWithRandomLog}] ${info}`, event || "");
    };
    const earlyDataHeader = request.headers.get("sec-websocket-protocol") || "";
    const readableWebSocketStream = makeReadableWebSocketStream(webSocket, earlyDataHeader, log);
    let remoteSocketWapper = {
        value: null
    };
    let udpStreamWrite = null;
    readableWebSocketStream.pipeTo(new WritableStream({
        async write(chunk, controller) {
            if (udpStreamWrite) {
                return udpStreamWrite(chunk);
            }
            if (remoteSocketWapper.value) {
                const writer = remoteSocketWapper.value.writable.getWriter();
                await writer.write(chunk);
                writer.releaseLock();
                return;
            }
            const {
                hasError,
                message,
                portRemote = 443,
                addressRemote = "",
                rawClientData
            } = await parseTrojanHeader(chunk);
            address = addressRemote;
            portWithRandomLog = `${portRemote}--${Math.random()} tcp`;
            if (hasError) {
                throw new Error(message);
                return;
            }
            handleTCPOutBound(remoteSocketWapper, addressRemote, portRemote, rawClientData, webSocket, log);
        },
        close() {
            log(`readableWebSocketStream is closed`);
        },
        abort(reason) {
            log(`readableWebSocketStream is aborted`, JSON.stringify(reason));
        }
    })).catch((err) => {
        log("readableWebSocketStream pipeTo error", err);
    });
    return new Response(null, {
        status: 101,
        // @ts-ignore
        webSocket: client
    });
}

async function parseTrojanHeader(buffer) {
    if (buffer.byteLength < 56) {
        return {
            hasError: true,
            message: "invalid data"
        };
    }
    let crLfIndex = 56;
    if (new Uint8Array(buffer.slice(56, 57))[0] !== 0x0d || new Uint8Array(buffer.slice(57, 58))[0] !== 0x0a) {
        return {
            hasError: true,
            message: "invalid header format (missing CR LF)"
        };
    }
    const password = new TextDecoder().decode(buffer.slice(0, crLfIndex));
    if (password !== sha224Password) {
        return {
            hasError: true,
            message: "invalid password"
        };
    }

    const socks5DataBuffer = buffer.slice(crLfIndex + 2);
    if (socks5DataBuffer.byteLength < 6) {
        return {
            hasError: true,
            message: "invalid SOCKS5 request data"
        };
    }

    const view = new DataView(socks5DataBuffer);
    const cmd = view.getUint8(0);
    if (cmd !== 1) {
        return {
            hasError: true,
            message: "unsupported command, only TCP (CONNECT) is allowed"
        };
    }

    const atype = view.getUint8(1);
    // 0x01: IPv4 address
    // 0x03: Domain name
    // 0x04: IPv6 address
    let addressLength = 0;
    let addressIndex = 2;
    let address = "";
    switch (atype) {
        case 1:
            addressLength = 4;
            address = new Uint8Array(
              socks5DataBuffer.slice(addressIndex, addressIndex + addressLength)
            ).join(".");
            break;
        case 3:
            addressLength = new Uint8Array(
              socks5DataBuffer.slice(addressIndex, addressIndex + 1)
            )[0];
            addressIndex += 1;
            address = new TextDecoder().decode(
              socks5DataBuffer.slice(addressIndex, addressIndex + addressLength)
            );
            break;
        case 4:
            addressLength = 16;
            const dataView = new DataView(socks5DataBuffer.slice(addressIndex, addressIndex + addressLength));
            const ipv6 = [];
            for (let i = 0; i < 8; i++) {
                ipv6.push(dataView.getUint16(i * 2).toString(16));
            }
            address = ipv6.join(":");
            break;
        default:
            return {
                hasError: true,
                message: `invalid addressType is ${atype}`
            };
    }

    if (!address) {
        return {
            hasError: true,
            message: `address is empty, addressType is ${address}`
        };
    }

    const portIndex = addressIndex + addressLength;
    const portBuffer = socks5DataBuffer.slice(portIndex, portIndex + 2);
    const portRemote = new DataView(portBuffer).getUint16(0);
    return {
        hasError: false,
        addressRemote: address,
        portRemote,
        rawClientData: socks5DataBuffer.slice(portIndex + 4)
    };
}

async function handleTCPOutBound(remoteSocket, addressRemote, portRemote, rawClientData, webSocket, log) {
    async function connectAndWrite(address, port) {
        const tcpSocket2 = connect({
            hostname: address,
            port
        });
        remoteSocket.value = tcpSocket2;
        log(`connected to ${address}:${port}`);
        const writer = tcpSocket2.writable.getWriter();
        await writer.write(rawClientData);
        writer.releaseLock();
        return tcpSocket2;
    }
    async function retry() {
        const tcpSocket2 = await connectAndWrite(proxyIP || addressRemote, portRemote);
        tcpSocket2.closed.catch((error) => {
            console.log("retry tcpSocket closed error", error);
        }).finally(() => {
            safeCloseWebSocket(webSocket);
        });
        remoteSocketToWS(tcpSocket2, webSocket, null, log);
    }
    const tcpSocket = await connectAndWrite(addressRemote, portRemote);
    remoteSocketToWS(tcpSocket, webSocket, retry, log);
}

function makeReadableWebSocketStream(webSocketServer, earlyDataHeader, log) {
    let readableStreamCancel = false;
    const stream = new ReadableStream({
        start(controller) {
            webSocketServer.addEventListener("message", (event) => {
                if (readableStreamCancel) {
                    return;
                }
                const message = event.data;
                controller.enqueue(message);
            });
            webSocketServer.addEventListener("close", () => {
                safeCloseWebSocket(webSocketServer);
                if (readableStreamCancel) {
                    return;
                }
                controller.close();
            });
            webSocketServer.addEventListener("error", (err) => {
                log("webSocketServer error");
                controller.error(err);
            });
            const { earlyData, error } = base64ToArrayBuffer(earlyDataHeader);
            if (error) {
                controller.error(error);
            } else if (earlyData) {
                controller.enqueue(earlyData);
            }
        },
        pull(controller) {},
        cancel(reason) {
            if (readableStreamCancel) {
                return;
            }
            log(`readableStream was canceled, due to ${reason}`);
            readableStreamCancel = true;
            safeCloseWebSocket(webSocketServer);
        }
    });
    return stream;
}

async function remoteSocketToWS(remoteSocket, webSocket, retry, log) {
    let hasIncomingData = false;
    await remoteSocket.readable.pipeTo(
        new WritableStream({
            start() {},
            /**
             *
             * @param {Uint8Array} chunk
             * @param {*} controller
             */
            async write(chunk, controller) {
                hasIncomingData = true;
                if (webSocket.readyState !== WS_READY_STATE_OPEN) {
                    controller.error(
                        "webSocket connection is not open"
                    );
                }
                webSocket.send(chunk);
            },
            close() {
                log(`remoteSocket.readable is closed, hasIncomingData: ${hasIncomingData}`);
            },
            abort(reason) {
                console.error("remoteSocket.readable abort", reason);
            }
        })
    ).catch((error) => {
        console.error(
            `remoteSocketToWS error:`,
            error.stack || error
        );
        safeCloseWebSocket(webSocket);
    });
    if (hasIncomingData === false && retry) {
        log(`retry`);
        retry();
    }
}

function base64ToArrayBuffer(base64Str) {
    if (!base64Str) {
        return { error: null };
    }
    try {
        base64Str = base64Str.replace(/-/g, "+").replace(/_/g, "/");
        const decode = atob(base64Str);
        const arryBuffer = Uint8Array.from(decode, (c) => c.charCodeAt(0));
        return { earlyData: arryBuffer.buffer, error: null };
    } catch (error) {
        return { error };
    }
}

let WS_READY_STATE_OPEN = 1;
let WS_READY_STATE_CLOSING = 2;

function safeCloseWebSocket(socket) {
    try {
        if (socket.readyState === WS_READY_STATE_OPEN || socket.readyState === WS_READY_STATE_CLOSING) {
            socket.close();
        }
    } catch (error) {
        console.error("safeCloseWebSocket error", error);
    }
}
export {
    worker_default as
    default
};
//# sourceMappingURL=worker.js.map
function revertFakeInfo(content, password, hostName, isBase64) {
	if (isBase64) content = atob(content);//Base64解码
	content = content.replace(new RegExp(fakePassword, 'g'), password).replace(new RegExp(fakeHostName, 'g'), hostName);
	if (isBase64) content = btoa(content);//Base64编码

	return content;
}

function generateRandomNumber() {
	let minNum = 100000;
	let maxNum = 999999;
	return Math.floor(Math.random() * (maxNum - minNum + 1)) + minNum;
}

function generateRandomString() {
	let minLength = 2;
	let maxLength = 3;
	let length = Math.floor(Math.random() * (maxLength - minLength + 1)) + minLength;
	let characters = 'abcdefghijklmnopqrstuvwxyz';
	let result = '';
	for (let i = 0; i < length; i++) {
		result += characters[Math.floor(Math.random() * characters.length)];
	}
	return result;
}

function generatePASSWORD() {
	let uuid = '';
	for (let i = 0; i < 32; i++) {
		let num = Math.floor(Math.random() * 16);
		if (num < 10) {
			uuid += num;
		} else {
			uuid += String.fromCharCode(num + 55);
		}
	}
	return uuid.replace(/(.{8})(.{4})(.{4})(.{4})(.{12})/, '$1-$2-$3-$4-$5').toLowerCase();
}

let subParams = ['sub','base64','b64','clash','singbox','sb'];

/**
 * @param {string} password
 * @param {string | null} hostName
 * @param {string} sub
 * @param {string} UA
 * @returns {Promise<string>}
 */
async function getTrojanConfig(password, hostName, sub, UA, RproxyIP, _url) {
	const userAgent = UA.toLowerCase();
	if ((!sub || sub === '' || (sub && userAgent.includes('mozilla'))) && !subParams.some(_searchParams => _url.searchParams.has(_searchParams))) {
		return `
		<!DOCTYPE html>
		<html>
		<head>
		<title>Welcome to nginx!</title>
		<style>
			body {
				width: 35em;
				margin: 0 auto;
				font-family: Tahoma, Verdana, Arial, sans-serif;
			}
		</style>
		</head>
		<body>
		<h1>Welcome to nginx!</h1>
		<p>If you see this page, the nginx web server is successfully installed and
		working. Further configuration is required.</p>
		
		<p>For online documentation and support please refer to
		<a href="http://nginx.org/">nginx.org</a>.<br/>
		Commercial support is available at
		<a href="http://nginx.com/">nginx.com</a>.</p>
		
		<p><em>Thank you for using nginx.</em></p>
		</body>
		</html>
		`;
        } else {
		if (typeof fetch != 'function') {
			return 'Error: fetch is not available in this environment.';
		}
		if (hostName.includes(".workers.dev")){
			fakeHostName = `${fakeHostName}.${generateRandomString()}${generateRandomNumber()}.workers.dev`;
		} else if (hostName.includes(".pages.dev")){
			fakeHostName = `${fakeHostName}.${generateRandomString()}${generateRandomNumber()}.pages.dev`;
		} else {
			fakeHostName = `${fakeHostName}.${generateRandomNumber()}.xyz`
		}

		let url = `https://${sub}/sub?host=${hostName}&password=${password}&proxyip=${RproxyIP}`;
		let isBase64 = true;
		if (!userAgent.includes(('CF-Workers-SUB').toLowerCase())){
			if ((userAgent.includes('clash') && !userAgent.includes('nekobox')) || ( _url.searchParams.has('clash') && !userAgent.includes('subconverter'))) {
				url = `https://${subconverter}/sub?target=clash&url=${encodeURIComponent(url)}&insert=false&config=${encodeURIComponent(subconfig)}&emoji=true&list=false&tfo=false&scv=true&fdn=false&sort=false&new_name=true`;
				isBase64 = false;
			} else if (userAgent.includes('sing-box') || userAgent.includes('singbox') || (( _url.searchParams.has('singbox') || _url.searchParams.has('sb')) && !userAgent.includes('subconverter'))) {
				url = `https://${subconverter}/sub?target=singbox&url=${encodeURIComponent(url)}&insert=false&config=${encodeURIComponent(subconfig)}&emoji=true&list=false&tfo=false&scv=true&fdn=false&sort=false&new_name=true`;
				isBase64 = false;
			}
		}
		
		try {
			const response = await fetch(url ,{
			headers: {
				'User-Agent': `${UA} CF-Workers-edgetunnel/cmliu`
			}});
			const content = await response.text();
			return revertFakeInfo(content, password, hostName, isBase64);
		} catch (error) {
			console.error('Error fetching content:', error);
			return `Error fetching content: ${error.message}`;
		}

	}
}
