// VLESS代理服务器 - 支持IPv4地址NAT64回落和负载均衡
import {
	connect
} from 'cloudflare:sockets';

export default {
	async fetch(req, env, ctx) {
		try {
			// 环境变量配置
			const UUID = env.UUID || '4ba0eec8-25e1-4ab3-b188-fd8a70b53984';
			const NAT64P = env.NAT64P || '2602:fc59:b0:64::,2001:67c:2960:6464::';

			// WebSocket代理处理
			if (req.headers.get('Upgrade')?.toLowerCase() === 'websocket') {
				const [client, ws] = Object.values(new WebSocketPair());
				ws.accept();

				const early = req.headers.get('sec-websocket-protocol') || '';
				let remote = null,
					udp = null,
					dns = false;

				// WebSocket数据流处理
				new ReadableStream({
					start(ctrl) {
						ws.addEventListener('message', e => ctrl.enqueue(e.data));
						ws.addEventListener('close', () => ctrl.close());
						ws.addEventListener('error', err => ctrl.error(err));

						// 处理早期数据
						if (early) {
							try {
								const decoded = atob(early.replace(/-/g, '+').replace(/_/g, '/'));
								ctrl.enqueue(Uint8Array.from(decoded, c => c.charCodeAt(0)).buffer);
							} catch (e) {}
						}
					}
				}).pipeTo(new WritableStream({
					async write(data) {
						// DNS UDP数据转发
						if (dns && udp) return udp(data);

						// TCP数据转发
						if (remote) {
							const w = remote.writable.getWriter();
							await w.write(data);
							w.releaseLock();
							return;
						}

						// VLESS协议头解析
						if (data.byteLength < 24) throw new Error('协议头长度不足');

						const view = new DataView(data);
						const ver = new Uint8Array(data.slice(0, 1));

						// UUID验证
						const bytes = new Uint8Array(data.slice(1, 17));
						const hex = Array.from(bytes, b => b.toString(16).padStart(2, '0')).join(
							'');
						const id =
							`${hex.slice(0,8)}-${hex.slice(8,12)}-${hex.slice(12,16)}-${hex.slice(16,20)}-${hex.slice(20)}`;
						if (id !== UUID) throw new Error('UUID验证失败');

						const optLen = view.getUint8(17);
						const cmd = view.getUint8(18 + optLen);
						const isUdp = cmd === 2;
						if (cmd !== 1 && cmd !== 2) throw new Error('不支持的命令类型');

						let pos = 19 + optLen;
						const port = view.getUint16(pos);
						pos += 2;

						// 地址解析
						const type = view.getUint8(pos++);
						let addr = '';

						if (type === 1) {
							// IPv4
							addr = Array.from(new Uint8Array(data.slice(pos, pos + 4))).join('.');
							pos += 4;
						} else if (type === 2) {
							// 域名
							const len = view.getUint8(pos++);
							addr = new TextDecoder().decode(data.slice(pos, pos + len));
							pos += len;
						} else if (type === 3) {
							// IPv6
							const parts = [];
							for (let i = 0; i < 8; i++) {
								parts.push(view.getUint16(pos).toString(16).padStart(4, '0'));
								pos += 2;
							}
							addr = parts.join(':').replace(/(^|:)0+(\w)/g, '$1$2');
						} else {
							throw new Error('不支持的地址类型');
						}

						const header = new Uint8Array([ver[0], 0]);
						const payload = data.slice(pos);

						// UDP DNS处理
						if (isUdp) {
							if (port !== 53) throw new Error('UDP仅支持DNS');
							dns = true;

							let sent = false;
							const t = new TransformStream({
								transform(chunk, ctrl) {
									for (let i = 0; i < chunk.byteLength;) {
										const len = new DataView(chunk.slice(i, i + 2))
											.getUint16(0);
										ctrl.enqueue(new Uint8Array(chunk.slice(i + 2, i +
											2 + len)));
										i += 2 + len;
									}
								}
							});

							t.readable.pipeTo(new WritableStream({
								async write(query) {
									const resp = await fetch(
										'https://1.1.1.1/dns-query', {
											method: 'POST',
											headers: {
												'content-type': 'application/dns-message'
											},
											body: query
										});

									const result = await resp.arrayBuffer();
									const len = result.byteLength;
									const lenBuf = new Uint8Array([len >> 8, len &
										0xff
									]);

									if (ws.readyState === 1) {
										const buf = sent ?
											await new Blob([lenBuf, result])
											.arrayBuffer() :
											await new Blob([header, lenBuf, result])
											.arrayBuffer();
										ws.send(buf);
										sent = true;
									}
								}
							}));

							udp = chunk => t.writable.getWriter().write(chunk);
							return udp(payload);
						}

						// TCP连接处理
						const conn = async (host, p) => {
							const sock = await connect({
								hostname: host,
								port: p
							});
							remote = sock;
							const w = sock.writable.getWriter();
							await w.write(payload);
							w.releaseLock();
							return sock;
						};

						// NAT64地址转换
						const nat64 = async (address) => {
							let ipv4;

							if (/^(\d{1,3}\.){3}\d{1,3}$/.test(address)) {
								ipv4 = address;
							} else {
								const resp = await fetch(
									`https://1.1.1.1/dns-query?name=${address}&type=A`, {
										headers: {
											'Accept': 'application/dns-json'
										}
									});
								const json = await resp.json();
								const record = json.Answer?.find(r => r.type === 1);
								if (!record) throw new Error('DNS解析失败');
								ipv4 = record.data;
							}

							const parts = ipv4.split('.');
							const hex = parts.map(p => parseInt(p).toString(16).padStart(2,
								'0'));
							const ipv4Hex = `${hex[0]}${hex[1]}:${hex[2]}${hex[3]}`;

							const prefixes = NAT64P.split(',').map(p => p.trim()).filter(
								p => p);
							const prefix = prefixes[Math.floor(Math.random() * prefixes
								.length)];

							return `[${prefix}${ipv4Hex}]`;
						};

						// 数据转发管道
						const pipe = (sock, retry = null) => {
							let sent = false,
								hasData = false;

							sock.readable.pipeTo(new WritableStream({
								write(chunk) {
									hasData = true;
									if (ws.readyState === 1) {
										if (!sent) {
											const buf = new Uint8Array(header
												.length + chunk.byteLength);
											buf.set(header, 0);
											buf.set(new Uint8Array(chunk), header
												.length);
											ws.send(buf.buffer);
											sent = true;
										} else {
											ws.send(chunk);
										}
									}
								},
								close() {
									if (!hasData && retry) return retry();
									if (ws.readyState === 1) ws.close(1000);
								}
							})).catch(() => {
								try {
									sock?.close();
								} catch (e) {}
								if (ws.readyState === 1) ws.close(1011);
							});
						};

						// 连接尝试 - 直连失败后NAT64回退
						try {
							const sock = await conn(addr, port);
							pipe(sock, async () => {
								try {
									const ipv6 = await nat64(addr);
									const retry = await conn(ipv6, port);
									pipe(retry);
								} catch (e) {
									ws.close(1011);
								}
							});
						} catch (e) {
							try {
								const ipv6 = await nat64(addr);
								const retrySock = await conn(ipv6, port);
								pipe(retrySock);
							} catch (natErr) {
								ws.close(1011);
							}
						}
					},
					close() {
						try {
							remote?.close();
						} catch (e) {}
					}
				})).catch(() => {
					try {
						remote?.close();
					} catch (e) {}
					ws.close(1011);
				});

				return new Response(null, {
					status: 101,
					webSocket: client
				});
			}

			// HTTP反向代理
			const url = new URL(req.url);
			url.hostname = 'example.com';

			return fetch(new Request(url.toString(), {
				method: req.method,
				headers: req.headers,
				body: req.body
			}));

		} catch (err) {
			return new Response(`服务器错误: ${err.message}`, {
				status: 500
			});
		}
	}
};
