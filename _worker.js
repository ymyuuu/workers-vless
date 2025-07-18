import {
	connect
} from 'cloudflare:sockets';

export default {
	async fetch(req, env) {
		const UUID = env.UUID || '4ba0eec8-25e1-4ab3-b188-fd8a70b53984';

		if (req.headers.get('Upgrade')?.toLowerCase() === 'websocket') {
			const [client, ws] = Object.values(new WebSocketPair());
			ws.accept();

			// 解析SOCKS5: /user:pass@host:port
			const path = new URL(req.url).pathname.slice(1);
			const socks5 = path.includes('@') ? (() => {
				const [cred, server] = path.split('@');
				const [user, pass] = cred.split(':');
				const [host, port = 1080] = server.split(':');
				return {
					user,
					pass,
					host,
					port: +port
				};
			})() : null;

			let remote = null,
				udpWriter = null,
				isDNS = false;

			// 创建处理流
			new ReadableStream({
				start(ctrl) {
					ws.addEventListener('message', e => ctrl.enqueue(e.data));
					ws.addEventListener('close', () => {
						remote?.close();
						ctrl.close();
					});
					ws.addEventListener('error', () => {
						remote?.close();
						ctrl.error();
					});

					// 0-RTT数据
					const early = req.headers.get('sec-websocket-protocol');
					if (early) {
						try {
							ctrl.enqueue(Uint8Array.from(atob(early.replace(/-/g, '+').replace(/_/g, '/')),
								c => c.charCodeAt(0)).buffer);
						} catch {}
					}
				}
			}).pipeTo(new WritableStream({
				async write(data) {
					// DNS UDP转发
					if (isDNS) return udpWriter?.write(data);

					// TCP数据转发
					if (remote) {
						const w = remote.writable.getWriter();
						await w.write(data);
						w.releaseLock();
						return;
					}

					// 协议验证
					if (data.byteLength < 24) return;

					// UUID验证 - 直接比较字节
					const uuidBytes = new Uint8Array(data.slice(1, 17));
					const expectedUUID = UUID.replace(/-/g, '');
					for (let i = 0; i < 16; i++) {
						if (uuidBytes[i] !== parseInt(expectedUUID.substr(i * 2, 2), 16)) return;
					}

					// 解析VLess头
					const view = new DataView(data);
					const optLen = view.getUint8(17);
					const cmd = view.getUint8(18 + optLen);
					if (cmd !== 1 && cmd !== 2) return;

					let pos = 19 + optLen;
					const port = view.getUint16(pos);
					const type = view.getUint8(pos + 2);
					pos += 3;

					// 解析地址
					let addr = '';
					if (type === 1) {
						addr =
							`${view.getUint8(pos)}.${view.getUint8(pos + 1)}.${view.getUint8(pos + 2)}.${view.getUint8(pos + 3)}`;
						pos += 4;
					} else if (type === 2) {
						const len = view.getUint8(pos++);
						addr = new TextDecoder().decode(data.slice(pos, pos + len));
						pos += len;
					} else if (type === 3) {
						const ipv6 = [];
						for (let i = 0; i < 8; i++, pos += 2) {
							ipv6.push(view.getUint16(pos).toString(16));
						}
						addr = ipv6.join(':');
					} else return;

					const header = new Uint8Array([data[0], 0]);
					const payload = data.slice(pos);

					// UDP DNS处理
					if (cmd === 2) {
						if (port !== 53) return;
						isDNS = true;

						let sent = false;
						const {
							readable,
							writable
						} = new TransformStream({
							transform(chunk, ctrl) {
								for (let i = 0; i < chunk.byteLength;) {
									const len = new DataView(chunk.slice(i, i + 2))
										.getUint16(0);
									ctrl.enqueue(chunk.slice(i + 2, i + 2 + len));
									i += 2 + len;
								}
							}
						});

						// DNS查询
						readable.pipeTo(new WritableStream({
							async write(query) {
								try {
									const resp = await fetch(
										'https://1.1.1.1/dns-query', {
											method: 'POST',
											headers: {
												'content-type': 'application/dns-message'
											},
											body: query
										});

									if (ws.readyState === 1) {
										const result = new Uint8Array(await resp
											.arrayBuffer());
										ws.send(new Uint8Array([
											...(sent ? [] : header),
											result.length >> 8, result
											.length & 0xff,
											...result
										]));
										sent = true;
									}
								} catch {}
							}
						}));

						udpWriter = writable.getWriter();
						return udpWriter.write(payload);
					}

					// TCP连接
					let sock;
					try {
						sock = connect({
							hostname: addr,
							port
						});
						await sock.opened;
					} catch (e) {
						if (!socks5) return;

						// SOCKS5回退
						sock = connect({
							hostname: socks5.host,
							port: socks5.port
						});
						await sock.opened;
						const w = sock.writable.getWriter();
						const r = sock.readable.getReader();

						try {
							// SOCKS5握手
							await w.write(new Uint8Array([5, 2, 0, 2]));
							const auth = (await r.read()).value;

							// 用户认证
							if (auth[1] === 2 && socks5.user) {
								const user = new TextEncoder().encode(socks5.user);
								const pass = new TextEncoder().encode(socks5.pass);
								await w.write(new Uint8Array([1, user.length, ...user, pass.length,
									...pass
								]));
								await r.read();
							}

							// 连接请求
							const domain = new TextEncoder().encode(addr);
							await w.write(new Uint8Array([5, 1, 0, 3, domain.length, ...domain,
								port >> 8, port & 0xff
							]));
							await r.read();

							w.releaseLock();
							r.releaseLock();
						} catch {
							sock.close();
							return;
						}
					}

					remote = sock;
					const w = sock.writable.getWriter();
					await w.write(payload);
					w.releaseLock();

					// 数据转发
					let sent = false;
					sock.readable.pipeTo(new WritableStream({
						write(chunk) {
							if (ws.readyState === 1) {
								ws.send(sent ? chunk : new Uint8Array([...header, ...
									new Uint8Array(chunk)
								]));
								sent = true;
							}
						},
						close: () => ws.readyState === 1 && ws.close(),
						abort: () => ws.readyState === 1 && ws.close()
					})).catch(() => {});
				}
			})).catch(() => {});

			return new Response(null, {
				status: 101,
				webSocket: client
			});
		}

		// HTTP反向代理
		const url = new URL(req.url);
		url.hostname = 'example.com';
		return fetch(new Request(url, req));
	}
};
