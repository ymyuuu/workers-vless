# Workers-Vless

轻量级版本，对抗4.0

* 群聊: [HeroCore](https://t.me/HeroCore)
* 频道: [HeroMsg](https://t.me/HeroMsg)

## Update history

* **20250906**：移除`仅ProxyIP`模式，无用
* **20250905**：代理模式配置：

  * `/?mode=direct`（仅直连）
  * `/?mode=s5&s5=user:pass@host:port`（仅SOCKS5）
  * ~~`/?mode=proxy&proxyip=host:port`（仅ProxyIP）~~
  * `/?mode=auto&direct&s5=user:pass@host:port`（直连优先，回退SOCKS5）
  * `/?mode=auto&direct&proxyip=host:port`（直连优先，回退ProxyIP）
  * `/?mode=auto&s5=user:pass@host:port&proxyip=host:port`（SOCKS5优先，回退ProxyIP）
  * `/?mode=auto&proxyip=host:port&s5=user:pass@host:port`（ProxyIP优先，回退SOCKS5）
  * `/?mode=auto&direct&s5=user:pass@host:port&proxyip=host:port`（三者都有：直连→SOCKS5→ProxyIP）
  * `/?mode=auto&s5=user:pass@host:port&proxyip=host:port&direct`（三者都有：SOCKS5→ProxyIP→直连）
  * `/?mode=auto&proxyip=host:port&s5=user:pass@host:port&direct`（三者都有：ProxyIP→SOCKS5→直连）
  * **上面只是示例，可自由搭配参数以满足不同场景需求**
    
* **20250718**：删掉 NAT64，添加SOCKS5：`/user:pass@host:port` 或 `/@host:port`。
* **20250527**：添加 NAT64。
* **20240417**：修复了报错问题（错误代码：1101）。
