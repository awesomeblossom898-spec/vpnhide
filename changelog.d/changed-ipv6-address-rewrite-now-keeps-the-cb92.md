_2026-07-29_

## English

IPv6 address rewrite now keeps the real interface identifier (low 64 bits) under the fake /64 on every path — netlink, /proc/net/if_inet6, LSPosed — so the visible global address shares one IID with the link-local address like a stock interface

## Русский

Подмена IPv6-адреса теперь везде — netlink, /proc/net/if_inet6, LSPosed — сохраняет реальный идентификатор интерфейса (младшие 64 бита) под фейковым /64, так что видимый глобальный адрес делит один IID с link-local адресом, как на стоковом интерфейсе
