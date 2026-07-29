_2026-07-29_

## English

IPv4 route addresses and getsockname() now rewrite to the configured fake: RTM_GETROUTE dumps rewrite gateway/dst/prefsrc on rule-covered interfaces (kernel fib_dump_info), and the new inet_getname/inet6_getname hooks rewrite a covered socket-local address (v6 keeps the real interface identifier under the fake /64)

## Русский

Адреса IPv4-маршрутов и getsockname() теперь подменяются настроенным фейком: выгрузки RTM_GETROUTE переписывают шлюз/dst/prefsrc на покрытых правилами интерфейсах (ядро, fib_dump_info), а новые хуки inet_getname/inet6_getname переписывают покрытый локальный адрес сокета (IPv6 сохраняет реальный идентификатор интерфейса под фейковым /64)
