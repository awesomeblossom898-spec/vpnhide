_2026-07-28_

## English

Address rewrite rules: a prefix rule can now show a configured fake address instead of dropping matches — IPv6 fakes keep the carrier prefix (kernel rewrites netlink, /proc and route destinations in place), and new rewrite-only ipv4Rules blind the cellular CGNAT address inside 100.64.0.0/10 (prefix4 on the wire, fail-open on old backends)

## Русский

Правила подмены адресов: префиксное правило теперь может показывать настроенный поддельный адрес вместо отбрасывания совпадений — IPv6-подмена сохраняет префикс оператора (ядро переписывает netlink, /proc и адреса назначения маршрутов на месте), а новые rewrite-only ipv4Rules скрывают CGNAT-адрес сотовой сети внутри 100.64.0.0/10 (prefix4 в протоколе, fail-open на старых бэкендах)
