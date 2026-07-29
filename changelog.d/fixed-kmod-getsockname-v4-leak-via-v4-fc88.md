_2026-07-29_

## English

kmod: getsockname v4 leak via v4-mapped AF_INET6 sockets — Android sockets are PF_INET6 with V6ONLY off, so a v4 connect returns ::ffff:a.b.c.d from inet6_getname and the v4 branch never ran; rewrite the mapped tail with the prefix4 rules

## Русский

kmod: утечка v4 в getsockname через v4-mapped AF_INET6 сокеты — сокеты Android это PF_INET6 без V6ONLY, v4-подключение возвращает ::ffff:a.b.c.d из inet6_getname и ветка v4 не работала; перезаписываем mapped-хвост по правилам prefix4
