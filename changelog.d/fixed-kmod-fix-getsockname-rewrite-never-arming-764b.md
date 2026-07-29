_2026-07-29_

## English

kmod: fix getsockname rewrite never arming — inet_getname/inet6_getname take 3 args on 4.17+ (peer is x2, not x3), so the getpeername gate read garbage and the exit handler returned early on every call

## Русский

kmod: починен rewrite getsockname — inet_getname/inet6_getname принимают 3 аргумента начиная с 4.17 (peer в x2, не x3), проверка getpeername читала мусор и обработчик всегда завершался рано
