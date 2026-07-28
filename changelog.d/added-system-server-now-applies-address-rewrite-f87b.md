_2026-07-28_

## English

system_server now applies address rewrite rules on the framework path too: LinkProperties handed to apps (sync results, push callbacks, parcel marshalling) show the same fake the native layer shows, gated globally so every app sees one consistent answer

## Русский

system_server теперь тоже применяет правила подмены адресов на уровне фреймворка: LinkProperties, выдаваемые приложениям (синхронные результаты, push-колбэки, маршаллинг parcel), показывают ту же подмену, что и нативный слой, с глобальным гейтом — каждое приложение видит один согласованный ответ
