# Модель безопасности

Статус: threat model и обязательные контрмеры, 22 октября 2026 года.

## Защищаемые активы

- SSH deploy key, Telegram bot token, HMAC pepper и любые VPN private keys;
- возможность создавать и отзывать VPN peers;
- одноразовые приглашения и соответствие «родственник — устройство»;
- доступность портала и корректность RU/direct-маршрутизации;
- целостность SQLite, backups, release artifacts и audit trail;
- действующие пользователи существующей Amnezia.

## Основные противники и риски

| Угроза | Последствие | Контрмеры |
| --- | --- | --- |
| Перебор короткого кода | Несанкционированная выдача VPN | 40 бит CSPRNG, TTL 10 минут, HMAC-хранение, per-code/IP/global limits, задержка, нейтральные ответы |
| Повтор или гонка активации | Два устройства получают один invite | транзакция `BEGIN IMMEDIATE`, state machine, idempotency key, уникальные ограничения |
| Кража БД | Offline-перебор кодов и раскрытие клиентов | keyed HMAC с pepper вне БД, короткий TTL, минимальные labels, зашифрованный backup |
| Подмена Telegram admin | Управление устройствами | точный allowlist числовых ID, deny-by-default, без доверия username, аудит операций |
| SSRF/command injection | Захват сервера/VPN | нет пользовательских URL, строгие схемы, типизированный Unix API, argv без shell, allowlist операций |
| Компрометация web-процесса | Доступ к root/Docker | непривилегированный user, отсутствие Docker socket, отдельный provisioner, systemd sandbox |
| Утечка через логи/кэш | Ключи и коды становятся доступными | редактирование полей, `no-store`, URL без кодов, отключение body/query logging, лимиты journal |
| Supply-chain/CI | Вредоносный релиз | минимальные permissions, actions pinned SHA, checksums, protected environment, immutable artifacts |
| MITM при deploy | Кража ключа/подмена сервера | проверенный `known_hosts`, `StrictHostKeyChecking=yes`, отдельный deploy key, без TOFU в workflow |
| Ошибка routing/DNS | RU-сайт видит зарубежный IP | deny-safe профиль, независимые IP/DNS-тесты, версионированные assets, rollback последней рабочей версии |
| Ошибка provisioner | Потеря существующих peers | backup, canary, идемпотентность, запрет массового удаления, отдельный отзыв по provider_ref |
| DoS | Исчерпание 1 vCPU/SQLite | body/time limits, bounded queues, rate limits, DB timeouts, global activation cap |

## Одноразовые коды

- Генерация только через `crypto/rand`; алфавит Crockford Base32 без неоднозначных символов.
- Публичный запрос доступа допускается один ожидающий на имя и IP, не более трёх
  новых запросов с IP и 30 глобально за час. Проверка статуса ограничена 40
  запросами с IP и 300 глобально в минуту.
- Нормализация допускает регистр и разделитель, но не Unicode-замены. В логах код всегда заменяется `[REDACTED]`.
- В БД хранится `HMAC-SHA-256(pepper, purpose || normalized_code)`. Pepper — минимум 32 случайных байта в root-only credential (`0600`) или systemd credential, не в БД и не в GitHub artifact.
- Поиск идёт по digest, сравнение — constant-time. Одинаковый внешний ответ и близкое время выдаются для неверного, истёкшего, использованного и отозванного кода.
- Максимум 5 ошибок на код; 10 попыток за 10 минут на HMAC IP; глобальный configurable cap. После ошибок — экспоненциальная задержка с ограничением и jitter.
- Создание: максимум 5 приглашений за 10 минут на администратора. Все лимиты сохраняются в SQLite, чтобы рестарт их не сбрасывал.
- Успех атомарно инвалидирует код до вызова выдачи ответа. Ошибка после создания peer обрабатывается idempotent compensation; конфигурация не сохраняется для повторной загрузки.

## Credentials устройств

- Один ключ/UUID на одно устройство; совместное использование запрещено даже при технической возможности.
- Приватный ключ генерируется максимально близко к data plane или однократно в защищённой памяти процесса; не попадает в SQLite, Telegram, audit или backup портала.
- Portal отдаёт конфигурацию только по HTTPS через часовую HMAC-backed subscription с `Cache-Control: no-store`, CSP и без сторонней аналитики; отзыв устройства немедленно инвалидирует ссылку.
- QR/deep link строится в браузере либо в памяти сервера и не записывается на диск. URL не содержит invitation code в query/path.
- Отзыв адресуется opaque device ID/provider ref; bulk wildcard и выбор по пользовательской строке запрещены.

## HTTP и frontend

- TLS 1.2+ через Caddy, HSTS после успешной проверки домена, `X-Content-Type-Options: nosniff`, строгая CSP, `Referrer-Policy: no-referrer`, `Permissions-Policy`.
- Admin endpoints требуют отдельный bearer token; web-admin держит его только в памяти вкладки, не в URL/storage. CORS не включён, CSP запрещает сторонние scripts, revoke требует явного подтверждения UI.
- Публичная активация принимает небольшой JSON body, проверяет `Content-Type`, длины и допустимые символы. Таймауты сервера обязательны.
- Не доверять `X-Forwarded-For` от Интернета; Caddy перезаписывает заголовок, приложение принимает его только с loopback peer.
- `/healthz` сообщает только состояние процесса/БД; детальные метрики слушают loopback или требуют admin auth.

## Telegram

- Long polling предпочтительнее публичного webhook для малого сервиса; offset сохраняется, повторные updates идемпотентны.
- Сначала сравнивается числовой sender/chat ID с allowlist, затем разбирается команда. Неизвестным пользователям не сообщаются версия, IP, устройства или факт существования администратора.
- Бот никогда не отправляет private keys, полные конфигурации или activation code вместе с идентифицирующими данными. Уведомления содержат opaque event ID.
- Токен хранится в `/etc/my-vpn/secrets.env` с `0600` или systemd credential; вывод окружения, shell tracing и debug HTTP запрещены.

## Systemd hardening

Web-сервис запускается отдельным пользователем без shell. Базовые ограничения:

```ini
User=myvpn
Group=myvpn
# Для обычных сервисов yes. Portal использует false только для строго
# разрешённого root-owned reality-helper через sudoers.
NoNewPrivileges=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectSystem=strict
ProtectHome=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
RestrictRealtime=yes
RestrictNamespaces=yes
SystemCallArchitectures=native
ReadWritePaths=/var/lib/my-vpn /run/my-vpn
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
```

`CapabilityBoundingSet` для web-сервиса пуст. Provisioner получает только доказанно необходимые capabilities; если управление возможно через узкий root-owned helper, ему не предоставляется Docker socket. Любое ослабление директив документируется и тестируется.

## Секреты и CI/CD

- В GitHub Actions хранятся только необходимые repository/environment secrets. Production environment защищает deploy; job имеет `contents: read` и не получает лишних permissions.
- SSH private key пишется во временный файл с `umask 077`, не печатается и удаляется в `always()` cleanup. Host key проверяется до аутентификации.
- Runtime `.env`, SQLite, клиентские конфигурации и backups исключаются из Git и artifacts. Secret scanning выполняется на PR и перед release.
- Токены не передаются как CLI arguments. Запрещены `set -x`, дампы окружения и загрузка диагностик без редактирования.
- Actions закрепляются полным commit SHA; зависимости проверяются checksum/signature и обновляются отдельным review.

## Firewall и сеть

До изменения firewall фиксируются текущий SSH-порт и рабочая сессия/rollback. Публично нужны только SSH 22, HTTP 80, HTTPS 443, VLESS Reality TCP 8443 и существующий AmneziaWG UDP 35473. SQLite, Go API и helper не публикуются.

Bootstrap добавляет allow-rules до включения UFW и после включения повторно проверяет SSH workflow, AWG container/tool/listener, Caddy и Xray. Он не сбрасывает Docker/Tailscale tables.

## Backup и восстановление

- Ежедневный online backup SQLite через поддерживаемый backup API/`.backup`, затем `PRAGMA integrity_check` на копии.
- Backup шифруется ключом вне сервера и хранится с ограниченной ретенцией; VPN private keys включаются только в отдельный защищённый backup data plane, если это требуется процедурой восстановления.
- Restore регулярно проверяется в изолированном каталоге. Проверяются схема, invite/device metadata и запуск бинарника без подключения к production provisioner.
- Удаление backup, старых peers или Amnezia запрещено автоматическому rollback/cleanup.

## Обязательные security gates перед production

1. Unit/integration тесты TTL, one-time use, rate limits, constant-time digest path и конкурентной активации.
2. Canary-проверка уникальности credentials и точечного revoke.
3. Независимые тесты RU/direct, foreign/proxy и DNS на поддерживаемых платформах.
4. TLS scan, проверка headers, отсутствие кодов и ключей в access/journal/Actions logs.
5. Проверка atomic deploy, автоматического rollback и восстановления SQLite backup.
6. Измерение idle RSS/CPU и ограниченный нагрузочный тест с запасом минимум 30%.
7. Ручное подтверждение, что существующий `amnezia-awg2` и его пользователи не изменены.
