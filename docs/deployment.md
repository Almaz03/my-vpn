# Развёртывание

Документ описывает целевой безопасный процесс. Он не является подтверждением выполненного production-деплоя.

## Исходное состояние

На сервере работает `amnezia-awg2` с UDP-портом `35473`. Его конфигурация, контейнер и правила сети считаются чужим работающим контуром: новый портал разворачивается параллельно и не изменяет их автоматически. TCP 80/443 во время аудита были свободны, но это необходимо перепроверить непосредственно перед установкой Caddy.

## Предварительные условия

- зелёные CI-проверки конкретного commit SHA;
- versioned Linux/amd64 artifact и SHA-256 checksum;
- проверенный SSH host key в `DEPLOY_SSH_KNOWN_HOSTS`;
- отдельные значения GitHub Actions Secrets, без вывода в лог;
- DNS `vpn.akalmaz.tech` указывает на сервер;
- резервная копия SQLite, server-side конфигурации и метаданных текущего релиза;
- подтверждено, что 80/443 свободны и firewall сохраняет текущий SSH-порт и UDP 35473.

Первичный bootstrap выполняется один раз через существующий `root` secret. Он
устанавливает `my-vpn-deploy` только с public key текущего deploy-ключа и даёт ему
sudo исключительно на root-owned `/usr/local/sbin/my-vpn-release`. Обычные deploy
и backup больше не используют root SSH. Загруженный release tar проходит whitelist
путей и типов до распаковки root-процессом.

## Целевая раскладка

Рекомендуемая схема:

```text
/opt/my-vpn/
  releases/<version>/
  current -> releases/<version>
/var/lib/my-vpn/
  my-vpn.db
/var/backups/my-vpn/
  <timestamp>.age
/etc/my-vpn/
  my-vpn.env
/etc/xray/config.json
```

Приватные файлы имеют минимальные права; `/etc/my-vpn/my-vpn.env` — `0640`
`root:my-vpn`, чтобы непривилегированный сервис мог прочитать его. VPN credentials
генерируются на сервере и не входят в GitHub artifacts. Сборка и установка
выполняются скриптами `scripts/build-release.sh` и `scripts/install-release.sh`;
явный откат — `scripts/rollback.sh`.

## Atomic deployment

1. Загрузить artifact во временный каталог нового versioned release.
2. Проверить checksum и тип бинарника.
3. Выполнить совместимую миграцию БД с предварительным backup.
4. Провести offline/self-check нового бинарника.
5. Атомарно переключить symlink `current`.
6. Перезапустить только сервис портала; Xray перечитывается лишь при изменении peers; Amnezia не трогать.
7. Проверить `/healthz`, внешний HTTPS/TCP 8443, Reality egress и полный activation/revoke canary.
8. При любом сбое вернуть предыдущий symlink, восстановить совместимую БД при необходимости и перезапустить предыдущую версию.

Два деплоя не должны выполняться одновременно. В GitHub Actions нужен `concurrency` для production environment.

## systemd и reverse proxy

`my-vpn.service` должен слушать loopback (например, `127.0.0.1:8080`). Caddy завершает TLS на 80/443 и проксирует только к loopback. Проект устанавливает отдельный snippet `/etc/caddy/conf.d/my-vpn.caddy`, но не должен самовольно переписывать основной Caddyfile. В unit рекомендуется включить:

- отдельного непривилегированного пользователя;
- `PrivateTmp=true`, `ProtectSystem=strict`; для портала `NoNewPrivileges=false`
  является осознанным исключением, поскольку он вызывает только root-owned
  `reality-helper` по узкому sudoers-правилу (Xray и backup сохраняют
  `NoNewPrivileges=true`);
- запись только в каталог данных и `/etc/xray` для атомарной работы строго
  ограниченного Reality helper;
- ограничение capabilities и системных вызовов после проверки совместимости;
- restart policy с задержкой и разумные лимиты ресурсов.

Caddyfile и unit-файлы проверяются штатными валидаторами. One-time bootstrap
включает UFW только после правил для текущего SSH, 80/443 TCP, Reality 8443 TCP,
AmneziaWG 35473 UDP и Tailscale, затем повторно проверяет AWG container/listener.

Запуск: сначала вручную `Bootstrap production host` с подтверждением `BOOTSTRAP`,
затем `Build and deploy production` с `deploy=true`. Автодеплой push включается
только variables `ENABLE_PRODUCTION_DEPLOY=true` и `PROVISIONER_MODE=vless-reality`.

## Проверки после развёртывания

- TLS-цепочка и hostname;
- `/healthz` без секретных данных;
- создание, применение и повторное применение тестового одноразового кода;
- независимые credentials двух устройств и отзыв одного из них;
- импорт тестового профиля в INCY;
- RU/direct, foreign/proxy и split-DNS на реальном клиенте;
- рестарт systemd и сохранность состояния;
- принудительно неуспешный canary и автоматический rollback;
- отсутствие токенов/ключей в логах и artifacts.

До завершения этих проверок нельзя отключать существующую Amnezia или объявлять портал готовым.
