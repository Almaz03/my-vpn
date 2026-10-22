# Семейный VPN-портал

Портал выдаёт отдельный профиль AmneziaWG каждому одобренному устройству. Пользователь запрашивает доступ на сайте, администратор одобряет запрос кнопкой в Telegram, а часовой одноразовый код активируется на `https://vpn.akalmaz.tech`.

В production используется только `PROVISIONER_MODE=amneziawg` и существующий контейнер `amnezia-awg2` на UDP 35473. Root-owned helper создаёт уникальные ключи, адрес и peer, а приложение хранит только непрозрачную ссылку на credential и HMAC токена загрузки. На одно имя разрешено одно активное устройство.

После активации нужно скачать `family-vpn.conf` или отсканировать QR-код и импортировать профиль в [AmneziaVPN](https://amnezia.org/downloads).

## Разработка

```bash
go test -race -count=1 ./...
go vet ./...
go build ./cmd/...
```

Секреты GitHub Actions: `DEPLOY_HOST`, `DEPLOY_PORT`, `DEPLOY_USER`, `DEPLOY_SSH_PRIVATE_KEY`, `DEPLOY_SSH_KNOWN_HOSTS`, `TELEGRAM_BOT_TOKEN`, `TELEGRAM_ADMIN_IDS`.

Документация: [архитектура](docs/architecture.md), [развёртывание](docs/deployment.md), [безопасность](docs/security.md), [эксплуатация](docs/operations.md), [сценарий пользователя](docs/user-flow.md), [ёмкость](docs/capacity.md), [восстановление](docs/disaster-recovery.md).
