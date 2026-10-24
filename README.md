# Family VPN

Семейный VPN с одобрением через Telegram и установкой профиля в один клик.
Пользователь запрашивает доступ на `https://vpn.akalmaz.tech`, администратор
нажимает «Одобрить» в боте, а одноразовый код создаёт отдельный профиль
[Clash Mi](https://apps.apple.com/ru/app/clash-mi/id6744321968). Один клиент
используется на iOS, Android, macOS, Windows и Linux и получает полный
Mihomo-профиль через обновляемую HTTPS-подписку.

Профиль содержит два VLESS Vision + Reality edge:

- `🇱🇹 Литва 🚀` — также размещает сайт, бот и SQLite control plane;
- `🇫🇮 Финляндия 🚀` — изолированный VPN data plane.

Mihomo автоматически проверяет оба маршрута и выбирает доступный с меньшей
задержкой. Российские домены и локальные сети идут напрямую с устройства,
остальной трафик — через VPN. Один человек может иметь одно активное
устройство; revoke удаляет один UUID сразу с обоих edge и инвалидирует
subscription-token.

Telegram показывает последнюю существенную активность, выбранный edge и
агрегированный трафик устройства и каждого узла за 24 часа/месяц. История
сайтов при этом не собирается.

## Разработка

```bash
go test -race -count=1 ./...
go vet ./...
go build ./cmd/...
bash -n scripts/*.sh
```

Секреты GitHub Actions: `DEPLOY_HOST`, `DEPLOY_PORT`, `DEPLOY_USER`,
`DEPLOY_SSH_PRIVATE_KEY`, `DEPLOY_SSH_KNOWN_HOSTS`, `TELEGRAM_BOT_TOKEN`,
`TELEGRAM_ADMIN_IDS`.

План полной перестройки находится в [BACKLOG.md](BACKLOG.md), готовый prompt
для Oh My Codex — в [docs/oh-my-codex-prompt.md](docs/oh-my-codex-prompt.md).
Остальная документация: [архитектура](docs/architecture.md),
[развёртывание](docs/deployment.md), [безопасность](docs/security.md),
[эксплуатация](docs/operations.md), [сценарий пользователя](docs/user-flow.md),
[ёмкость](docs/capacity.md), [восстановление](docs/disaster-recovery.md).
