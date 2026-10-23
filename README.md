# Family VPN

Семейный VPN с одобрением через Telegram и установкой профиля в один клик.
Пользователь запрашивает доступ на `https://vpn.akalmaz.tech`, администратор
нажимает «Одобрить» в боте, а одноразовый код создаёт отдельный профиль
[Hiddify](https://hiddify.com/app/).

Профиль содержит два VLESS Vision + Reality edge:

- `🇱🇹 Литва 🚀` — также размещает сайт, бот и SQLite control plane;
- `🇫🇮 Финляндия 🚀` — изолированный VPN data plane.

Xray автоматически проверяет оба маршрута и выбирает доступный с меньшей
задержкой. Российские домены и локальные сети идут напрямую с устройства,
остальной трафик — через VPN. Один человек может иметь одно активное
устройство; revoke удаляет один UUID сразу с обоих edge и инвалидирует
subscription-token.

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
