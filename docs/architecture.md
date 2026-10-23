# Архитектура

Управляющий узел `vpn.akalmaz.tech` хранит SQLite, обслуживает сайт и Telegram-бота. Go-приложение управляет приглашениями, запросами доступа и подписками INCY. Ссылка `/s/{token}` хранится только как HMAC и немедленно инвалидируется при отзыве устройства.

VPN data plane работает на Xray VLESS Reality. Каждое устройство получает отдельный UUID; выдача и отзыв выполняются через узкий root-owned helper и локальный HandlerService API Xray без перезапуска активных соединений.

## Масштабируемая схема

Управляющий узел `vpn.akalmaz.tech` хранит SQLite, обслуживает сайт и Telegram-бота. Дополнительные VPN-edge узлы не запускают приложение, Telegram polling или отдельную базу: на них работают только Xray Reality, локальная Caddy-маскировка и ограниченный helper синхронизации пользователей.

Каждый edge получает отдельный GitHub Environment (`production-edge-2`, `production-edge-3`, …) с одинаковыми именами секретов `DEPLOY_HOST`, `DEPLOY_PORT`, `DEPLOY_USER`, `DEPLOY_SSH_PRIVATE_KEY`, `DEPLOY_SSH_KNOWN_HOSTS`. Workflow `Bootstrap VPN edge` можно повторно запускать без ротации уже созданных Reality-ключей.

До переключения клиентов новый edge должен пройти bootstrap, HTTPS/443 smoke test и синхронизацию активных UUID. Удалять Xray с управляющего узла разрешается только после успешного клиентского canary через новый основной edge.
