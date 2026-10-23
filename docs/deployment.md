# Развёртывание

## Управляющий узел

1. Запустить workflow `Bootstrap production host` с подтверждением `BOOTSTRAP`.
2. Установить repository variables `ENABLE_PRODUCTION_DEPLOY=true` и `PROVISIONER_MODE=vless-reality`.
3. Запустить `Build and deploy production` или отправить commit в `main`.

Обычный deploy создаёт зашифрованный backup, атомарно меняет release и проверяет портал, приглашение, активацию, VLESS Reality egress и отзыв устройства. Публичны только SSH и TCP 80/443; приложение и Xray HandlerService слушают loopback.

## Дополнительный VPN-edge

1. Создать DNS-запись отдельного имени, например `tcp2.vpn.akalmaz.tech`, на IPv4 нового сервера.
2. Создать GitHub Environment `production-edge-2`; общий repository secret `DEPLOY_SSH_PRIVATE_KEY` используется повторно.
3. Получить SHA256 fingerprint ED25519 host key через консоль сервера.
4. Запустить workflow `Bootstrap VPN edge`, указав environment, IP, SSH-порт, пользователя, fingerprint, DNS-имя и подтверждение `BOOTSTRAP-EDGE`.
5. После smoke test подключить edge к синхронизации устройств и выдать клиентам обновлённую подписку.
6. Только после реального клиентского теста отключать data plane на прежнем узле.

На edge нет сайта, Telegram-бота и пользовательской базы. Команды `edge-user-helper add DEVICE_ID UUID`, `remove DEVICE_ID` и `metadata` доступны только выделенному deploy-пользователю через фиксированное правило sudo; публичного управляющего API нет.
