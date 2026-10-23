# Развёртывание

## Управляющий узел

1. Запустить workflow `Bootstrap production host` с подтверждением `BOOTSTRAP`.
2. Установить repository variables `ENABLE_PRODUCTION_DEPLOY=true` и `PROVISIONER_MODE=vless-reality`.
3. Запустить `Build and deploy production` или отправить commit в `main`.

Обычный deploy создаёт зашифрованный backup, атомарно меняет release и проверяет портал, приглашение, активацию, VLESS Reality egress и отзыв устройства. Публичны только SSH и TCP 80/443; приложение и Xray HandlerService слушают loopback.

## Дополнительный VPN-edge

1. Создать DNS-запись отдельного имени, например `tcp2.vpn.akalmaz.tech`, на IPv4 нового сервера.
2. Создать GitHub Environment `production-edge-2` и заполнить в нём стандартные `DEPLOY_*` secrets.
3. Запустить workflow `Bootstrap VPN edge`, указав environment, DNS-имя и подтверждение `BOOTSTRAP-EDGE`.
4. После smoke test подключить edge к синхронизации устройств и выдать клиентам обновлённую подписку.
5. Только после реального клиентского теста отключать data plane на прежнем узле.

На edge нет сайта, Telegram-бота и пользовательской базы. Команды `edge-user-helper add DEVICE_ID UUID`, `remove DEVICE_ID` и `metadata` доступны только выделенному deploy-пользователю через фиксированное правило sudo; публичного управляющего API нет.
