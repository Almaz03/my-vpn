# Развёртывание

## Управляющий узел

1. Запустить workflow `Bootstrap production host` с подтверждением `BOOTSTRAP`.
2. Установить repository variables `ENABLE_PRODUCTION_DEPLOY=true` и `PROVISIONER_MODE=vless-reality`.
3. Запустить `Build and deploy production` или отправить commit в `main`.

Bootstrap ставит локальный литовский edge и записывает root-only `edges.json`, где Финляндия подключена по SSH с закреплённым host key. Обычный deploy создаёт зашифрованный backup, атомарно меняет release и проверяет портал, приглашение, двухузловую активацию, VLESS Reality egress и отзыв устройства. Публичны только SSH и TCP 80/443; приложение и Xray HandlerService слушают loopback.

## Дополнительный VPN-edge

1. Создать DNS-запись отдельного имени, например `tcp2.vpn.akalmaz.tech`, на IPv4 нового сервера.
2. Создать GitHub Environment `production-edge-2`; общий repository secret `DEPLOY_SSH_PRIVATE_KEY` используется повторно.
3. Получить SHA256 fingerprint ED25519 host key через консоль сервера.
4. Запустить workflow `Bootstrap VPN edge`, указав environment, IP, SSH-порт, пользователя, fingerprint, DNS-имя и подтверждение `BOOTSTRAP-EDGE`.
5. Запустить `Bootstrap production host`: он проверит fingerprint, установит `edges.json` и выполнит временный provision/config/revoke сразу на LT и FI.
6. Запустить основной deploy и убедиться, что application canary получил два outbound (`lt-reality`, `fi-reality`) и вышел в Интернет через balancer.
7. Только после canary удалить старые пользовательские профили и выдать новый профиль OneXray.

На edge нет сайта, Telegram-бота и пользовательской базы. Команды `edge-user-helper add DEVICE_ID UUID`, `remove DEVICE_ID` и `metadata` доступны только выделенному deploy-пользователю через фиксированное правило sudo; публичного управляющего API нет.
