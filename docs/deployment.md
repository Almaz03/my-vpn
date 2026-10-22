# Развёртывание

1. Запустить workflow `Bootstrap production host` с подтверждением `BOOTSTRAP`.
2. Установить repository variable `ENABLE_PRODUCTION_DEPLOY=true`. Production backend зафиксирован в workflow как `amneziawg`.
3. Запустить `Build and deploy production` или отправить commit в `main`.

Bootstrap проверяет работающий `amnezia-awg2` до изменений, устанавливает Caddy, systemd unit, узкие root helpers, firewall и backup timer. Деплой создаёт зашифрованный backup, атомарно меняет release и запускает canary: приглашение, активацию, проверку AmneziaWG-конфига, отзыв и HTTP 404 для отозванной ссылки.

Публичные порты: SSH, TCP 80/443 и UDP 35473. Приложение слушает только `127.0.0.1:8080`.
