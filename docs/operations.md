# Эксплуатация

Проверки состояния:

```bash
curl -fsS https://vpn.akalmaz.tech/healthz
sudo systemctl status my-vpn caddy
sudo docker exec amnezia-awg2 awg show awg0
sudo ss -lntup
```

Команда `/status` в Telegram показывает состояние портала; кнопки бота создают приглашения, показывают активные устройства и выполняют отзыв. Отозванные устройства удаляются из обычного списка.

Production canary: `sudo /usr/local/sbin/my-vpn-release canary`. Backup: `sudo /usr/local/sbin/my-vpn-release backup`. Не выводите содержимое клиентских профилей или runtime env.
