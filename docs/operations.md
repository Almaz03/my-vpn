# Эксплуатация

Проверки состояния:

```bash
curl -fsS https://vpn.akalmaz.tech/healthz
sudo systemctl status my-vpn caddy
sudo systemctl status xray
sudo xray api statssys --server=127.0.0.1:10085
sudo ss -lntup
```

Команда `/status` в Telegram показывает состояние портала; кнопки бота создают приглашения, показывают активные устройства и выполняют отзыв. Отозванные устройства удаляются из обычного списка.

Production canary: `sudo /usr/local/sbin/my-vpn-release canary`. Он создаёт временный UUID на двух edge, проверяет профиль/egress и отзывает его. Backup: `sudo /usr/local/sbin/my-vpn-release backup`. Не выводите содержимое клиентских профилей, `edges.json` или runtime env.
