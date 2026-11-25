# waf-mikrotik

Автоблокировка подозрительных IP на веб-сервере (nginx/apache) с выгрузкой их
в `address-list` на роутере **MikroTik** по SSH. Дроп трафика делает сам
MikroTik правилом firewall, а срок блокировки снимается нативным `timeout=`
записи address-list.

Форк/переработка [bash-waf-iptables](https://github.com/NickRudoy/bash-waf-iptables):
детект-логика сохранена, блокировка через `ipset`/`iptables` заменена на MikroTik.

```
nginx (анализ логов) ──SSH──▶ MikroTik address-list ──▶ firewall drop
```

## Что детектит

awk-анализатор access-логов ловит сканеры уязвимостей по URL-паттернам:
PHP-backdoor/веб-шеллы (`wso.php`, `shell.php`, `c99.php`, …), попытки SQL-инъекций,
path traversal (`../`, `/etc/passwd`, `/proc/self`), обращения к `.env`/`.git`/`.svn`,
конфигам, `phpMyAdmin`/`adminer`/`cgi-bin`, а также WordPress/Bitrix-специфичные
точки входа (профили `generic`/`wordpress`/`bitrix`).

Легитимные боты (Googlebot, YandexBot, bingbot, мониторинг и т.п.) в белом списке
User-Agent и не блокируются. Поддерживается белый список IP, ротированные и `.gz` логи.

Порог по умолчанию: 3+ «жёстких» попадания с одного IP (для WordPress дополнительно
учитывается брутфорс по «мягким» паттернам).

## Отличия от оригинала

- **Блокировка:** `ipset add` + `iptables -m set --match-set … DROP` → отправка IP
  в `address-list` на MikroTik одним SSH-сеансом (пачкой).
- **Авторазблокировка:** вместо фонового `sleep` + `ipset del` используется нативный
  `timeout=` записи address-list на роутере.
- **Дедупликация:** перед проходом скрипт забирает текущий список с роутера и не шлёт
  повторно уже заблокированные IP.
- **Безопасность:** на роутер уходит только строго валидированный IPv4; в `comment`
  записи НЕ попадают данные из логов (URL/UA) — исключена инъекция команд в консоль
  RouterOS через подделанный запрос.
- **Исправления детекта относительно оригинала:**
  - корректное извлечение URL (в оригинале из-за `\s` внутри `[...]` в gawk путь
    обрезался на первой букве `s`, из-за чего `/shell.php`, `/wso.php`, `/etc/passwd`,
    `settings.php` и т.п. не детектировались);
  - устойчивое извлечение User-Agent для стандартного nginx `combined` и BitrixVM
    (в оригинале UA бралось строго предпоследним полем, и в стандартном nginx вместо
    UA подхватывался Referer — ломался белый список ботов).

## Требования

- веб-сервер: `bash`, `gawk` (нужен для 3-аргументного `match()`), `ssh`
  (опц. `sshpass` — если авторизация по паролю);
- MikroTik RouterOS 6/7 с SSH-доступом.

## Установка

### 1. На веб-сервере

```bash
apt install -y gawk            # обязательно: анализатору нужен gawk, не mawk
mkdir -p /srv/waf-Mikrotik/auto-block
install -m 0755 auto-block-suspicious-mikrotik.sh /usr/local/sbin/
cp mikrotik.conf.example /srv/waf-Mikrotik/auto-block/mikrotik.conf
chmod 600 /srv/waf-Mikrotik/auto-block/mikrotik.conf
```

Отредактируйте `/srv/waf-Mikrotik/auto-block/mikrotik.conf` — минимум `MIKROTIK_HOST`.

Авторизация — по SSH-ключу (рекомендуется) или по паролю (`MIKROTIK_PASSWORD`
в конфиге + `apt install sshpass`).

Ключ SSH. **Важно:** RouterOS 7.x принимает `ed25519`, а RouterOS **6.x — только
RSA**. Для 6.x генерируйте RSA:

```bash
# RouterOS 6.x:
ssh-keygen -t rsa -b 2048 -N '' -f /srv/waf-Mikrotik/auto-block/mikrotik_id_rsa
chmod 600 /srv/waf-Mikrotik/auto-block/mikrotik_id_rsa
cat /srv/waf-Mikrotik/auto-block/mikrotik_id_rsa.pub   # зальём на роутер

# RouterOS 7.x — можно ed25519:
# ssh-keygen -t ed25519 -N '' -f /srv/waf-Mikrotik/auto-block/mikrotik_id_ed25519
```

Путь к выбранному ключу пропишите в `mikrotik.conf` (`MIKROTIK_SSH_KEY`).

### 2. На MikroTik (RouterOS)

Подставьте IP веб-сервера вместо `203.0.113.10`:

```rsc
# Группа и пользователь с ограниченными правами
/user group add name=waf policy=ssh,read,write,test,api
/user add name=waf group=waf address=203.0.113.10/32

# Импорт публичного ключа (файл .pub предварительно залить на роутер)
/user ssh-keys import user=waf public-key-file=mikrotik_id_rsa.pub

# Правило блокировки по списку
/ip firewall filter add chain=input  src-address-list=waf_blacklist action=drop \
    comment="WAF auto-block (input)"
/ip firewall filter add chain=forward src-address-list=waf_blacklist action=drop \
    comment="WAF auto-block (forward)"
```

> Если роутер стоит перед сайтом (NAT/проброс) — отсекает в `forward`; если защищаете
> сам роутер — `input`. Можно оставить оба правила.

### 3. Проверка

```bash
auto-block-suspicious-mikrotik.sh test    # связь с роутером
auto-block-suspicious-mikrotik.sh run     # один проход анализа
auto-block-suspicious-mikrotik.sh list    # что сейчас в списке
auto-block-suspicious-mikrotik.sh flush   # очистить список
```

Лог работы: `/var/log/auto-block.log`.

### 4. Запуск по расписанию (cron)

```cron
# /etc/cron.d/auto-block-mikrotik
*/5 * * * * root /usr/local/sbin/auto-block-suspicious-mikrotik.sh run >/dev/null 2>&1
```

## Настройки

Основные параметры — в `/srv/waf-Mikrotik/auto-block/mikrotik.conf` (см. `mikrotik.conf.example`):
`MIKROTIK_HOST`, `MIKROTIK_PORT`, `MIKROTIK_USER`, `MIKROTIK_SSH_KEY` или
`MIKROTIK_PASSWORD`, `MIKROTIK_ADDRESS_LIST`, `BLOCK_DURATION` (сек).

Пороги детекта, белые списки и паттерны правятся в начале самого скрипта.

### Несколько сайтов (per-site логи)

Если у каждого сайта свой access-лог, например:

```nginx
access_log /var/log/nginx/site1.example.com.access.log;
access_log /var/log/nginx/site2.example.com.access.log;
```

задайте в конфиге glob-маску — анализируются все совпавшие файлы сразу
(`*.error.log` при этом не трогаются):

```ini
ACCESS_LOG_GLOB="/var/log/nginx/*.access.log"
```

Можно указать несколько масок через пробел. Анализ `.gz`-архивов ротации
включается `ANALYZE_GZ="1"` (`GZ_PER_LOG` — сколько архивов на каждый лог);
для частого запуска по cron архивы обычно не нужны. Если `ACCESS_LOG_GLOB`
пуст — используется автоопределение одного лога, как раньше.

## Лицензия

Соответствует лицензии исходного проекта
[bash-waf-iptables](https://github.com/NickRudoy/bash-waf-iptables).
