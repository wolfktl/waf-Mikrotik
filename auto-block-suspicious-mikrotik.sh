#!/bin/bash
###############################################################################
# Автоблокировка подозрительных IP через MikroTik address-list
#
# Анализирует логи веб-сервера (nginx/apache) и отправляет IP, которые ищут
# уязвимости, в address-list на роутере MikroTik по SSH. Сам дроп трафика
# делает MikroTik правилом firewall по этому списку. Срок блокировки задаётся
# нативным timeout= у записи address-list (авторазблокировка на стороне роутера).
#
# НЕ блокирует легитимных ботов (поисковики, мониторинг и т.п.).
#
# Основано на bash-waf-iptables (NickRudoy), детект-логика сохранена.
# Отличие: вместо ipset/iptables — выгрузка на MikroTik.
###############################################################################

# PATH для cron
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

VERSION="3.0.0-mikrotik"

# ----------------------------- Пути и состояние ------------------------------
LOG_FILE="/var/log/auto-block.log"
STATE_DIR="/var/lib/auto-block"
COMPONENTS_DIR="$STATE_DIR/components"
LEGACY_STATE_FILE="$STATE_DIR/enabled"
SUSPICIOUS_STATE_FILE="$COMPONENTS_DIR/suspicious.enabled"
WHITELIST_FILE="$STATE_DIR/whitelist.txt"
PROFILE_FILE="$STATE_DIR/profile"
ACCESS_LOG_FILE="$STATE_DIR/access_log"

# =============================================================================
#                      НАСТРОЙКИ ПОДКЛЮЧЕНИЯ К MIKROTIK
# =============================================================================
# Значения по умолчанию. Их можно переопределить в файле:
#   /var/lib/auto-block/mikrotik.conf
# (обычный shell-синтаксис: KEY="value"), чтобы не хранить секреты в скрипте.

MIKROTIK_HOST=""                                       # IP/hostname роутера (обязательно)
MIKROTIK_PORT="22"                                     # SSH-порт MikroTik
MIKROTIK_USER="waf"                                    # Пользователь на MikroTik
MIKROTIK_SSH_KEY="/var/lib/auto-block/mikrotik_id_ed25519"  # Приватный ключ (приоритетный способ)
MIKROTIK_PASSWORD=""                                   # Либо пароль (требует sshpass). Если задан — ключ игнорируется
MIKROTIK_ADDRESS_LIST="waf_blacklist"                  # Имя address-list на роутере
SSH_CONNECT_TIMEOUT=10                                 # Таймаут SSH-соединения, сек

# Длительность блокировки (сек). Пишется в timeout= записи address-list.
BLOCK_DURATION=7200                                    # 2 часа

# --- Логи nginx ---
# Если у каждого сайта свой access-лог (например /var/log/nginx/site.access.log),
# задайте glob-маску — анализируются ВСЕ совпавшие файлы. Можно несколько масок
# через пробел. Пустое значение = старое поведение (один автоопределяемый лог).
# Пример: ACCESS_LOG_GLOB="/var/log/nginx/*.access.log"
ACCESS_LOG_GLOB=""
# Анализировать ли свежие .gz-архивы ротации (0/1) и сколько архивов на каждый лог.
# Для cron-режима (частый запуск) архивы обычно не нужны — хватает текущих логов.
ANALYZE_GZ=0
GZ_PER_LOG=1

# Подхватываем пользовательский конфиг, если он есть
MIKROTIK_CONF="$STATE_DIR/mikrotik.conf"
if [ -f "$MIKROTIK_CONF" ]; then
    # shellcheck disable=SC1090
    source "$MIKROTIK_CONF"
fi

# =============================================================================
#                           ДЕТЕКТ: лог-файл и профиль
# =============================================================================
# Определение лог-файла
if [ -n "$ACCESS_LOG_GLOB" ]; then
    # Per-site логи: конкретный ACCESS_LOG не важен, список даёт get_log_files().
    # Для сообщений/проверок используем первый совпавший файл.
    LOG_FORMAT="nginx"
    ACCESS_LOG=""
    for _g in $ACCESS_LOG_GLOB; do
        for _f in $_g; do
            if [ -f "$_f" ]; then ACCESS_LOG="$_f"; break; fi
        done
        [ -n "$ACCESS_LOG" ] && break
    done
    # Если ни один файл ещё не существует — оставим маску для информативных сообщений
    [ -z "$ACCESS_LOG" ] && ACCESS_LOG="${ACCESS_LOG_GLOB%% *}"
elif [ -f "$ACCESS_LOG_FILE" ]; then
    ACCESS_LOG=$(head -n1 "$ACCESS_LOG_FILE" 2>/dev/null)
    if echo "$ACCESS_LOG" | grep -qi "httpd"; then
        LOG_FORMAT="apache"
    else
        LOG_FORMAT="nginx"
    fi
else
    if [ -f "/var/log/nginx/default_access.log" ]; then
        ACCESS_LOG="/var/log/nginx/default_access.log"   # Nginx (BitrixVM)
        LOG_FORMAT="nginx"
    elif [ -f "/var/log/nginx/access.log" ]; then
        ACCESS_LOG="/var/log/nginx/access.log"           # Nginx (стандартный)
        LOG_FORMAT="nginx"
    elif [ -f "/var/log/httpd/access_log" ]; then
        ACCESS_LOG="/var/log/httpd/access_log"           # Apache
        LOG_FORMAT="apache"
    else
        if systemctl is-active --quiet nginx 2>/dev/null; then
            if [ -f "/var/log/nginx/default_access.log" ]; then
                ACCESS_LOG="/var/log/nginx/default_access.log"
            else
                ACCESS_LOG="/var/log/nginx/access.log"
            fi
            LOG_FORMAT="nginx"
        elif systemctl is-active --quiet httpd 2>/dev/null; then
            ACCESS_LOG="/var/log/httpd/access_log"
            LOG_FORMAT="apache"
        else
            if [ -f "/var/log/nginx/default_access.log" ]; then
                ACCESS_LOG="/var/log/nginx/default_access.log"
            else
                ACCESS_LOG="/var/log/nginx/access.log"
            fi
            LOG_FORMAT="nginx"
        fi
    fi
fi

# Профиль сайта (generic|bitrix|wordpress)
CMS_PROFILE="generic"
if [ -f "$PROFILE_FILE" ]; then
    CMS_PROFILE=$(tr '[:upper:]' '[:lower:]' < "$PROFILE_FILE" 2>/dev/null || echo "generic")
    case "$CMS_PROFILE" in
        wordpress|bitrix|generic) ;;
        *) CMS_PROFILE="generic" ;;
    esac
fi

# Пороги для блокировки
MIN_SUSPICIOUS_REQUESTS=3    # Минимум «жёстких» подозрительных запросов
WP_SOFT_THRESHOLD=20         # Порог «мягких» WordPress-паттернов (брутфорс)
TIME_WINDOW=300              # Окно анализа, сек (информативно)
# BLOCK_DURATION задан в блоке настроек MikroTik выше

# Белый список User-Agent (регулярки) — НЕ блокировать
WHITELIST_USER_AGENTS=(
    "Googlebot"
    "Google-InspectionTool"
    "bingbot"
    "YandexBot"
    "YandexImages"
    "YandexMetrika"
    "Mail\.RU_Bot"
    "DuckDuckBot"
    "Baiduspider"
    "facebookexternalhit"
    "Twitterbot"
    "LinkedInBot"
    "Slackbot"
    "TelegramBot"
    "WhatsApp"
    "AhrefsBot"
    "SemrushBot"
    "DotBot"
    "MJ12bot"
    "BLEXBot"
    "SEMrushBot"
    "proximic"
    "Chrome-Lighthouse"
    "PTST"
    "StatusCake"
    "UptimeRobot"
    "Pingdom"
    "GTmetrix"
    "monitis"
)

# ----------------------------- Логирование -----------------------------------
log_message() {
    echo "$(date '+%Y-%m-%d %H:%M:%S'): $1" >> "$LOG_FILE"
}

# ====================== Вспомогательные функции MikroTik ======================

# Строгая валидация IPv4 (ничего кроме корректного адреса на роутер не уходит)
is_valid_ipv4() {
    local ip=$1 o
    [[ $ip =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]] || return 1
    for o in "${BASH_REMATCH[@]:1}"; do
        ((o <= 255)) || return 1
    done
    return 0
}

# Секунды -> формат времени RouterOS (HH:MM:SS)
ros_timeout() {
    local d=$1 h m s
    h=$((d / 3600))
    m=$(((d % 3600) / 60))
    s=$((d % 60))
    printf '%02d:%02d:%02d' "$h" "$m" "$s"
}

# Единая точка SSH: команды подаются на stdin, вывод роутера идёт на stdout.
# Поддерживает авторизацию по ключу (по умолчанию) или по паролю (sshpass).
mikrotik_exec() {
    local ssh_opts=(
        -p "$MIKROTIK_PORT"
        -o StrictHostKeyChecking=accept-new
        -o ConnectTimeout="$SSH_CONNECT_TIMEOUT"
        -o ServerAliveInterval=5
        -o ServerAliveCountMax=3
        -o PreferredAuthentications=publickey,password
    )

    if [ -n "$MIKROTIK_PASSWORD" ]; then
        if ! command -v sshpass >/dev/null 2>&1; then
            log_message "✗ Задан MIKROTIK_PASSWORD, но sshpass не установлен (apt install sshpass)"
            return 2
        fi
        SSHPASS="$MIKROTIK_PASSWORD" sshpass -e \
            ssh "${ssh_opts[@]}" "${MIKROTIK_USER}@${MIKROTIK_HOST}"
    else
        ssh -i "$MIKROTIK_SSH_KEY" -o BatchMode=yes \
            "${ssh_opts[@]}" "${MIKROTIK_USER}@${MIKROTIK_HOST}"
    fi
}

# Проверка связи/авторизации с роутером
mikrotik_test() {
    local out
    out=$(echo '/system identity print' | mikrotik_exec 2>&1)
    if [ $? -eq 0 ] && [ -n "$out" ]; then
        return 0
    fi
    log_message "✗ Нет связи с MikroTik ${MIKROTIK_USER}@${MIKROTIK_HOST}:${MIKROTIK_PORT} (${out})"
    return 1
}

# Кэш уже заблокированных IP (чтобы не слать дубликаты и считать «новые»)
BLOCKED_CACHE=$(mktemp)

fetch_blocked() {
    : > "$BLOCKED_CACHE"
    echo "/ip firewall address-list print terse where list=$MIKROTIK_ADDRESS_LIST" \
        | mikrotik_exec 2>/dev/null \
        | grep -oE 'address=[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' \
        | cut -d= -f2 | sort -u > "$BLOCKED_CACHE"
}

is_blocked() {
    grep -qFx "$1" "$BLOCKED_CACHE" 2>/dev/null
}

is_whitelisted_ip() {
    local ip=$1
    [ -f "$WHITELIST_FILE" ] || return 1
    grep -qFx "$ip" "$WHITELIST_FILE" 2>/dev/null
}

# Отправка пачки IP на MikroTik одним SSH-сеансом
push_to_mikrotik() {
    local infile=$1
    local to; to=$(ros_timeout "$BLOCK_DURATION")
    local ts; ts=$(date '+%Y%m%d-%H%M')
    local lines=()
    local blocked=0 skipped=0 wl=0 bad=0
    local ip reason

    while IFS='|' read -r ip reason; do
        [ -n "$ip" ] || continue

        if ! is_valid_ipv4 "$ip"; then
            ((bad++)); continue
        fi
        # Сетевые/broadcast адреса пропускаем (кроме localhost — но он и так отфильтрован)
        if [[ "$ip" =~ \.(0|255)$ ]]; then
            continue
        fi
        if is_whitelisted_ip "$ip"; then
            log_message "IP $ip в белом списке, пропуск"
            ((wl++)); continue
        fi
        if is_blocked "$ip"; then
            ((skipped++)); continue
        fi

        # reason делаем строго числовым — в комментарий не попадают данные из логов
        reason=${reason//[^0-9]/}
        [ -n "$reason" ] || reason=0

        lines+=("/ip firewall address-list add list=$MIKROTIK_ADDRESS_LIST address=$ip timeout=$to comment=\"waf-auto $ts hits=$reason\"")
        # помечаем в локальном кэше, чтобы не задублировать в этом же проходе
        echo "$ip" >> "$BLOCKED_CACHE"
        ((blocked++))
    done < "$infile"

    if [ "$blocked" -gt 0 ]; then
        if printf '%s\n' "${lines[@]}" | mikrotik_exec >/dev/null 2>&1; then
            log_message "✓ Отправлено на MikroTik ($MIKROTIK_ADDRESS_LIST, timeout $to): новых IP $blocked, пропущено уже в списке $skipped, в белом списке $wl, невалидных $bad"
        else
            log_message "✗ Ошибка отправки пачки IP на MikroTik (проверьте доступ/права пользователя)"
            return 1
        fi
    else
        log_message "Анализ завершён. Новых подозрительных IP не найдено (уже в списке $skipped, белый список $wl, невалидных $bad)"
    fi
    return 0
}

# ------------------------- Состояние модуля (совместимость) ------------------
# Если каталог состояния вообще не создан (standalone-установка только этого
# скрипта) — считаем модуль включённым. Иначе уважаем флаги исходного проекта.
is_suspicious_enabled() {
    if [ ! -d "$STATE_DIR" ]; then
        return 0
    fi
    if [ -f "$SUSPICIOUS_STATE_FILE" ]; then
        return 0
    fi
    if [ ! -d "$COMPONENTS_DIR" ] && [ -f "$LEGACY_STATE_FILE" ]; then
        return 0
    fi
    # Каталог есть, но флагов нет — по умолчанию тоже включаем,
    # чтобы скрипт работал без установщика. Чтобы отключить —
    # используйте отдельный механизм управления.
    if [ ! -d "$COMPONENTS_DIR" ] && [ ! -f "$LEGACY_STATE_FILE" ]; then
        return 0
    fi
    return 1
}

# ----------------------------- Чтение логов ----------------------------------
read_log_file() {
    local file=$1
    local lines=${2:-50000}
    if [[ "$file" == *.gz ]]; then
        if command -v zcat >/dev/null 2>&1; then
            zcat "$file" 2>/dev/null | tail -n "$lines"
        elif command -v gunzip >/dev/null 2>&1; then
            gunzip -c "$file" 2>/dev/null | tail -n "$lines"
        else
            log_message "Ошибка: нет zcat/gunzip для чтения .gz"
            return 1
        fi
    else
        tail -n "$lines" "$file" 2>/dev/null
    fi
}

# Список логов для анализа (текущий + свежие архивы)
get_log_files() {
    # Режим per-site: собираем все файлы по glob-маске(ам) + опционально их .gz
    if [ -n "$ACCESS_LOG_GLOB" ]; then
        local files=() f base gz gz_count
        for pattern in $ACCESS_LOG_GLOB; do
            for f in $pattern; do
                [ -f "$f" ] || continue
                files+=("$f")
                if [ "$ANALYZE_GZ" = "1" ]; then
                    # База без .log (например /var/log/nginx/site.access) для поиска архивов
                    base="${f%.log}"
                    gz_count=0
                    while IFS= read -r gz; do
                        [ -n "$gz" ] && [ -f "$gz" ] || continue
                        files+=("$gz")
                        ((gz_count++))
                        [ "$gz_count" -ge "$GZ_PER_LOG" ] && break
                    done < <(ls -t "${base}".log*.gz "${base}".log-*.gz 2>/dev/null | head -n "$GZ_PER_LOG")
                fi
            done
        done
        printf '%s\n' "${files[@]}"
        return
    fi

    local log_dir; log_dir=$(dirname "$ACCESS_LOG")
    local log_name; log_name=$(basename "$ACCESS_LOG")
    local log_base="${log_name%.*}"
    local files=()

    if [ -f "$ACCESS_LOG" ]; then
        files+=("$ACCESS_LOG")
    fi

    if [ -d "$log_dir" ]; then
        while IFS= read -r file; do
            if [ -n "$file" ] && [ -f "$file" ] && [[ ! "$file" == *.gz ]]; then
                local basename_file; basename_file=$(basename "$file")
                if [[ "$file" != "$ACCESS_LOG" ]] && [[ "$basename_file" =~ ${log_base}\.log-[0-9]{8}$ ]]; then
                    files+=("$file")
                fi
            fi
        done < <(ls -t "$log_dir"/${log_base}.log-* 2>/dev/null | grep -v "\.gz$" | head -1)
    fi

    if [ -d "$log_dir" ]; then
        local gz_count=0
        while IFS= read -r file; do
            if [ -n "$file" ] && [ -f "$file" ] && [[ "$file" == *.gz ]]; then
                files+=("$file")
                ((gz_count++))
                [ $gz_count -ge 2 ] && break
            fi
        done < <(ls -t "$log_dir"/${log_base}*.gz 2>/dev/null | head -2)
    fi

    printf '%s\n' "${files[@]}"
}

# =============================================================================
#                          АНАЛИЗ ЛОГОВ (детект-ядро)
# =============================================================================
# Логика детекта полностью сохранена из оригинала. Меняется только «выхлоп»:
# найденные IP пишутся во временный файл и уходят на MikroTik пачкой.
analyze_logs_fast() {
    log_message "Начало анализа логов ($LOG_FORMAT) v$VERSION, профиль: $CMS_PROFILE"
    log_message "Цель блокировки: MikroTik ${MIKROTIK_HOST} -> address-list '$MIKROTIK_ADDRESS_LIST'"

    local temp_file; temp_file=$(mktemp)
    local temp_suspicious; temp_suspicious=$(mktemp)

    local log_files=()
    while IFS= read -r file; do
        if [ -n "$file" ] && [ -f "$file" ]; then
            log_files+=("$file")
        fi
    done < <(get_log_files)

    if [ ${#log_files[@]} -eq 0 ]; then
        log_message "Ошибка: не найдены файлы логов для анализа"
        rm -f "$temp_file" "$temp_suspicious"
        return 1
    fi

    log_message "Анализирую ${#log_files[@]} файл(ов) логов"

    {
        for log_file in "${log_files[@]}"; do
            read_log_file "$log_file" 50000
        done
    } | awk -v profile="$CMS_PROFILE" -v default_threshold="$MIN_SUSPICIOUS_REQUESTS" -v wp_soft_threshold="$WP_SOFT_THRESHOLD" '
    {
        ip = $1
        if (ip ~ /^127\./ || ip == "::1" || ip == "-") next

        url = ""
        user_agent = ""

        original_line = $0
        quoted_fields_count = 0
        delete quoted_array
        while (match(original_line, /"([^"]*)"/, match_result)) {
            quoted_fields_count++
            quoted_array[quoted_fields_count] = match_result[1]
            original_line = substr(original_line, RSTART + RLENGTH)
        }

        # User-Agent: в стандартном nginx/apache combined это ПОСЛЕДНЕЕ поле в
        # кавычках. В BitrixVM последним часто идёт "-" или gzip-ratio — тогда
        # берём предыдущее значимое поле. Корректно работает для обоих форматов
        # (в оригинале UA бралось строго предпоследним, из-за чего в стандартном
        # nginx вместо UA подхватывался Referer и ломался белый список ботов).
        if (quoted_fields_count >= 1) {
            user_agent = quoted_array[quoted_fields_count]
            if ((user_agent == "-" || user_agent ~ /^[0-9.]+$/) && quoted_fields_count >= 2) {
                user_agent = quoted_array[quoted_fields_count - 1]
            }
        }

        for (i = 1; i <= NF; i++) {
            if ($i ~ /^"[A-Z]+/) {
                rest = substr($0, index($0, $i))
                # Разделитель URL — пробел/таб/кавычка. Важно: класс [ \t"] вместо \s,
                # т.к. \s внутри [...] в gawk НЕ является пробелом (иначе URL
                # обрезается на первой букве "s": /shell.php -> /, /wso.php -> /w).
                match(rest, /"[A-Z]+[ \t]+([^ \t"]+)/, parts)
                if (parts[1] != "") {
                    url = parts[1]
                    break
                }
            }
        }

        if (url == "") {
            for (i = 1; i <= NF; i++) {
                if ($i ~ /^\//) {
                    url = $i
                    gsub(/^"/, "", url)
                    gsub(/".*$/, "", url)
                    break
                }
            }
        }

        if (url == "") next

        url_decoded = url
        gsub(/%2e/i, ".", url_decoded)
        gsub(/%2f/i, "/", url_decoded)
        gsub(/%5c/i, "\\", url_decoded)

        suspicious_match = 0
        wp_soft_match = 0

        if (url ~ /(wso\.php|shell\.php|cmd\.php|c99\.php|r57\.php|byp8\.php|zwso\.php|shoha\.php|raw\.php|berlin\.php|num\.php|yu\.php|widgets\.php|ioxi-o\.php|class-t\.api\.php|class19\.php|chosen\.php|dejavu\.php|well-known\/acme-challenge.*\.php|\.well-known.*\.php)/) {
            suspicious_match = 1
        }

        if (url ~ /(xmlrpc\.php|wp-cron\.php|\/wp-json\/|admin-ajax\.php|\/wp-config\.php)/) {
            if (profile == "wordpress") {
                wp_soft_match = 1
            } else {
                suspicious_match = 1
            }
        }

        if (profile == "bitrix" && url ~ /(wp-login\.php|\/wp-admin(\/|$))/) {
            suspicious_match = 1
        }

        if (url ~ /(\.env|\.git|\.svn|config\.php|configuration\.php|settings\.php|database\.yml)/) {
            suspicious_match = 1
        }

        if (url ~ /(union.*select|concat.*\(|char\(|0x[0-9a-f]+)/) {
            suspicious_match = 1
        }

        if (url ~ /(\/etc\/passwd|\/bin\/bash|\/usr\/bin|cmd=|exec=|system\()/) {
            suspicious_match = 1
        }

        if (url ~ /(phpMyAdmin|phpmyadmin|pma\/|adminer|cgi-bin|\.cgi)/) {
            suspicious_match = 1
        }

        if (url ~ /(\.\.\/\.\.|\.\.\/|etc\/passwd|proc\/self)/ || url_decoded ~ /\.\.\//) {
            suspicious_match = 1
        }

        if (url ~ /(\/tmb\/wso\.php|\/1\.php$|\/b\.php$|\/nc4\.php|\/d4\.php|\/cc\.php|\/abcd\.php|\/test\.php$)/) {
            suspicious_match = 1
        }

        if (suspicious_match == 1 || wp_soft_match == 1) {
            if (suspicious_match == 1) suspicious[ip]++
            if (wp_soft_match == 1) wp_suspicious[ip]++
            if (!(ip in sample_ua)) sample_ua[ip] = user_agent
        }
    }
    END {
        for (ip in suspicious) {
            hard_hits = suspicious[ip]
            soft_hits = (ip in wp_suspicious ? wp_suspicious[ip] : 0)
            if (hard_hits >= default_threshold ||
                (profile == "wordpress" && soft_hits >= wp_soft_threshold)) {
                total_hits = hard_hits + soft_hits
                print ip "|suspicious:" total_hits "|ua:" sample_ua[ip]
            }
        }
    }' > "$temp_suspicious"

    # Фильтрация по белому списку User-Agent
    while IFS= read -r line; do
        [ -n "$line" ] || continue
        ip=$(echo "$line" | cut -d'|' -f1)
        reason=$(echo "$line" | sed -n 's/.*suspicious:\([0-9]*\).*/\1/p')
        ua=$(echo "$line" | sed -n 's/.*ua:\(.*\)/\1/p')
        [ -n "$ip" ] || continue

        is_bot=0
        if [ -n "$ua" ]; then
            for pattern in "${WHITELIST_USER_AGENTS[@]}"; do
                if echo "$ua" | grep -qiE "$pattern"; then
                    is_bot=1
                    log_message "Пропуск IP $ip — легитимный бот ($(echo "$ua" | grep -oiE "$pattern" | head -1))"
                    break
                fi
            done
        fi

        if [ $is_bot -eq 0 ]; then
            echo "$ip|$reason" >> "$temp_file"
        fi
    done < "$temp_suspicious"

    # Отправка на MikroTik
    push_to_mikrotik "$temp_file"

    rm -f "$temp_file" "$temp_suspicious"
}

# ----------------------------- CLI-команды -----------------------------------
cmd_test() {
    echo "Проверка связи с MikroTik ${MIKROTIK_USER}@${MIKROTIK_HOST}:${MIKROTIK_PORT}..."
    local out
    out=$(echo '/system identity print' | mikrotik_exec 2>&1)
    if [ $? -eq 0 ] && [ -n "$out" ]; then
        echo "OK:"
        echo "$out"
        exit 0
    else
        echo "ОШИБКА: $out"
        exit 1
    fi
}

cmd_list() {
    echo "/ip firewall address-list print where list=$MIKROTIK_ADDRESS_LIST" | mikrotik_exec
}

cmd_flush() {
    echo "Очистка address-list '$MIKROTIK_ADDRESS_LIST' на MikroTik..."
    echo "/ip firewall address-list remove [find list=$MIKROTIK_ADDRESS_LIST]" | mikrotik_exec \
        && echo "Готово." || echo "Ошибка очистки."
}

# ----------------------------- Основная функция ------------------------------
main() {
    if [ "$EUID" -ne 0 ]; then
        echo "Ошибка: скрипт должен запускаться от root"
        exit 1
    fi

    if [ -z "$MIKROTIK_HOST" ]; then
        log_message "✗ Не задан MIKROTIK_HOST. Укажите его в $MIKROTIK_CONF или в начале скрипта."
        echo "Ошибка: не задан MIKROTIK_HOST (см. $MIKROTIK_CONF)"
        exit 1
    fi

    log_message "Используется лог: $ACCESS_LOG (формат: $LOG_FORMAT)"

    if ! is_suspicious_enabled; then
        log_message "⚠ Модуль suspicious отключён. Анализ пропущен."
        return 0
    fi

    # Проверяем связь с роутером и забираем текущий список для дедупликации
    if ! mikrotik_test; then
        echo "Ошибка: нет связи с MikroTik — см. $LOG_FILE"
        exit 1
    fi
    fetch_blocked

    analyze_logs_fast
}

# Очистка временных файлов
cleanup() { rm -f "$BLOCKED_CACHE" 2>/dev/null; }
trap cleanup EXIT

# ----------------------------- Точка входа -----------------------------------
case "${1:-run}" in
    run|"")   main ;;
    test)     cmd_test ;;
    list)     cmd_list ;;
    flush)    cmd_flush ;;
    -h|--help|help)
        cat <<EOF
Использование: $(basename "$0") [команда]

  run     анализ логов и отправка подозрительных IP на MikroTik (по умолчанию)
  test    проверить SSH-связь с MikroTik
  list    показать текущий address-list на MikroTik
  flush   очистить address-list на MikroTik

Настройки подключения: $MIKROTIK_CONF
EOF
        ;;
    *)
        echo "Неизвестная команда: $1 (см. --help)"
        exit 1
        ;;
esac
