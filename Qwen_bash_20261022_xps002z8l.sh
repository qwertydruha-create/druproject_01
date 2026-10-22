#!/bin/bash
# ============================================================================
# port_audit.sh — Аудит открытых портов для Astra Linux 1.7 SE
# Назначение: выявление открытых сетевых сервисов и статистика использования
# Требования: права root для полной информации о процессах
# Совместимость: Astra Linux 1.7 SE, Ubuntu 20.04+, Debian 11+
# ============================================================================

set -euo pipefail

# Цвета для вывода
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color

# Переменные
OUTPUT_CSV=""
STATS_ONLY=false
VERBOSE=false

# ============================================================================
# Функции
# ============================================================================

usage() {
    cat << EOF
Использование: $0 [опции]

Опции:
  -c, --csv <файл>    Экспорт результатов в CSV
  -s, --stats         Показать только статистику (без деталей)
  -v, --verbose       Подробный вывод с дополнительными проверками
  -h, --help          Показать эту справку

Примеры:
  sudo $0                    # Полный аудит
  sudo $0 -c audit.csv       # Аудит с экспортом в CSV
  sudo $0 -s                 # Только статистика портов
  sudo $0 -v -c full.csv     # Подробный аудит с экспортом

EOF
    exit 0
}

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Проверка прав root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_warn "Скрипт запущен без прав root. Информация о процессах будет неполной."
        log_warn "Для полного аудита выполните: sudo $0 $*"
        echo ""
    fi
}

# Проверка доступности утилит
check_tools() {
    local tools=("ss" "awk" "sort" "uniq")
    local missing=()
    
    for tool in "${tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            missing+=("$tool")
        fi
    done
    
    if [[ ${#missing[@]} -gt 0 ]]; then
        log_error "Отсутствуют необходимые утилиты: ${missing[*]}"
        log_error "Установите их через: sudo apt install iproute2 gawk coreutils"
        exit 1
    fi
    
    log_info "Все необходимые утилиты доступны"
}

# Сбор данных об открытых портах
collect_ports() {
    log_info "Сбор информации об открытых портах..."
    
    # Используем ss (современная замена netstat)
    # -tulnp: TCP+UDP, listening, numeric, processes
    ss -tulnp 2>/dev/null | \
    awk '
    NR>1 {
        proto = $1
        state = $2
        local_addr = $5
        
        # Извлекаем порт из адреса
        if (local_addr ~ /:/) {
            split(local_addr, parts, ":")
            port = parts[length(parts)]
        } else {
            port = local_addr
        }
        
        # Извлекаем процесс (если есть права)
        process = "N/A"
        if (NF >= 7 && $7 ~ /users:/) {
            match($7, /\"([^\"]+)\"/, arr)
            if (arr[1] != "") {
                process = arr[1]
            }
        }
        
        # Выводим в формате для дальнейшей обработки
        print proto "|" port "|" state "|" process
    }' | sort -t'|' -k2 -n | uniq
}

# Статистика по портам
generate_stats() {
    local data="$1"
    
    echo ""
    echo "============================================================================"
    echo "СТАТИСТИКА ОТКРЫТЫХ ПОРТОВ"
    echo "============================================================================"
    echo ""
    
    # Общее количество
    local total=$(echo "$data" | wc -l)
    log_info "Всего открытых портов: $total"
    echo ""
    
    # Статистика по протоколам
    echo "--- По протоколам ---"
    echo "$data" | awk -F'|' '{print $1}' | sort | uniq -c | sort -rn | \
    awk '{printf "  %-10s: %d\n", $2, $1}'
    echo ""
    
    # Топ-10 наиболее частых портов
    echo "--- Топ-10 наиболее часто используемых портов ---"
    echo "$data" | awk -F'|' '{print $2}' | sort -n | uniq -c | sort -rn | head -10 | \
    awk '{printf "  Порт %-6s: %d слушателей\n", $2, $1}'
    echo ""
    
    # Анализ по процессам
    echo "--- По процессам (топ-10) ---"
    echo "$data" | awk -F'|' '{print $4}' | sort | uniq -c | sort -rn | head -10 | \
    awk '{printf "  %-30s: %d портов\n", $2, $1}'
    echo ""
}

# Детальный вывод
show_details() {
    local data="$1"
    
    echo ""
    echo "============================================================================"
    echo "ДЕТАЛЬНАЯ ИНФОРМАЦИЯ ОБ ОТКРЫТЫХ ПОРТАХ"
    echo "============================================================================"
    echo ""
    printf "%-8s %-8s %-12s %-20s\n" "PROTO" "PORT" "STATE" "PROCESS"
    echo "------------------------------------------------------------------------"
    
    echo "$data" | while IFS='|' read -r proto port state process; do
        printf "%-8s %-8s %-12s %-20s\n" "$proto" "$port" "$state" "$process"
    done
    
    echo ""
}

# Экспорт в CSV
export_csv() {
    local data="$1"
    local file="$2"
    
    log_info "Экспорт в CSV: $file"
    
    {
        echo "Протокол,Порт,Состояние,Процесс"
        echo "$data" | awk -F'|' '{printf "%s,%s,%s,%s\n", $1, $2, $3, $4}'
    } > "$file"
    
    log_info "Экспорт завершён. Файл: $file"
}

# Дополнительные проверки (verbose)
verbose_checks() {
    echo ""
    echo "============================================================================"
    echo "ДОПОЛНИТЕЛЬНЫЕ ПРОВЕРКИ БЕЗОПАСНОСТИ"
    echo "============================================================================"
    echo ""
    
    # Проверка слушающих на всех интерфейсах (0.0.0.0 или ::)
    log_info "Порты, слушающие на всех интерфейсах (потенциальный риск):"
    ss -tulnp | awk 'NR>1 && ($5 ~ /0\.0\.0\.0:/ || $5 ~ /:::/) {print "  " $5 " (" $1 ")"}' | sort -u
    echo ""
    
    # Проверка нестандартных портов (< 1024, кроме стандартных)
    log_info "Привилегированные порты (< 1024):"
    ss -tulnp | awk 'NR>1 {
        split($5, parts, ":")
        port = parts[length(parts)]
        if (port < 1024) print "  Порт " port " (" $1 ") - " $7
    }' | sort -u
    echo ""
    
    # Проверка firewall
    if command -v iptables &> /dev/null; then
        log_info "Правила iptables (первые 10):"
        iptables -L -n 2>/dev/null | head -15 || log_warn "Нет доступа к iptables"
    fi
    echo ""
}

# ============================================================================
# Основной блок
# ============================================================================

main() {
    # Парсинг аргументов
    while [[ $# -gt 0 ]]; do
        case $1 in
            -c|--csv)
                OUTPUT_CSV="$2"
                shift 2
                ;;
            -s|--stats)
                STATS_ONLY=true
                shift
                ;;
            -v|--verbose)
                VERBOSE=true
                shift
                ;;
            -h|--help)
                usage
                ;;
            *)
                log_error "Неизвестная опция: $1"
                usage
                ;;
        esac
    done
    
    echo "============================================================================"
    echo "АУДИТ ОТКРЫТЫХ ПОРТОВ — ASTRA LINUX 1.7 SE"
    echo "Дата: $(date '+%Y-%m-%d %H:%M:%S')"
    echo "Хост: $(hostname)"
    echo "============================================================================"
    echo ""
    
    # Проверки
    check_root "$@"
    check_tools
    
    # Сбор данных
    local port_data
    port_data=$(collect_ports)
    
    if [[ -z "$port_data" ]]; then
        log_warn "Открытые порты не обнаружены или нет данных"
        exit 0
    fi
    
    # Вывод
    if [[ "$STATS_ONLY" == false ]]; then
        show_details "$port_data"
    fi
    
    generate_stats "$port_data"
    
    if [[ "$VERBOSE" == true ]]; then
        verbose_checks
    fi
    
    if [[ -n "$OUTPUT_CSV" ]]; then
        export_csv "$port_data" "$OUTPUT_CSV"
    fi
    
    echo "============================================================================"
    log_info "Аудит завершён"
    echo "============================================================================"
}

# Запуск
main "$@"