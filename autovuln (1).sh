set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
RESET='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCANNER="$SCRIPT_DIR/scanner.py"
LOG_DIR="$SCRIPT_DIR/logs"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

usage() {
  echo -e "${BOLD}Usage:${RESET} $0 <target> [options]"
  echo ""
  echo -e "${BOLD}Options:${RESET}"
  echo "  --full              Scan all CVE-tracked ports + top 1024"
  echo "  --ports <p1 p2...>  Scan specific ports only"
  echo "  --output <prefix>   Save HTML + JSON report to file"
  echo "  --threads <n>       Concurrent threads (default: 50)"
  echo "  --no-log            Skip writing to logs/"
  echo ""
  echo -e "${BOLD}Examples:${RESET}"
  echo "  $0 scanme.nmap.org"
  echo "  $0 192.168.1.1 --full --output reports/scan_host"
  echo "  $0 example.com --ports 22 80 443 --output reports/quick"
  exit 1
}

check_dependencies() {
  echo -e "${BLUE}[*]${RESET} Running pre-flight checks..."

  if ! command -v python3 &>/dev/null; then
    echo -e "${RED}[✗]${RESET} Python3 not found. Please install Python 3.8+"
    exit 1
  fi
  echo -e "${GREEN}[✓]${RESET} Python3: $(python3 --version)"

  if [ ! -f "$SCANNER" ]; then
    echo -e "${RED}[✗]${RESET} scanner.py not found at $SCANNER"
    exit 1
  fi
  echo -e "${GREEN}[✓]${RESET} Scanner module found"

  echo -e "${GREEN}[✓]${RESET} Pre-flight checks passed\n"
}

validate_target() {
  local target="$1"
  if [[ -z "$target" ]]; then
    echo -e "${RED}[✗]${RESET} No target specified"
    usage
  fi

  # Warn if scanning a public IP without --output
  if [[ "$target" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo -e "${YELLOW}[!]${RESET} Scanning IP: $target — ensure you have authorization"
  fi
}

setup_logs() {
  if [[ "$NO_LOG" == "false" ]]; then
    mkdir -p "$LOG_DIR"
    LOG_FILE="$LOG_DIR/scan_${TIMESTAMP}.log"
    echo -e "${BLUE}[*]${RESET} Log: $LOG_FILE"
  fi
}

main() {
  if [[ $# -eq 0 ]]; then usage; fi

  TARGET="$1"
  shift

  EXTRA_ARGS=()
  NO_LOG="false"
  OUTPUT_SET="false"

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --full)       EXTRA_ARGS+=("--full"); shift ;;
      --ports)      EXTRA_ARGS+=("--ports"); shift
                    while [[ $# -gt 0 && "$1" =~ ^[0-9]+$ ]]; do
                      EXTRA_ARGS+=("$1"); shift
                    done ;;
      --output)     EXTRA_ARGS+=("--output" "$2"); OUTPUT_SET="true"; shift 2 ;;
      --threads)    EXTRA_ARGS+=("--threads" "$2"); shift 2 ;;
      --no-log)     NO_LOG="true"; shift ;;
      --help|-h)    usage ;;
      *)            echo -e "${RED}[✗]${RESET} Unknown option: $1"; usage ;;
    esac
  done

  if [[ "$OUTPUT_SET" == "false" ]]; then
    mkdir -p "$SCRIPT_DIR/reports"
    AUTO_OUT="$SCRIPT_DIR/reports/${TARGET//\//_}_${TIMESTAMP}"
    EXTRA_ARGS+=("--output" "$AUTO_OUT")
    echo -e "${BLUE}[*]${RESET} Auto-saving report to: $AUTO_OUT.html"
  fi

  check_dependencies
  validate_target "$TARGET"
  setup_logs

  echo -e "${BLUE}[*]${RESET} Starting scan: ${BOLD}$TARGET${RESET} at $(date)\n"

  if [[ "$NO_LOG" == "false" ]]; then
    python3 "$SCANNER" --target "$TARGET" "${EXTRA_ARGS[@]}" 2>&1 | tee "$LOG_FILE"
  else
    python3 "$SCANNER" --target "$TARGET" "${EXTRA_ARGS[@]}"
  fi

  echo -e "\n${GREEN}${BOLD}[✓] AutoVuln scan finished.${RESET}"
}

main "$@"
