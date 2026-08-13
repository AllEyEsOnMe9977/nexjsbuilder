RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }
log_step() { echo -e "${BLUE}[STEP]${NC} $1"; }

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   log_error "This script must be run as root or with sudo"
fi

# Generate random password
generate_password() {
    openssl rand -base64 32 | tr -d "=+/" | cut -c1-24
}

# Validate and sanitize project name
sanitize_project_name() {
    local name=$1
    # Convert to lowercase
    name=$(echo "$name" | tr '[:upper:]' '[:lower:]')
    # Replace spaces and underscores with hyphens
    name=$(echo "$name" | tr '_' '-' | tr ' ' '-')
    # Remove any characters that aren't alphanumeric or hyphens
    name=$(echo "$name" | sed 's/[^a-z0-9-]//g')
    # Remove leading/trailing hyphens
    name=$(echo "$name" | sed 's/^-*//;s/-*$//')
    # Ensure it doesn't start with a number
    if [[ $name =~ ^[0-9] ]]; then
        name="app-$name"
    fi
    echo "$name"
}

# Validate domain
validate_domain() {
    local domain=$1
    if [[ ! $domain =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$ ]]; then
        return 1
    fi
    return 0
}

# Validate email
validate_email() {
    local email=$1
    if [[ ! $email =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
        return 1
    fi
    return 0
}

# Check if port is in use
check_port() {
    local port=$1
    if lsof -Pi :$port -sTCP:LISTEN -t >/dev/null 2>&1 ; then
        return 0
    else
        return 1
    fi
}