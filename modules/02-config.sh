# Get domain from user with validation
log_step "Domain Configuration"
while true; do
    read -p "Enter your domain name (e.g., example.com): " DOMAIN
    if [[ -z "$DOMAIN" ]]; then
        log_warn "Domain cannot be empty. Please try again."
        continue
    fi
    if validate_domain "$DOMAIN"; then
        break
    else
        log_warn "Invalid domain format. Please try again."
    fi
done

# Get email for Let's Encrypt with validation
while true; do
    read -p "Enter your email for SSL certificate notifications: " EMAIL
    if [[ -z "$EMAIL" ]]; then
        log_warn "Email cannot be empty. Please try again."
        continue
    fi
    if validate_email "$EMAIL"; then
        break
    else
        log_warn "Invalid email format. Please try again."
    fi
done

# Get project name with validation
while true; do
    read -p "Enter project name (default: nextjs-app): " PROJECT_NAME_INPUT
    PROJECT_NAME_INPUT=${PROJECT_NAME_INPUT:-nextjs-app}
    PROJECT_NAME=$(sanitize_project_name "$PROJECT_NAME_INPUT")
    
    if [[ -z "$PROJECT_NAME" ]]; then
        log_warn "Invalid project name. Please use letters, numbers, and hyphens."
        continue
    fi
    
    if [[ ${#PROJECT_NAME} -lt 3 ]]; then
        log_warn "Project name must be at least 3 characters long."
        continue
    fi
    
    log_info "Project name will be: $PROJECT_NAME"
    break
done

# Database selection
log_step "Database Configuration"
echo "Select database:"
echo "1) SQLite (lightweight, file-based)"
echo "2) MariaDB (full-featured SQL server)"
while true; do
    read -p "Enter choice [1-2]: " DB_CHOICE
    case $DB_CHOICE in
        1|2)
            break
            ;;
        *)
            log_warn "Invalid choice. Please enter 1 or 2."
            ;;
    esac
done

DB_TYPE=""
DB_NAME="${PROJECT_NAME//-/_}_db"
DB_USER="${PROJECT_NAME//-/_}_user"
DB_PASSWORD=$(generate_password)
DB_HOST="localhost"
DB_PORT="3306"

case $DB_CHOICE in
    1)
        DB_TYPE="sqlite"
        log_info "SQLite selected"
        ;;
    2)
        DB_TYPE="mariadb"
        log_info "MariaDB selected"
        ;;
esac

# Admin user configuration
log_step "Admin User Configuration"
while true; do
    read -p "Enter admin username (default: admin): " ADMIN_USER
    ADMIN_USER=${ADMIN_USER:-admin}
    # Sanitize username
    ADMIN_USER=$(echo "$ADMIN_USER" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9_-]//g')
    
    if [[ -z "$ADMIN_USER" ]]; then
        log_warn "Username cannot be empty after sanitization."
        continue
    fi
    
    if [[ ${#ADMIN_USER} -lt 3 ]]; then
        log_warn "Username must be at least 3 characters long."
        continue
    fi
    
    break
done

read -p "Enter admin password (leave empty to auto-generate): " ADMIN_PASSWORD
if [[ -z "$ADMIN_PASSWORD" ]]; then
    ADMIN_PASSWORD=$(generate_password)
    AUTO_GENERATED_PASS=true
else
    AUTO_GENERATED_PASS=false
    if [[ ${#ADMIN_PASSWORD} -lt 8 ]]; then
        log_warn "Password is less than 8 characters. Consider using a stronger password."
    fi
fi

# Template selection
log_step "Template Selection"

echo "Select homepage template:"
echo "1) Blank (minimal welcome page)"
echo "2) Shop (e-commerce template)"
while true; do
    read -p "Enter choice [1-2]: " TEMPLATE_CHOICE
    case $TEMPLATE_CHOICE in
        1)
            TEMPLATE_FILE="blank.tsx"
            # Look for templates relative to the script location
            TEMPLATE_PATH="$SCRIPT_DIR/templates/$TEMPLATE_FILE"

            # If not found, try current directory
            if [[ ! -f "$TEMPLATE_PATH" ]]; then
                TEMPLATE_PATH="$(pwd)/templates/$TEMPLATE_FILE"
            fi
            log_info "Blank template selected"
            break
            ;;
        2)
            TEMPLATE_FILE="shop.tsx"
            # Look for templates relative to the script location
            TEMPLATE_PATH="$SCRIPT_DIR/templates/$TEMPLATE_FILE"

            # If not found, try current directory
            if [[ ! -f "$TEMPLATE_PATH" ]]; then
                TEMPLATE_PATH="$(pwd)/templates/$TEMPLATE_FILE"
            fi
            log_info "Shop template selected"
            break
            ;;
        *)
            log_warn "Invalid choice. Please enter 1 or 2."
            ;;
    esac
done

# Check if template file exists
if [[ ! -f "$TEMPLATE_PATH" ]]; then
    log_error "Template file not found: $TEMPLATE_PATH"
fi

log_info "Using template: $TEMPLATE_PATH"