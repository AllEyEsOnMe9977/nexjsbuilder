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

# Prompt the user to pick one item from a list; the choice is stored in PICKED_ITEM
pick_from_list() {
    local prompt="$1"; shift
    local items=("$@") i choice
    echo "$prompt"
    for i in "${!items[@]}"; do
        echo "$((i+1))) ${items[$i]}"
    done
    while true; do
        read -p "Enter choice [1-${#items[@]}]: " choice
        if [[ "$choice" =~ ^[0-9]+$ ]] && (( choice >= 1 && choice <= ${#items[@]} )); then
            PICKED_ITEM="${items[$((choice-1))]}"
            return 0
        fi
        log_warn "Invalid choice. Enter a number between 1 and ${#items[@]}."
    done
}

# Layout: templates/<category>/<variant>/page.tsx
# Step 1 - categories = folders in templates/ holding at least one valid variant
CATEGORY_LIST=()
for cat_dir in "$SCRIPT_DIR"/templates/*/; do
    cat_name="$(basename "$cat_dir")"
    if [[ -f "${cat_dir}page.tsx" ]]; then
        log_warn "Ignoring flat template '$cat_name' - move it into templates/$cat_name/default/"
        continue
    fi
    for var_dir in "$cat_dir"*/; do
        if [[ -f "${var_dir}page.tsx" ]]; then
            CATEGORY_LIST+=("$cat_name")
            break
        fi
    done
done
if [[ ${#CATEGORY_LIST[@]} -eq 0 ]]; then
    log_error "No valid templates found in $SCRIPT_DIR/templates (expected templates/<category>/<variant>/page.tsx)"
fi

pick_from_list "Select template category:" "${CATEGORY_LIST[@]}"
TEMPLATE_CATEGORY="$PICKED_ITEM"

# Step 2 - variants inside the chosen category
VARIANT_LIST=()
for var_dir in "$SCRIPT_DIR/templates/$TEMPLATE_CATEGORY"/*/; do
    if [[ -f "${var_dir}page.tsx" ]]; then
        VARIANT_LIST+=("$(basename "$var_dir")")
    fi
done

if [[ ${#VARIANT_LIST[@]} -eq 1 ]]; then
    TEMPLATE_VARIANT="${VARIANT_LIST[0]}"
    log_info "Only one variant available: $TEMPLATE_VARIANT"
else
    pick_from_list "Select '$TEMPLATE_CATEGORY' variant:" "${VARIANT_LIST[@]}"
    TEMPLATE_VARIANT="$PICKED_ITEM"
fi

# TEMPLATE_NAME is "category/variant" and is used below to build TEMPLATE_PATH
TEMPLATE_NAME="$TEMPLATE_CATEGORY/$TEMPLATE_VARIANT"
log_info "Template selected: $TEMPLATE_NAME"

# Resolve template directory relative to the script location
TEMPLATE_PATH="$SCRIPT_DIR/templates/$TEMPLATE_NAME"

# If not found, try current directory
if [[ ! -d "$TEMPLATE_PATH" ]]; then
    TEMPLATE_PATH="$(pwd)/templates/$TEMPLATE_NAME"
fi

# Check if template directory exists and has the mandatory page.tsx
if [[ ! -d "$TEMPLATE_PATH" ]]; then
    log_error "Template directory not found: $TEMPLATE_PATH"
fi
if [[ ! -f "$TEMPLATE_PATH/page.tsx" ]]; then
    log_error "Template directory is missing required page.tsx: $TEMPLATE_PATH"
fi

log_info "Using template: $TEMPLATE_PATH"