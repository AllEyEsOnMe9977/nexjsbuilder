#!/bin/bash

# Next.js Automated Setup Script with SSL, Nginx, Database, and Analytics
# Run as root or with sudo

set -e

# Define base directory so modules can correctly reference relative paths (like templates/)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Source all setup modules in sequential order
source "$SCRIPT_DIR/modules/01-utils.sh"
source "$SCRIPT_DIR/modules/02-config.sh"
source "$SCRIPT_DIR/modules/03-system.sh"
source "$SCRIPT_DIR/modules/04-app.sh"
source "$SCRIPT_DIR/modules/05-deploy.sh"