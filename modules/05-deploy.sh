#!/bin/bash
# 05-deploy.sh - Orchestrator for deployment

# Source the deployment modules (absolute paths — CWD may have changed to $PROJECT_DIR by now)
source "$SCRIPT_DIR/modules/deploy/05a-deploy-admin.sh"
source "$SCRIPT_DIR/modules/deploy/05b-deploy-systemd.sh"
source "$SCRIPT_DIR/modules/deploy/05c-deploy-nginx-http.sh"
source "$SCRIPT_DIR/modules/deploy/05d-deploy-ssl.sh"
source "$SCRIPT_DIR/modules/deploy/05e-deploy-backup.sh"
source "$SCRIPT_DIR/modules/deploy/05f-deploy-summary.sh"