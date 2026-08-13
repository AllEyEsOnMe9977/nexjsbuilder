#!/bin/bash
# 05-deploy.sh - Orchestrator for deployment

# Source the deployment modules
source ./modules/deploy/05a-deploy-admin.sh
source ./modules/deploy/05b-deploy-systemd.sh
source ./modules/deploy/05c-deploy-nginx-http.sh
source ./modules/deploy/05d-deploy-ssl.sh
source ./modules/deploy/05e-deploy-backup.sh
source ./modules/deploy/05f-deploy-summary.sh