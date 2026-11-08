#!/bin/bash
set -e

echo "Detectando Public IP..."

PUBLIC_IP=$(curl -s https://api.ipify.org)

if [ -z "$PUBLIC_IP" ]; then
    echo "ERROR: No fue posible obtener la Public IP."
    exit 1
fi

echo "Public IP detectada: $PUBLIC_IP"

export N8N_HOST="$PUBLIC_IP"
export N8N_WEBHOOK_URL="http://${PUBLIC_IP}:5678/"
export N8N_EDITOR_BASE_URL="http://${PUBLIC_IP}:5678/"

echo "Iniciando n8n..."

docker compose up -d

echo ""
echo "============================================"
echo " DIMA AI Agent Security Lab"
echo "============================================"
echo ""
echo "n8n:"
echo "http://${PUBLIC_IP}:5678"
echo ""
echo "Public IP: $PUBLIC_IP"
echo "============================================"
