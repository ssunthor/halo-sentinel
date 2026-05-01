#!/bin/sh

# This script is used to inject environment variables into the frontend at runtime.
# It creates a file called env-config.js in the web root.

ENV_CONFIG_FILE="/usr/share/nginx/html/env-config.js"

echo "window._env_ = {" > $ENV_CONFIG_FILE

# List of variables to inject
VARS="VITE_API_BASE_URL VITE_WS_URL VITE_SHOW_OVERVIEW VITE_SHOW_HOST_INVENTORY VITE_SHOW_GALAXY VITE_SHOW_DESTINATIONS VITE_SHOW_LOG_DNA VITE_SHOW_NETFLOW_DNA VITE_SHOW_USER_ACTIVITY VITE_SHOW_HOST_FORENSICS VITE_SHOW_NETWORK VITE_SHOW_NETBOX VITE_SHOW_RAW_DATA VITE_SHOW_CONFIG_ANALYZER VITE_SHOW_CONFIG_TRANSLATOR VITE_SHOW_CONFIG_BUILD_TOOL"

for varname in $VARS; do
    # Get value of the variable
    eval varvalue=\$$varname
    
    # Only add to the config if it's not empty
    if [ -n "$varvalue" ]; then
        echo "  $varname: \"$varvalue\"," >> $ENV_CONFIG_FILE
    fi
done

echo "};" >> $ENV_CONFIG_FILE

echo "Generated $ENV_CONFIG_FILE"

# --- NEW: Inject variables into Nginx Config ---
# Ensure BACKEND_URL has a default if not set
# For local docker-compose dev, use 'backend:5174'
# For K8s single deployment (sidecar/local), override this to '127.0.0.1:5174'
if [ -z "$BACKEND_URL" ]; then
    export BACKEND_URL="backend:5174"
fi

if [ -z "$CONFIG_ANALYZER_URL" ]; then
    export CONFIG_ANALYZER_URL="config-analyzer:8010"
fi

# Use envsubst to replace variables in the nginx configs
# We use a temporary file to avoid overwriting the source if it's mounted
envsubst '${BACKEND_URL} ${CONFIG_ANALYZER_URL}' < /etc/nginx/conf.d/default.conf > /etc/nginx/conf.d/default.conf.tmp
mv /etc/nginx/conf.d/default.conf.tmp /etc/nginx/conf.d/default.conf

echo "Nginx config updated with BACKEND_URL=${BACKEND_URL} and CONFIG_ANALYZER_URL=${CONFIG_ANALYZER_URL}"

# Start Nginx
exec nginx -g "daemon off;"
