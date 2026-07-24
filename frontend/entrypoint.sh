#!/bin/sh

ENV_CONFIG_FILE="/usr/share/nginx/html/env-config.js"

echo "window._env_ = {" > $ENV_CONFIG_FILE

VARS="VITE_API_BASE_URL"

for varname in $VARS; do
    eval "varvalue=\$$varname"
    if [ -n "$varvalue" ]; then
        echo "  $varname: \"$varvalue\"," >> $ENV_CONFIG_FILE
    fi
done

echo "};" >> $ENV_CONFIG_FILE

echo "Generated $ENV_CONFIG_FILE"

if [ -z "$BACKEND_URL" ]; then
    export BACKEND_URL="backend:5174"
fi

# shellcheck disable=SC2016  # single quotes are intentional: envsubst needs the literal ${BACKEND_URL}
envsubst '${BACKEND_URL}' < /etc/nginx/conf.d/default.conf > /etc/nginx/conf.d/default.conf.tmp
mv /etc/nginx/conf.d/default.conf.tmp /etc/nginx/conf.d/default.conf

echo "Nginx config updated with BACKEND_URL=${BACKEND_URL}"

exec nginx -g "daemon off;"
