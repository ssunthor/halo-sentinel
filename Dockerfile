# --- Stage 1: Build the React App ---
FROM node:20-alpine AS build
WORKDIR /app

# Copy ONLY package.json first to leverage caching
COPY package.json ./

# We use 'install' instead of 'ci' because the lockfile is out of sync.
# This will generate a fresh dependency tree inside the container.
RUN npm install --legacy-peer-deps

# Now copy the rest of the source (including your local lockfile, 
# which will be ignored because node_modules already exists)
COPY . .

# Build the static files
RUN npm run build

# --- Stage 2: Serve with Nginx ---
FROM nginx:alpine
COPY --from=build /app/dist /usr/share/nginx/html
COPY nginx/default.conf /etc/nginx/conf.d/default.conf
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 80
ENTRYPOINT ["/entrypoint.sh"]
