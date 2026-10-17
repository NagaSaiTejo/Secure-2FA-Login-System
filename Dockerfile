FROM node:20-alpine

WORKDIR /app

# Install curl for container health check
RUN apk add --no-cache curl

# Copy dependency manifests
COPY package*.json ./

# Install production dependencies
RUN npm install --omit=dev

# Copy application source and assets
COPY src/ ./src/
COPY public/ ./public/
COPY submission.json ./submission.json

# Expose default HTTP port
EXPOSE 3000

# Default environment variables (can be overridden by docker-compose)
ENV PORT=3000
ENV NODE_ENV=production

# Start the application
CMD ["node", "src/server.js"]
