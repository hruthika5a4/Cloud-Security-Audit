# Build Environment
FROM node:18-alpine as builder

WORKDIR /app

# Copy package dependencies
COPY package*.json ./

# Install packages
RUN npm install

# Copy source code
COPY . .

# Build the app using Vite
RUN npm run build

# Production Environment
FROM nginx:alpine

# Copy custom nginx config
COPY nginx.conf /etc/nginx/conf.d/default.conf

# Copy build files from builder stage
COPY --from=builder /app/dist /usr/share/nginx/html

# Expose port 8080 (Cloud Run default)
EXPOSE 8080

CMD ["nginx", "-g", "daemon off;"]
