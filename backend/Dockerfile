# Base image - Node 20 required by AWS SDK
FROM node:20-slim

# Install OpenSSL for Prisma
RUN apt-get update -y && apt-get install -y openssl && rm -rf /var/lib/apt/lists/*

# Create app directory
WORKDIR /app

# Database URL should be provided at runtime via Cloud Run environment variables
# ENV DATABASE_URL="postgresql://..."
ENV JWT_SECRET="super-secure-production-key"

# Copy dependency definitions
COPY package*.json ./

# Install dependencies (includes devDependencies for Prisma CLI)
RUN npm install

# Copy Prisma schema
COPY prisma ./prisma/

# Generate Prisma Client
RUN npx prisma generate

# Note: We do not run prisma db push here because DATABASE_URL is not available during build.
# It will be executed at runtime instead.

# Copy the rest of the application
COPY . .

# Expose port (Cloud Run defaults to 8080)
EXPOSE 8080
ENV PORT=8080
# Give Node.js more heap memory for heavy GCP/AWS scanning
ENV NODE_OPTIONS="--max-old-space-size=768"

# Command to run the application
CMD [ "node", "server.js" ]
