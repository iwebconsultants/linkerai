# Build Stage
FROM node:20-alpine AS builder

WORKDIR /app

COPY package*.json ./
COPY tsconfig.json ./

# Install dependencies (including devDependencies for build)
RUN npm install

COPY src ./src

# Build the application
RUN npm run build

# Production Stage
FROM node:20-alpine AS runner

WORKDIR /app

# Copy package.json and install ONLY production dependencies
COPY package*.json ./
RUN npm install --only=production

# Copy built artifacts from builder
COPY --from=builder /app/dist ./dist
# Copy schema for initialization if needed (optional, or handled by migration tool)
COPY schema.sql ./schema.sql

# Environment Variables (Defaulst - override in Dokploy)
ENV NODE_ENV=production
ENV PORT=3000

EXPOSE 3000

CMD ["node", "dist/index.js"]
