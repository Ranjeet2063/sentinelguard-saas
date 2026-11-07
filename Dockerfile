# Multi-stage lightweight production Dockerfile
FROM node:22-alpine AS builder

WORKDIR /app
RUN npm install -g pnpm

COPY package.json tsconfig.json pnpm-workspace.yaml ./
RUN pnpm install --frozen-lockfile=false

COPY src/ ./src/
RUN pnpm build

FROM node:22-alpine AS runner

WORKDIR /app
ENV NODE_ENV=production
RUN npm install -g pnpm

COPY package.json pnpm-workspace.yaml ./
RUN pnpm install --prod --frozen-lockfile=false

COPY --from=builder /app/dist ./dist

EXPOSE 3000

CMD ["node", "dist/server.js"]
