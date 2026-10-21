FROM node:22-alpine
WORKDIR /app
COPY package.json server.mjs index.html ./
ENV PORT=3000 DB_PATH=/data/game.db
EXPOSE 3000
CMD ["node", "server.mjs"]
