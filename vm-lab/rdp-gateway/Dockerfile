FROM node:22-alpine
WORKDIR /app
COPY package*.json ./
RUN npm ci --omit=dev
# Every module server.js requires at runtime. Copying only server.js
# leaves the container to fail at startup with MODULE_NOT_FOUND.
COPY server.js connectionStore.js labApi.js browserToken.js ./
COPY public ./public
USER node
EXPOSE 8080 8081
CMD ["node", "server.js"]
