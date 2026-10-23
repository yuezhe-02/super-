FROM node:24-alpine
WORKDIR /app
COPY --chown=node:node package.json server.mjs index.html ./
COPY --chown=node:node server ./server
RUN mkdir -p /data/uploads && chown -R node:node /data
ENV NODE_ENV=production DATA_DIR=/data PORT=3000
USER node
EXPOSE 3000
CMD ["node", "server.mjs"]
