# Gitline in a container — no Node install needed on the host.
#
#   docker build -t gitline .
#   docker run --rm -p 9292:9292 gitline
#
# Then open http://localhost:9292, or http://<this-machine-ip>:9292 from
# anywhere on the network. Scanning happens in the browser that loads the
# page, so the container never sees your token.
FROM node:20-alpine

WORKDIR /app
COPY . .

# serve.js binds 0.0.0.0 so the port is reachable from outside the container.
EXPOSE 9292

# Nothing here needs root, and the base image already ships a `node` user.
USER node

CMD ["node", "serve.js"]
