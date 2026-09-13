# Synthetic AI-built-app fixture — IaC clean projection.
# CASE:IAC-01 clean: pinned base image
FROM node:20-alpine@sha256:fb4cd12c85ee03686f6af5362a0b0d56d50c58a04632e6c0fb8363f609372293
# CASE:IAC-02 clean: no remote installer
RUN addgroup -S app && adduser -S app -G app
COPY . /app
WORKDIR /app
# CASE:IAC-03/04 clean
USER app
CMD ["node", "server.js"]
