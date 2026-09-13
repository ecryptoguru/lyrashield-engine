# Synthetic AI-built-app fixture — IaC clean projection.
FROM node:20-alpine  # CASE:IAC-01 clean
RUN addgroup  # CASE:IAC-02 clean -S app && adduser -S app -G app
COPY . /app
WORKDIR /app
USER app  # CASE:IAC-03/04 clean
CMD ["node", "server.js"]
