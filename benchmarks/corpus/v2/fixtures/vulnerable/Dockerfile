# Synthetic AI-built-app fixture — IaC cases.
FROM node:latest  # CASE:IAC-01
RUN curl https://fixture-installer.invalid/setup.sh | sh  # CASE:IAC-02
ENV DATABASE_PASSWORD=fixture-secret-placeholder-iac01  # CASE:IAC-03
COPY . /app
WORKDIR /app
CMD ["node", "server.js"]  # CASE:IAC-04 — absence case: no USER directive
