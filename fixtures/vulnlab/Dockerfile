FROM node:latest
ARG NPM_TOKEN=npm_secret_value_1234567890
ENV API_KEY=sk-live-abcdefghijklmnopqrstuvwxyz
WORKDIR /app
ADD . .
RUN curl -fsSL https://example.com/install.sh | sh
RUN npm install
EXPOSE 3000
EXPOSE 22
CMD ["node", "src/app.js"]
