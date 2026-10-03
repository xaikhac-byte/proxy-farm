FROM python:3.12-alpine
RUN apk add --no-cache docker-cli curl openssl
WORKDIR /app
COPY farm.py providers.py presets.json countries.json locations.json ui.html /app/
COPY flags /app/flags
LABEL proxy-farm=manager
ENTRYPOINT ["python3", "farm.py", "serve"]
