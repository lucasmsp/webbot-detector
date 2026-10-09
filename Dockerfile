FROM python:3.12-slim
LABEL maintainer="Lucas Miguel S. Ponce <lucasmsp@gmail.com>"
LABEL description="Bot Detection & Risk Assessment Server"

WORKDIR /app
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PORT=8000

# Install Chromium, ChromeDriver, Firefox ESR, and Geckodriver for automation testing
RUN apt-get update && apt-get install -y --no-install-recommends \
    chromium \
    chromium-driver \
    firefox-esr \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && ln -sf /usr/bin/chromium /usr/bin/google-chrome \
    && ln -sf /usr/bin/firefox-esr /usr/bin/firefox \
    && python3 -c 'import urllib.request, tarfile, io, os; \
url = "https://github.com/mozilla/geckodriver/releases/download/v0.37.1/geckodriver-v0.37.1-linux64.tar.gz"; \
req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"}); \
resp = urllib.request.urlopen(req); \
tar = tarfile.open(fileobj=io.BytesIO(resp.read()), mode="r:gz"); \
tar.extractall("/usr/local/bin"); \
os.chmod("/usr/local/bin/geckodriver", 0o755)'

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY run_server.py .
COPY backend/ ./backend/
COPY frontend/ ./frontend/
COPY pytest.ini .
COPY tests/ ./tests/

RUN mkdir -p backend/logs

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD python3 -c 'import urllib.request, os; urllib.request.urlopen(f"http://localhost:{os.environ.get(\"PORT\", 8000)}/api/health")' || exit 1

CMD ["python3", "run_server.py"]
