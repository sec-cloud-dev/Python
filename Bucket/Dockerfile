FROM python:3.11-slim
WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt && \
    rm -rf /root/.cache/pip

COPY . .

RUN useradd -m -u 1001 appuser
USER appuser

CMD ["python", "-m", "src.main"]