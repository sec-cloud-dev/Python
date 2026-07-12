FROM python:3.11-slim
WORKDIR /app

COPY requirements.txt .
RUN pip install --upgrade pip==25.0.1 && \
    pip install --no-cache-dir -r requirements.txt && \
    rm -rf /root/.cache/pip

COPY chels.py .

RUN useradd -m -u 1001 appuser
USER appuser

CMD ["python", "chels.py"]
