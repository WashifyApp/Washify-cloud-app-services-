# auth_service/Dockerfile

```dockerfile
# ============================================
# BUILD STAGE
# ============================================

FROM python:3.9-slim AS builder

WORKDIR /app

RUN apt-get update && \
    apt-get install -y gcc && \
    rm -rf /var/lib/apt/lists/*

RUN python -m venv /opt/venv

ENV PATH="/opt/venv/bin:$PATH"

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

# ============================================
# RUNTIME STAGE
# ============================================

FROM python:3.9-slim

RUN groupadd -r appuser && \
    useradd -r -g appuser appuser

WORKDIR /app

COPY --from=builder /opt/venv /opt/venv

ENV PATH="/opt/venv/bin:$PATH"

COPY . .

RUN chown -R appuser:appuser /app

USER appuser

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
```
