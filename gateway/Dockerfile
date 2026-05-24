FROM python:3.11-slim

WORKDIR /app

# Install runtime dependencies
RUN pip install --no-cache-dir \
    fastapi \
    uvicorn[standard] \
    httpx \
    pyjwt \
    cryptography \
    pyyaml

# Copy SDK and gateway source
COPY sdk/python /app/sdk/python
COPY gateway /app/gateway

ENV PYTHONPATH=/app/sdk/python:/app

EXPOSE 5052

CMD ["python", "-m", "uvicorn", "gateway.app:app", "--host", "0.0.0.0", "--port", "5052"]
