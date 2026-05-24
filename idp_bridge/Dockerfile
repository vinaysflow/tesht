FROM python:3.11-slim

WORKDIR /app

RUN pip install --no-cache-dir \
    fastapi \
    uvicorn[standard] \
    httpx \
    pyjwt \
    cryptography \
    pyyaml

COPY sdk/python /app/sdk/python
COPY idp_bridge /app/idp_bridge

ENV PYTHONPATH=/app/sdk/python:/app

EXPOSE 5053

CMD ["python", "-m", "uvicorn", "idp_bridge.app:app", "--host", "0.0.0.0", "--port", "5053"]
