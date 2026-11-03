FROM python:3.12-slim@sha256:b18b261e1b4974b4f321451ad5251ded85abb22c2b8b262da527dda1d031ab30
RUN pip install --no-cache-dir cryptography==50.0.0
WORKDIR /app
COPY config_server.py /app/config_server.py
USER 10001:10001
ENTRYPOINT ["python", "-B", "/app/config_server.py", "--bind", "0.0.0.0", "--data-dir", "/data"]
