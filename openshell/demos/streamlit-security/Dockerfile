FROM python:3.12-slim

WORKDIR /opt/openshell-demo
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
RUN chown 1500:1500 /opt/openshell-demo
COPY --chown=1500:1500 app.py model_client.py ./
RUN printf '%s\n' 'demo-file-read-marker-not-a-real-secret' > /opt/openshell-demo-secret \
    && chown 1500:1500 /opt/openshell-demo-secret \
    && chmod 0400 /opt/openshell-demo-secret
USER 1500:1500

ENV PYTHONUNBUFFERED=1 \
    DEMO_MODE=safe \
    MODEL_BASE_URL=https://api.openai.com/v1 \
    DEMO_MARKER=demo-not-a-real-secret

EXPOSE 8501
CMD ["/usr/local/bin/python3.12", "-m", "streamlit", "run", "/opt/openshell-demo/app.py", "--server.port=8501", "--server.address=0.0.0.0", "--server.headless=true"]
