FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
RUN useradd --system --uid 10001 --home /app riskbyte
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY riskbyte ./riskbyte
COPY rules ./rules
COPY intel ./intel
RUN mkdir /data && chown riskbyte /data
USER riskbyte
ENV RISKBYTE_DATA_DIR=/data RISKBYTE_RULES_DIR=/app/rules RISKBYTE_INTEL_FILE=/app/intel/indicators.txt
EXPOSE 8080 5514/udp
HEALTHCHECK --interval=30s --timeout=5s CMD python -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8080/healthz')"
CMD ["python", "-m", "riskbyte", "serve"]
