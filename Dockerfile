FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    libzbar0 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

ENV FLASK_APP=app.py

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
    && pip install --no-cache-dir mysql-connector-python

COPY app.py .
COPY templates/ templates/
COPY static/ static/
COPY migrations/ migrations/

VOLUME ["/data"]

EXPOSE 5000

CMD ["sh", "-c", "flask db upgrade && python app.py"]
