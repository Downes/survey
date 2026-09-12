FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

VOLUME ["/data"]

EXPOSE 8085

CMD ["gunicorn", "--bind", "0.0.0.0:8085", "--workers", "1", "--timeout", "30", "wsgi:application"]
