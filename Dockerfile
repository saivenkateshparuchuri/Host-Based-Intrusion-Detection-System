FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source
COPY . .

ENV HIDS_HOST=0.0.0.0
ENV HIDS_PORT=5055
ENV PYTHONUNBUFFERED=1

EXPOSE 5055

CMD ["gunicorn", "--workers", "1", "--threads", "4", "--bind", "0.0.0.0:5055", "web.app:create_app()"]
