FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /srv
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN chmod +x start.sh
# Non-root user; only data/ is writable (SQLite lives there).
RUN useradd --create-home --uid 10001 appuser && mkdir -p data && chown -R appuser /srv/data
USER appuser
EXPOSE 8000
CMD ["./start.sh"]
