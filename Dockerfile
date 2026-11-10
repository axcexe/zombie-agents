FROM python:3.12-slim-bookworm
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PYTHONIOENCODING=utf-8
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY zombie_agents ./zombie_agents
ENTRYPOINT ["python", "-m", "zombie_agents"]
CMD ["--check", "--out", "/app/results"]
