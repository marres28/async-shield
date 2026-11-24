FROM python:3.12-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

COPY pyproject.toml README.md LICENSE ./
COPY shield ./shield
COPY demo ./demo
COPY tests ./tests

RUN pip install --no-cache-dir ".[dev]"

CMD ["python", "demo/attack_scenario.py", "--mode=protected"]
