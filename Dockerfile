FROM python:3.13-slim

WORKDIR /credenza

COPY pyproject.toml ./

RUN pip install --upgrade pip setuptools build \
 && pip install --no-cache-dir gunicorn .

COPY credenza ./credenza

ENV PYTHONPATH=/credenza
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

CMD ["gunicorn", "--workers", "1", "--threads", "4", "--bind", "0.0.0.0:8999", "credenza.credenza_wsgi:application"]
