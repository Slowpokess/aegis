FROM python:3.12.4-slim@sha256:a3e58f9399353be051735f09be0316bfdeab571a5c6a24fd78b92df85bcb2d85

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/aegis/.venv/bin:${PATH}"

WORKDIR /opt/aegis

RUN python -m venv /opt/aegis/.venv
COPY requirements.txt /tmp/lab-requirements.txt
RUN python -m pip install --no-cache-dir --requirement /tmp/lab-requirements.txt \
    && addgroup --system --gid 10001 aegis \
    && adduser --system --uid 10001 --ingroup aegis --no-create-home aegis

COPY --chown=aegis:aegis . /opt/aegis/lab/vulnerable_api

USER 10001:10001
EXPOSE 8001

CMD ["python", "-m", "uvicorn", "lab.vulnerable_api.main:app", "--host", "0.0.0.0", "--port", "8001"]
