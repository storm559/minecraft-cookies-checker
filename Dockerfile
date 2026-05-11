FROM python:3.11-slim AS base

WORKDIR /app

RUN groupadd -r checker && useradd -r -g checker checker

COPY pyproject.toml ./
RUN pip install --no-cache-dir .

COPY src/ src/
RUN pip install --no-cache-dir .

RUN mkdir -p /app/data && chown -R checker:checker /app/data

USER checker

EXPOSE 8080

ENTRYPOINT ["minecookiechecker"]
CMD ["--help"]
