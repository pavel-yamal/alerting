# Образ узла alerting: сервер и три CLI в одном пакете.
#
# Запускается от непривилегированного пользователя с фиксированным uid 10001: файлы
# секретов в томах принадлежат именно ему с правами 0400, а сервер отказывается
# читать секрет, доступный группе или остальным.

FROM python:3.11-slim-bookworm AS build
WORKDIR /src
COPY pyproject.toml README.md ./
COPY src ./src
# Если pypi.org недоступен (обрыв соединения, фильтр) — зеркало или внутренний
# Nexus/Artifactory. pip читает эти переменные сам; без --build-arg они не заданы.
#   docker build --build-arg PIP_INDEX_URL=https://mirror/simple .
ARG PIP_INDEX_URL
ARG PIP_TRUSTED_HOST
# За корпоративным TLS-прокси pip не доверяет его сертификату. CA передаётся
# секретом сборки и в образ не попадает:
#   docker build --secret id=ca,src=/path/corp-ca.crt .
RUN --mount=type=secret,id=ca,required=false \
    if [ -s /run/secrets/ca ]; then export PIP_CERT=/run/secrets/ca; fi; \
    pip install --no-cache-dir --prefix=/install .

FROM python:3.11-slim-bookworm
COPY --from=build /install /usr/local
WORKDIR /opt/alerting
COPY config ./config
COPY scripts ./scripts
COPY src ./src

RUN useradd --system --uid 10001 --home-dir /var/lib/alerting --shell /usr/sbin/nologin alerting \
    && install -d -o alerting -g alerting -m 0700 \
        /var/lib/alerting /var/lib/alerting/heads /var/lib/alerting/spool \
        /var/lib/alerting/clients /var/lib/alerting/demo-keys /var/lib/alerting/panel \
        /run/alerting-app /run/alerting-owner

# Все пути абсолютные: относительные отказывают молча (docs/09-deployment.md §4).
ENV PYTHONUNBUFFERED=1 \
    ALERTING_WORDLIST=/opt/alerting/config/wordlist.ru.txt \
    ALERTING_ESCALATION_CONFIG=/opt/alerting/config/escalation.example.yaml \
    ALERTING_HEADS_DIR=/var/lib/alerting/heads \
    ALERTING_SPOOL_DIR=/var/lib/alerting/spool

USER alerting
EXPOSE 8080

HEALTHCHECK --interval=15s --timeout=5s --start-period=20s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/v1/readyz', timeout=4).status == 200 else 1)"

ENTRYPOINT ["alerting-server"]
CMD ["serve", "--host", "0.0.0.0", "--port", "8080"]
