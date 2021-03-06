FROM python:3.9.2-alpine3.13

RUN /sbin/apk add --no-cache libpq openssl-dev

COPY requirements.txt /ops-web/requirements.txt

RUN /usr/local/bin/pip install --no-cache-dir --requirement /ops-web/requirements.txt

ENV APP_VERSION="2021.13" \
    ELASTIC_APM_ENABLED="false" \
    PYTHONUNBUFFERED="1" \
    TZ="Etc/UTC"

ENTRYPOINT ["/usr/local/bin/python"]
CMD ["/ops-web/run.py"]

LABEL org.opencontainers.image.authors="William Jackson <wjackson@informatica.com>" \
      org.opencontainers.image.version="${APP_VERSION}"

COPY . /ops-web
