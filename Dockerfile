FROM python:3.8.3-alpine3.12

RUN /sbin/apk add --no-cache libpq openssl-dev samba-client

COPY requirements.txt /ops-web/requirements.txt

RUN /sbin/apk add --no-cache --virtual .deps gcc libffi-dev make musl-dev postgresql-dev \
 && /usr/local/bin/pip install --no-cache-dir --requirement /ops-web/requirements.txt \
 && /sbin/apk del --no-cache .deps

ENV APP_VERSION="2020.17" \
    PYTHONUNBUFFERED="1" \
    TZ="Etc/UTC"

ENTRYPOINT ["/usr/local/bin/python"]
CMD ["/ops-web/run.py"]

LABEL org.opencontainers.image.authors="William Jackson <wjackson@informatica.com>" \
      org.opencontainers.image.version="${APP_VERSION}"

COPY . /ops-web
