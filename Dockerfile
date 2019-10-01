FROM python:3.7.4-alpine3.10

COPY requirements.txt /ops-web/requirements.txt

RUN /sbin/apk add --no-cache --virtual .deps gcc libffi-dev musl-dev postgresql-dev \
 && /sbin/apk add --no-cache libpq openssl-dev \
 && /usr/local/bin/pip install --no-cache-dir --requirement /ops-web/requirements.txt \
 && /sbin/apk del --no-cache .deps

ENV APP_VERSION="0.9.6" \
    AUTO_SYNC="true" \
    AUTO_SYNC_INTERVAL="10" \
    AWS_ACCESS_KEY_ID="" \
    AWS_DEFAULT_REGION="us-west-2" \
    AWS_SECRET_ACCESS_KEY="" \
    AZ_CLIENT_ID="" \
    AZ_CLIENT_SECRET="" \
    AZ_TENANT_ID="" \
    BOOTSTRAP_ADMIN="" \
    CLOUDS_TO_SYNC="aws az" \
    DB="" \
    DEBUG_LAYOUT="false" \
    FEATURE_FLAGS="" \
    LOG_FORMAT="%(levelname)s [%(name)s] %(message)s" \
    LOG_LEVEL="INFO" \
    OTHER_LOG_LEVELS="" \
    PERMANENT_SESSIONS="false" \
    POWER_CONTROL_DOMAIN="example.com" \
    PYTHONUNBUFFERED="1" \
    REP_SC_PAIRS_DB="" \
    RESET_DATABASE="false" \
    SCHEME="http" \
    SECRET_KEY="" \
    SUPPORT_EMAIL="" \
    TZ="Etc/UTC"

ENTRYPOINT ["/usr/local/bin/python"]
CMD ["/ops-web/run.py"]

LABEL org.opencontainers.image.authors="William Jackson <wjackson@informatica.com>" \
      org.opencontainers.image.version=${APP_VERSION}

COPY . /ops-web
