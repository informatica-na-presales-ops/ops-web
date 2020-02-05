FROM python:3.8.1-alpine3.11

COPY requirements.txt /ops-web/requirements.txt

RUN /sbin/apk add --no-cache --virtual .deps gcc libffi-dev make musl-dev postgresql-dev \
 && /sbin/apk add --no-cache libpq openssl-dev samba-client \
 && /usr/local/bin/pip install --no-cache-dir --requirement /ops-web/requirements.txt \
 && /sbin/apk del --no-cache .deps

ENV APP_VERSION="2020.1" \
    AUTO_SYNC="true" \
    AUTO_SYNC_INTERVAL="10" \
    AWS_IGNORED_SECURITY_GROUPS="" \
    AWS_SES_CONFIGURATION_SET="" \
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
    RESET_DATABASE="false" \
    SCHEME="http" \
    SECRET_KEY="" \
    SEND_EMAIL="False" \
    SERVER_NAME="" \
    SMTP_FROM="" \
    SMTP_HOST="" \
    SMTP_PASSWORD="" \
    SMTP_USERNAME="" \
    SUPPORT_EMAIL="" \
    TZ="Etc/UTC" \
    WEB_SERVER_THREADS="4" \
    ZENDESK_WIDGET_KEY=""

ENTRYPOINT ["/usr/local/bin/python"]
CMD ["/ops-web/run.py"]

LABEL org.opencontainers.image.authors="William Jackson <wjackson@informatica.com>" \
      org.opencontainers.image.version="${APP_VERSION}"

COPY . /ops-web
