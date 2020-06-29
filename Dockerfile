# The first set of instructions is for building the latest version of pendulum
# Working around this issue: https://github.com/sdispater/pendulum/issues/454

FROM python:3.8.3-alpine3.12 AS pendulum-builder
RUN /sbin/apk add --no-cache curl gcc git musl-dev
WORKDIR /root
RUN /usr/bin/git clone --branch 2.1.0 --depth 1 https://github.com/sdispater/pendulum.git
RUN /usr/bin/curl --location https://raw.githubusercontent.com/python-poetry/poetry/master/get-poetry.py --output /root/get-poetry.py
RUN /usr/local/bin/python /root/get-poetry.py
WORKDIR /root/pendulum
RUN /root/.poetry/bin/poetry build

# Done building pendulum

FROM python:3.8.3-alpine3.12

# Next two lines installs pendulum from the wheel we built previously
COPY --from=pendulum-builder /root/pendulum/dist/pendulum-2.1.0-cp38-cp38-linux_x86_64.whl /wheel-cache/pendulum-2.1.0-cp38-cp38-linux_x86_64.whl
RUN /usr/local/bin/pip install --no-cache-dir /wheel-cache/pendulum-2.1.0-cp38-cp38-linux_x86_64.whl

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
