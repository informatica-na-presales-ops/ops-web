#!/bin/sh

/sbin/apk add --no-cache git
/usr/local/bin/pip install --no-cache-dir --requirement .devcontainer/requirements.txt
