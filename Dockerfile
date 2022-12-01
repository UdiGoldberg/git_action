FROM python:latest

COPY npm_audit.py /npm_audit.py
COPY entrypoint.sh /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
