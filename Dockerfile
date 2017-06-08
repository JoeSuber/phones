FROM python:3.6-onbuild

EXPOSE 5000

CMD gunicorn app:app --log-file --bind 0.0.0.0