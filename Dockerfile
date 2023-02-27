FROM python:3.10-bullseye

ENV PYTHONUNBUFFERED 1
RUN mkdir /PANOpticon
WORKDIR /PANOpticon
COPY . /PANOpticon
# RUN apt add --update --no-cache postgresql-client jpeg-dev
# RUN apt add --update --no-cache --virtual .tmp-build-deps gcc libc-dev linux-headers postgresql-dev musl-dev zlib zlib-dev
RUN pip install -r requirements.txt