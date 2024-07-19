# FROM python:3.8.5 as base
FROM ubuntu:20.04 as base
ENV PYTHONUNBUFFERED 1
ENV TZ=Europe/London
ENV DEBIAN_FRONTEND="noninteractive"

RUN apt-get update && \
    apt-get install -y \
    easy-rsa \
    python3-pip \
    docker.io \
    vim

WORKDIR /app
COPY ./requirements.txt requirements.txt
RUN pip3 install -r requirements.txt

FROM base as release
WORKDIR /app/src
# COPY /src .


# env var to detect we are in a docker instance
ENV APP_ENV=docker
EXPOSE 5005
CMD [ "python3", "main.py"]