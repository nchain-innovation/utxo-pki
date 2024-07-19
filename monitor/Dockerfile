FROM python:3.12-slim as base
ENV PYTHONUNBUFFERED 1
ENV TZ=Europe/London

RUN apt-get update && \
    apt-get install -y \
    easy-rsa \
    curl \
    build-essential python3-dev \
    && rm -rf /var/lib/apt/lists/*

    # Install pip and necessary Python packages
RUN pip3 install --upgrade pip setuptools wheel Cython

# Install Rust and Cargo using rustup
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y

# Ensure that the "cargo" and "rustc" binaries are in the PATH
ENV PATH="/root/.cargo/bin:${PATH}"

WORKDIR /app
COPY ./requirements.txt requirements.txt
RUN pip3 install -r requirements.txt


FROM base as release

RUN mkdir -p /app/src
COPY ./src /app/src
WORKDIR /app/src

# remove any unwanted files
RUN rm -rf __pycache__
RUN rm -f *.dat

# env var to detect we are in a docker instance
ENV APP_ENV=docker
EXPOSE 5003
CMD [ "python3", "main.py"]
