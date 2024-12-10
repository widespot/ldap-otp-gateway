ARG PYTHON_TAG=3.11-alpine

FROM python:${PYTHON_TAG} AS build

RUN apk add --no-cache \
        gcc \
        libressl-dev \
        musl-dev \
        libffi-dev

# We need to update wget, as the Alpine binary is really lightweight, and doesn't work very
# well with proxy.
# https://github.com/gliderlabs/docker-alpine/issues/259#issuecomment-284684923
RUN wget --help
RUN apk add wget
RUN wget --help

RUN wget https://install.python-poetry.org -O install.py
RUN python3 install.py

FROM python:${PYTHON_TAG}

COPY --from=build /root/.local/ /root/.local/

# add Poetry install path
ENV PATH="/root/.local/bin:$PATH"

# Poetry will use Dulwich library to load git dependencies without git CLI
# The library unfortunately doesn't work with secured proxy. We therefore
# need to fall back on the native git CLI. This option of Poetry is enabled
# using the POETRY_EXPERIMENTAL_SYSTEM_GIT_CLIENT environment variable
#RUN apk add --no-cache git
#ENV POETRY_EXPERIMENTAL_SYSTEM_GIT_CLIENT=true

RUN poetry config virtualenvs.create false
WORKDIR /opt/ldap-otp-gateway
RUN mkdir certs
COPY . .
RUN poetry install --with peer

ENTRYPOINT ["python", "-m", "ldap_otp_gateway.run"]
