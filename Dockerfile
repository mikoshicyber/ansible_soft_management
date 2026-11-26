ARG BASE_IMAGE=quay.io/ansible/awx-ee:latest
FROM ${BASE_IMAGE}

USER 0

RUN dnf install -y dnf-plugins-core \
    && dnf config-manager --set-enabled crb \
    && dnf install -y epel-release epel-next-release \
    && dnf install -y msitools-0.102-3.el9 \
    && dnf clean all \
    && rm -rf /var/cache/dnf

RUN /usr/bin/python3.12 -m pip install --no-cache-dir pefile==2024.8.26 \
    && msiinfo --help \
    && /usr/bin/python3.12 -c 'import pefile'

USER 1000:0
