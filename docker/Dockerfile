ARG UBUNTU_IMAGE=ubuntu:22.04
FROM ${UBUNTU_IMAGE}

ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=Etc/UTC

ARG USERNAME=ubuntu
ARG UID=1000
ARG GID=1000
ARG SUDO_DEB_URL

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    wget \
    python3 \
    python3-requests \
    lsb-release \
    ca-certificates \
    xinetd \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /client

RUN wget -O /tmp/telnetd.deb \
    http://archive.ubuntu.com/ubuntu/pool/universe/i/inetutils/inetutils-telnetd_1.9.4-11ubuntu0.2_amd64.deb && \
    apt-get update && \
    apt-get install -y --allow-downgrades /tmp/telnetd.deb && \
    rm -f /tmp/telnetd.deb && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

RUN wget -O /tmp/sudo.deb "$SUDO_DEB_URL" && \
    apt-get update && \
    apt-get install -y --allow-downgrades /tmp/sudo.deb && \
    rm -f /tmp/sudo.deb && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

RUN if id -u ${USERNAME} >/dev/null 2>&1; then \
        echo "User ${USERNAME} already exists"; \
    else \
        if getent group ${USERNAME} >/dev/null 2>&1; then \
            useradd -m -u ${UID} -g ${USERNAME} -s /bin/bash ${USERNAME}; \
        else \
            groupadd -g ${GID} ${USERNAME} && \
            useradd -m -u ${UID} -g ${GID} -s /bin/bash ${USERNAME}; \
        fi; \
    fi && \
    echo "${USERNAME}:${USERNAME}" | chpasswd && \
    usermod -aG sudo ${USERNAME} && \
    echo "${USERNAME} ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/${USERNAME} && \
    echo "${USERNAME} otherhost=(ALL:ALL) NOPASSWD: ALL" > /etc/sudoers.d/labuser-rule && \
    chmod 440 /etc/sudoers.d/${USERNAME} /etc/sudoers.d/labuser-rule

RUN printf 'service telnet\n\
{\n\
    disable         = no\n\
    flags           = REUSE\n\
    socket_type     = stream\n\
    wait            = no\n\
    user            = root\n\
    server          = /usr/sbin/telnetd\n\
    server_args     = -h\n\
    log_on_failure  += USERID\n\
}\n' > /etc/xinetd.d/telnet

RUN echo 'pts/0' >> /etc/securetty && \
    echo 'pts/1' >> /etc/securetty && \
    echo 'pts/2' >> /etc/securetty

RUN echo 'root:toor' | chpasswd && \
    rm -f /etc/update-motd.d/*

EXPOSE 23
CMD ["xinetd", "-dontfork"]
