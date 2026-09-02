FROM debian:bookworm-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        ca-certificates \
        git \
        perl \
        libnet-ssleay-perl \
        libxml-writer-perl \
        libjson-perl && \
    rm -rf /var/lib/apt/lists/* && \
    git clone --depth 1 https://github.com/sullo/nikto.git /opt/nikto

WORKDIR /opt/nikto/program

ENTRYPOINT ["perl", "/opt/nikto/program/nikto.pl"]
