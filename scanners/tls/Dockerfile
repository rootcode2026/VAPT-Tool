FROM drwetter/testssl.sh:3.2

USER root
COPY entrypoint.sh /usr/local/bin/vapt-tls-entrypoint.sh
RUN chmod 755 /usr/local/bin/vapt-tls-entrypoint.sh

USER testssl
ENTRYPOINT ["/usr/local/bin/vapt-tls-entrypoint.sh"]
