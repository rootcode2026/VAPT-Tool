FROM projectdiscovery/dnsx:v1.2.2

COPY entrypoint.sh /usr/local/bin/vapt-dns-entrypoint.sh
RUN chmod 755 /usr/local/bin/vapt-dns-entrypoint.sh

ENTRYPOINT ["/usr/local/bin/vapt-dns-entrypoint.sh"]
