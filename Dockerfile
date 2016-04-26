FROM centos:6

#ENV LANG en_US.UTF-8
#ENV LC_ALL en_US.UTF-8
ADD ocserv-install-centos6.sh /
ADD ocserv /etc/init.d

#ENV LD_LIBRARY_PATH=/usr/local/lib
RUN chmod +x /ocserv-install-centos6.sh && /ocserv-install-centos6.sh

CMD ["/usr/local/sbin/ocserv", "-c", "/usr/local/etc/ocserv/ocserv.conf", "-f", "-d", "99" ]

EXPOSE 443/udp 443/tcp
#ENTRYPOINT ["/sbin/entrypoint.sh"]
#CMD ["/usr/sbin/named"]
