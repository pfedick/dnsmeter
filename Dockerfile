FROM fedora:36

# Install base packages
RUN yum install -y tzdata gcc gcc-c++ pcre-devel libpcap-devel bind-utils

# configure timezone to CET
RUN rm -rf /etc/localtime && ln -s /usr/share/zoneinfo/Europe/Berlin /etc/localtime


COPY configure /tmp
COPY Makefile.in /tmp
COPY *.m4 /tmp/
ADD autoconf /tmp/autoconf
ADD include /tmp/include
ADD src /tmp/src
ADD ppl7 /tmp/ppl7

WORKDIR /tmp
RUN ./configure
RUN make -j
RUN cp dnsmeter /usr/bin

#CMD /usr/sbin/httpd -DFOREGROUND
CMD /bin/sh
