FROM ubuntu:bionic

RUN apt-get update \
  && apt-get install -y \
  bind9 \
  bind9utils \
  bind9-doc \
  dnsutils \
  iputils-ping \
  python3 \
  python3-pip


# To enable DNS logs
RUN mkdir /var/log/bind && chown bind:bind /var/log/bind 

# Enable IPv4
RUN sed -i 's/OPTIONS=.*/OPTIONS="-4 -u bind"/' /etc/default/bind9

# Copy configuration files
COPY named.conf.options /etc/bind/
COPY named.conf.local /etc/bind/
COPY db.test.com /var/lib/bind/
COPY Ktest-key.+157+43149.key /root/
COPY Ktest-key.+157+43149.private /root/
COPY main.py /root/
COPY server.py /root/
COPY client.py /root/

# Run eternal loop
CMD ["/bin/bash", "-c", "while :; do sleep 10; done"]
