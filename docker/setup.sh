#!/bin/bash

# Create the network for the containers
#sudo docker network create --subnet=172.20.0.0/16 test-net

# Build the image
sudo docker build -t bind9 . 

# Create the dns-server and start it
sudo docker run -d --rm --name=dns-server --net=test-net --ip=172.20.0.2 bind9
sudo docker exec -d dns-server /etc/init.d/bind9 start

# Create two other hosts
sudo docker run -d --rm --name=host1 --net=test-net --ip=172.20.0.3 --dns=172.20.0.2 bind9 
sudo docker run -d --rm --name=host2 --net=test-net --ip=172.20.0.4 --dns=172.20.0.2 bind9


