FROM kathara/base

# system packages installation
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    python3-setuptools \
    openvswitch-switch \
    iproute2 \
    iputils-ping \
    tcpdump \
    && rm -rf /var/lib/apt/lists/*

# install Ryu SDN Framework and a specific Eventlet version
# 0.33.3 version is required to prevent timeouterror crashes on python 3.11
RUN pip3 install ryu --break-system-packages
RUN pip3 install "eventlet==0.33.3" --break-system-packages

# PYTHON 3.11 COMPATIBILITY PATCHES FOR RYU

# 1: reintroduce ALREADY_HANDLED in Eventlet WSGI
# Ryu looks for this variable, which was removed in newer Eventlet version. created this to prevent import crashes at startup
RUN echo "ALREADY_HANDLED = object()" >> /usr/local/lib/python3.11/dist-packages/eventlet/wsgi.py

# 2: Fix Socket import behavior
# Force eventlet to use the standard Python socket module, the standard one cause AF_INET resolution errors inside Kathara containers
RUN sed -i 's/from eventlet.green import socket/import socket/g' /usr/local/lib/python3.11/dist-packages/eventlet/convenience.py

# 3. Open vSwitch directories preparation
RUN mkdir -p /var/run/openvswitch
RUN mkdir -p /var/log/openvswitch