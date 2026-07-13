FROM kathara/base

# 1. Installazione pacchetti di sistema
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    python3-setuptools \
    openvswitch-switch \
    iproute2 \
    iputils-ping \
    tcpdump \
    && rm -rf /var/lib/apt/lists/*

# 2. Installiamo RYU e la versione NUOVA di Eventlet
# Eventlet 0.33.3 risolve i crash di Python 3.11 (TimeoutError)
RUN pip3 install ryu --break-system-packages
RUN pip3 install "eventlet==0.33.3" --break-system-packages

# --- PATCH DI COMPATIBILITÀ (FRANKENSTEIN) ---

# PATCH 1: Reinseriamo ALREADY_HANDLED (Risolve il tuo errore attuale)
# Ryu cerca questa variabile che è stata rimossa. Noi la ricreiamo finta.
RUN echo "ALREADY_HANDLED = object()" >> /usr/local/lib/python3.11/dist-packages/eventlet/wsgi.py

# PATCH 2: Fix importazione Socket (Risolve eventuali errori AF_INET)
# Diciamo a eventlet di usare il socket normale invece di quello "green" che spesso fallisce.
RUN sed -i 's/from eventlet.green import socket/import socket/g' /usr/local/lib/python3.11/dist-packages/eventlet/convenience.py

# -----------------------------------------------

# 3. Preparazione cartelle OVS
RUN mkdir -p /var/run/openvswitch
RUN mkdir -p /var/log/openvswitch