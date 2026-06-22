FROM node:lts-alpine

# Install monitoring tools for Layer 2 dynamic analysis
RUN apk add --no-cache strace tcpdump bind-tools dnsmasq

# Working directory for package under analysis
WORKDIR /pkg

# Copy entrypoint script
COPY run_layer2.sh /run_layer2.sh
RUN chmod +x /run_layer2.sh

ENTRYPOINT ["/run_layer2.sh"]
