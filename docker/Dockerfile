FROM node:lts-alpine

# Install monitoring tools for Layer 2 dynamic analysis + libfaketime for Layer 3
# clock-manipulation scenario.
RUN apk add --no-cache strace tcpdump bind-tools dnsmasq libfaketime

# Working directory for package under analysis
WORKDIR /pkg

# Copy entrypoints (Layer 2 and Layer 3 share this image; Layer 3 is invoked via
# `docker run --entrypoint /run_layer3.sh`, leaving the default Layer 2 entrypoint
# untouched).
COPY run_layer2.sh /run_layer2.sh
COPY run_layer3.sh /run_layer3.sh
COPY fuzz_exports.js /fuzz_exports.js
RUN chmod +x /run_layer2.sh /run_layer3.sh

ENTRYPOINT ["/run_layer2.sh"]
