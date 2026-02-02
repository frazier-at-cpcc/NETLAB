FROM tsl0922/ttyd:latest

# Install SSH client and sshpass for password authentication
RUN apt-get update && apt-get install -y --no-install-recommends \
    openssh-client \
    sshpass \
    bsdutils \
    && rm -rf /var/lib/apt/lists/*
