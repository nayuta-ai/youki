ARG VARIANT="bullseye"
FROM mcr.microsoft.com/vscode/devcontainers/rust:1-${VARIANT}

# Install docker with youki
COPY <<EOF /etc/docker/daemon.json
  {
    "runtimes": {
      "youki": {
        "path": "/workspaces/youki/youki"
      }
    }
  }
EOF

RUN <<EOF
apt-get update

# For building
apt-get install -y \
  build-essential \
  git \
  libclang-dev \
  libelf-dev \
  libseccomp-dev \
  libssl-dev \
  libsystemd-dev \
  pkg-config

# For debugging
apt-get install -y \
  podman \
  bpftrace

curl --proto '=https' --tlsv1.2 -sSf https://just.systems/install.sh | bash -s -- --to /usr/bin

curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
chmod +x kubectl
mv ./kubectl /usr/bin/kubectl

# nightly build is required for `cargo fmt` as `rustfmt.toml` uses unstable features.
curl https://sh.rustup.rs -sSf | sh -s -- -y
rustup install nightly
rustup component add rustfmt
rustup component add clippy 
EOF
