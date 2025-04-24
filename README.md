# Router

An ebpf-based router!

This is mostly exploratory code, and not intended for production use.

## Usage

### 1. Install Pre-requisites

```shell
sudo snap install go --channel=1.24/stable --classic
sudo apt update
sudo apt -y install clang llvm gcc-multilib libbpf-dev
```

### 2. Create environment

```shell
# 1. Create namespaces
for ns in hostA router hostB; do
  sudo ip netns add $ns
  sudo ip netns exec $ns ip link set lo up
done

# 2. Create veths
sudo ip link add vethA type veth peer name vethR1
sudo ip link add vethB type veth peer name vethR2

sudo ip link set vethA netns hostA
sudo ip link set vethR1 netns router
sudo ip link set vethB netns hostB
sudo ip link set vethR2 netns router

# 3. Assign addresses & bring up
sudo ip netns exec hostA ip addr add 10.0.0.1/24 dev vethA
sudo ip netns exec hostA ip link set vethA up

sudo ip netns exec router ip addr add 10.0.0.254/24 dev vethR1
sudo ip netns exec router ip link set vethR1 up

sudo ip netns exec hostB ip addr add 10.1.0.1/24 dev vethB
sudo ip netns exec hostB ip link set vethB up

sudo ip netns exec router ip addr add 10.1.0.254/24 dev vethR2
sudo ip netns exec router ip link set vethR2 up

sudo ip netns exec hostA ip route add 10.1.0.0/24 via 10.0.0.254 dev vethA
sudo ip netns exec hostB ip route add 10.0.0.0/24 via 10.1.0.254 dev vethB
```

### 3. Build and run the project

```shell
go build cmd/router/main.go
sudo ip netns exec router ./main --config router.yaml
```
