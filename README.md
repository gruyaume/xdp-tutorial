# xdp-tutorial

## Usage

### 1. Install Pre-requisites

```shell
sudo snap install go --channel=1.24/stable --classic
sudo apt update
sudo apt -y install clang llvm gcc-multilib libbpf-dev
```

### 2. Create environment

```shell
sudo ip netns add A
sudo ip netns add B

# veth0 in A <-> veth1 in B
sudo ip link add veth0 type veth peer name veth1
sudo ip link set veth0 netns A
sudo ip link set veth1 netns B

sudo ip netns exec A ip addr add 10.0.0.1/24 dev veth0
sudo ip netns exec A ip link set veth0 up

sudo ip netns exec B ip addr add 10.0.0.254/24 dev veth1
sudo ip netns exec B ip link set veth1 up
```

### 3. Build and run the project


```shell
go build cmd/xdp/main.go
sudo ./main --config tutorial.yaml
```