# Router

An ebpf-based router!

This is mostly exploratory code, and not intended for production use.

## Usage

### On 1 host using network namespaces

#### 1. Install Pre-requisites

```shell
sudo snap install go --channel=1.24/stable --classic
sudo apt update
sudo apt -y install clang llvm gcc-multilib libbpf-dev
```

#### 2. Create environment

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

#### 3. Build and run the project

```shell
go build cmd/router/main.go
sudo ip netns exec router ./main --config router.yaml
```

### On 3 hosts using Multipass

#### 1. Create environment

Create three LXD networks:

```shell
lxc network create net1 ipv4.address=10.0.0.1/24 ipv4.routing=false
lxc network create net2 ipv4.address=20.0.0.1/24 ipv4.routing=false
```

Create three Multipass instances:

```shell
multipass launch noble --name=host1 --network net1
multipass launch noble --name=host2 --network net2
multipass launch noble --name=router --network net1 --network net2
```

Validate that the 3 instances have been created:

```shell
multipass list
```

You should see the following output:

```shell
Name                    State             IPv4             Image
host1                   Running           10.166.86.124    Ubuntu 24.04 LTS
                                          10.0.0.144
host2                   Running           10.166.86.61     Ubuntu 24.04 LTS
                                          20.0.0.41
router                  Running           10.166.86.122    Ubuntu 24.04 LTS
                                          10.0.0.130
                                          20.0.0.12
```

#### 2. Create routes in host1 and host2 towards the router VM

Connect to host1:

```shell
multipass shell host1
```

Create a route to host2:

```shell
sudo ip route add 20.0.0.0/24 via 10.0.0.130 dev ens4
```

Try to ping host2:

```shell
ping -I ens4 20.0.0.41
```

You should see that the ping fails.

Exit the shell:

```shell
exit
```

Log into host2:

```shell
multipass shell host2
```

Create a route to host1:

```shell
sudo ip route add 10.0.0.0/24 via 20.0.0.12 dev ens4
```

Exit the shell:

```shell
exit
```

#### 3. Build and run the project

Log into the router:

```shell
multipass shell router
```

Build the project:

```shell
sudo snap install go --channel=1.24/stable --classic
sudo apt update
sudo apt -y install clang llvm gcc-multilib libbpf-dev
git clone https://github.com/gruyaume/router.git
cd router
go build cmd/router/main.go
```

Write the configuration file:

```shell
cat << EOF > router.yaml
interfaces: ["ens4", "ens5"]
routes:
  - destination: "10.0.0.144"
    prefixlen: 24
    interface: "ens4"
    gateway: "0.0.0.0"
  - destination: "20.0.0.41"
    prefixlen: 24
    interface: "ens5"
    gateway: "0.0.0.0"
neighbors:
  - ip: "10.0.0.144"
    mac: "52:54:00:e1:7b:38"
  - ip: "20.0.0.41"
    mac: "52:54:00:86:fe:fd"
log_level: "info"
EOF
```

Run the router:

```shell
sudo ./main --config router.yaml
```