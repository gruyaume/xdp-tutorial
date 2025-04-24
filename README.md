# Router

**A fast eBPF-based router for Linux**

This is mostly exploratory code, and not intended for production use.

## Tutorials

### Installing Router on 1 host using network namespaces

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

### Installing Router and validating it using Multipass

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

## Reference

### Performance

Using the Multipass setup, I am able to achieve **over 3 Gbps throughput** between host1 and host2, going through the router.

```shell
ubuntu@host1:~$ iperf3 -c 20.0.0.41 --bind-dev ens4
Connecting to host 20.0.0.41, port 5201
[  5] local 10.0.0.144 port 33702 connected to 20.0.0.41 port 5201
[ ID] Interval           Transfer     Bitrate         Retr  Cwnd
[  5]   0.00-1.00   sec   403 MBytes  3.37 Gbits/sec  509    520 KBytes       
[  5]   1.00-2.00   sec   404 MBytes  3.39 Gbits/sec  302    457 KBytes       
[  5]   2.00-3.00   sec   404 MBytes  3.39 Gbits/sec  151    687 KBytes       
[  5]   3.00-4.00   sec   435 MBytes  3.65 Gbits/sec   81    940 KBytes       
[  5]   4.00-5.00   sec   417 MBytes  3.50 Gbits/sec  247    433 KBytes       
[  5]   5.00-6.00   sec   403 MBytes  3.38 Gbits/sec  156    496 KBytes       
[  5]   6.00-7.00   sec   416 MBytes  3.49 Gbits/sec  164    550 KBytes       
[  5]   7.00-8.00   sec   403 MBytes  3.38 Gbits/sec  331    369 KBytes       
[  5]   8.00-9.00   sec   420 MBytes  3.53 Gbits/sec    0    882 KBytes       
[  5]   9.00-10.00  sec   394 MBytes  3.31 Gbits/sec  305    393 KBytes       
- - - - - - - - - - - - - - - - - - - - - - - - -
[ ID] Interval           Transfer     Bitrate         Retr
[  5]   0.00-10.00  sec  4.00 GBytes  3.44 Gbits/sec  2246             sender
[  5]   0.00-10.00  sec  4.00 GBytes  3.44 Gbits/sec                  receiver

iperf Done.
```
