# xdp-tutorial

## Usage

### 1. Install pre-requisites

```shell
sudo snap install go --channel=1.24/stable --classic
sudo apt update
sudo apt -y install clang llvm gcc-multilib libbpf-dev
```

### 2. Build and run the project

```shell
go build cmd/xdp/main.go
sudo ./main --config tutorial.yaml
```
