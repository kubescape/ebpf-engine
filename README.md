# eBPF Engine
[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2Fkubescape%2Febpf-engine.svg?type=shield)](https://app.fossa.com/projects/git%2Bgithub.com%2Fkubescape%2Febpf-engine?ref=badge_shield)


## Build

1. Pull and build vendor libraries by running the following script:
```sh
./install_dependencies.sh
```
<i>This step can take ~15 minutes depending on your machine.</i>

2. Build the engine:

```sh
mkdir ./build && cd build
cmake ..
make all
```

## Run

```sh
sudo ./build/main -f "evt.type=execve or evt.type=execveat" -e ./dependencies/falco-libs/build/driver/bpf/probe.o
```

The command above will listen on all `execve` and `execveat` syscalls occuring in containers (by default we will print data only in containers).

Check out the available flags by running: `./build/main -h`


## License
[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2Fkubescape%2Febpf-engine.svg?type=large)](https://app.fossa.com/projects/git%2Bgithub.com%2Fkubescape%2Febpf-engine?ref=badge_large)