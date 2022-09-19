# kubescape-ebpf-engine
## installing steps
    1. run the script ./install_dependencies.sh in order to pull falco libs and build relavent libraries - this step is quiet long (15 minutes more or less)
    2. create new build directory: mkdir ./build
    3. run cmake in the build directory: cmake ..
    4. build the project: make all

## runnig steps
    1. run the command line for example: sudo ./build/main -f "evt.type=execve or evt.type=execveat" -e ./dependencies/falco-libs/build/driver/bpf/probe.o
       in order to listen on all execve and execveat syscalls occuring in containers (by default we will print data only in containers)

run ./build/main -h in order to see all flags

