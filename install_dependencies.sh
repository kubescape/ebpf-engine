# install predependencies
sudo apt update && sudo apt install llvm clang cmake -y

#download libscap and build it
git clone https://github.com/falcosecurity/libs.git ./dependencies/falco-libs
mkdir ./dependencies/falco-libs/build && cd ./dependencies/falco-libs/build
cmake -DBUILD_BPF=true ../
make bpf 
cmake -DUSE_BUNDLED_DEPS=true -DCREATE_TEST_TARGETS=OFF ../
make sinsp
