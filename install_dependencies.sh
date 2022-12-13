# install predependencies
sudo apt update && sudo apt install llvm clang cmake libelf-dev -y

#download libscap and build it
git clone https://github.com/falcosecurity/libs.git ./dependencies/falco-libs
cd ./dependencies/falco-libs
git checkout 5a02ca746cda9866d574061fc61c146dae906526
mkdir ./build && cd ./build
cmake -DBUILD_BPF=true ../
make bpf 
cmake ../
make sinsp
