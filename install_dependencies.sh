# install predependencies
sudo apt update && sudo apt install llvm clang cmake -y

#download libscap and build it
git clone https://github.com/falcosecurity/libs.git ./dependencies/falco-libs
cd ./dependencies/falco-libs
git checkout b44ed2cdfd85fdd75486be63bbda55c17de7c825
mkdir ./build && cd ./build
cmake -DBUILD_BPF=true ../
make bpf 
cmake ../
make sinsp
