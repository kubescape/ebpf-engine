# install predependencies
sudo apt update && sudo apt install llvm clang cmake libelf-dev -y

#download libscap and build it
if [[ ! -d ./dependencies/falco-libs ]]; then
  git clone https://github.com/falcosecurity/libs.git ./dependencies/falco-libs
fi
cd ./dependencies/falco-libs
git checkout tags/4.0.0+driver
mkdir -p ./build && cd ./build
cmake -DBUILD_BPF=true ../
make bpf
cmake ../
make sinsp
