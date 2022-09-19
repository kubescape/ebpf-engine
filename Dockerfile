FROM ubuntu
RUN apt update && apt install libelf-dev libcap2-bin -y
COPY ./build/start-capture.sh /etc/
COPY ./build/main /etc/
COPY ./dependencies/falco-libs/build/driver/bpf/probe.o /etc/probe.o
CMD /etc/start-capture.sh
