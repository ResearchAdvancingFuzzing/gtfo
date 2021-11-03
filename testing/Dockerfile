FROM ubuntu:21.04
WORKDIR /home/
RUN apt-get update
RUN apt-get -y upgrade
RUN DEBIAN_FRONTEND="noninteractive" apt-get -y install git clang build-essential cmake pkg-config libyaml-0-2 libyaml-dev systemd --fix-missing
RUN git clone https://github.com/intel/libipt
RUN cd libipt && mkdir build && cd build && CC=clang cmake .. && make && make install
RUN git clone https://github.com/intelxed/xed
RUN git clone https://github.com/intelxed/mbuild.git
RUN cd xed && ./mfile.py --shared install
RUN cp xed/kits/xed-install-base-2021-11-03-lin-x86-64/lib/libxed.so /usr/local/lib/
RUN cp -r xed/kits/xed-install-base-2021-11-03-lin-x86-64/include/xed /usr/local/include/
RUN useradd -d /home/gtfo_testuser -m -s /bin/bash gtfo_testuser && echo "gtfo_testuser:gtfo_testuser" | chpasswd && adduser gtfo_testuser sudo
ENTRYPOINT ["/home/testing/scripts/test_everything.sh"]
