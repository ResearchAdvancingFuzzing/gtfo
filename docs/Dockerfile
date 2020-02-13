FROM ubuntu:18.04
RUN apt-get update -y 
RUN apt-get upgrade -y
RUN apt-get install -y clang wget xxd build-essential python cmake python-pip pkg-config python-yaml libyaml-0-2 libyaml-dev systemd --fix-missing

WORKDIR /fuzzing
RUN mkdir libtiff_working
WORKDIR /fuzzing/libtiff_working
RUN wget http://lcamtuf.coredump.cx/afl/releases/afl-2.52b.tgz
RUN wget https://download.osgeo.org/libtiff/old/tiff-3.7.0.tar.gz
RUN  tar xvf afl-2.52b.tgz
RUN  tar xvf tiff-3.7.0.tar.gz
RUN rm afl-2.52b.tgz
RUN rm tiff-3.7.0.tar.gz
WORKDIR /fuzzing/libtiff_working/afl-2.52b
RUN make
WORKDIR /fuzzing/libtiff_working/tiff-3.7.0
RUN CFLAGS="-static -fno-PIE -fno-PIC" CC=/fuzzing/libtiff_working/afl-2.52b/afl-clang ./configure --enable-shared=no
RUN CFLAGS="-static -fno-PIE -fno-PIC" CC=/fuzzing/libtiff_working/afl-2.52b/afl-clang make
RUN make install
WORKDIR /fuzzing/
COPY gtfo/ /fuzzing/
RUN mkdir -p build/ooze build/the_fuzz gtfo
WORKDIR /fuzzing/build/ooze
RUN CC=clang cmake -DCMAKE_INSTALL_PREFIX=/fuzzing/gtfo ../../ooze/
#RUN CC=clang cmake -DCMAKE_BUILD_TYPE=Debug -DCMAKE_INSTALL_PREFIX=/fuzzing/gtfo ../../ooze/
RUN make
RUN make install
WORKDIR /fuzzing/build/the_fuzz
RUN CC=clang cmake -DCMAKE_INSTALL_PREFIX=/fuzzing/gtfo ../../the_fuzz/
#RUN CC=clang cmake -DCMAKE_BUILD_TYPE=Debug -DCMAKE_INSTALL_PREFIX=/fuzzing/gtfo ../../the_fuzz/
RUN make
RUN make install
WORKDIR /fuzzing/
ENTRYPOINT ["bash"]