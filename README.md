# awdb-c
www.ipplus360.com 官方支持的解析awdb格式的C代码(Official support for parsing C code in AWDB format ) 

## Usage：
**To install this code, run the following commands:**

1. install package on ubuntu:

   ```sh
   sudo apt-get –y install  dh-autoreconf gcc make 
   ```

   on centos:

   ```shell
   yum –y install gcc make autoreconf
   ```

2. compile and install

   ```shell
   $ sh bootstrap 
   $ ./configure --disable-tests
   $ sudo make
   $ sudo make install
   $ sudo sh -c "echo /usr/local/lib  >> /etc/ld.so.conf.d/local.conf"
   $ sudo ldconfig
   ```

3. compile the demo

   ```shell
   $ gcc test.c -I./include -laiwendb
   $ ./a.out
   ```

4. problems. if you got compile error,you need update your gcc version

   1. download gcc 5.4.0

      ```shell
      $ wget https://ftp.gnu.org/gnu/gcc/gcc-5.4.0/gcc-5.4.0.tar.bz2
      $ tar -jxvf gcc-5.4.0.tar.bz2
      $ cd gcc-5.4.0
      $ ./contrib/download_prerequisites
      $ mkdir gcc-build-5.4.0
      $ cd gcc-build-5.4.0
      $ ../configure --enable-checking=release --enable-languages=c,c++ --disable-multilib
      $ make
      $ make install
      $ cd /usr/bin/
      $ mv gcc gcc_back
      $ mv g++ g++_back
      $ ln -s /usr/local/bin/gcc gcc
      $ ln -s /usr/local/bin/g++ g++
      ```

   2. if got error: ‘__int128’ is not supported on this target ,you machine is x86,change machine to x86_64

