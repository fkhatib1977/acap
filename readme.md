docker build --no-cache -t lg:native-12.5.0 .
docker run --rm -v C:\AXIS\Firas\src:/app lg /bin/bash
make clean && make
acap-build . -a ./libmicrohttpd.so -a ./libmicrohttpd.so.12 -a LogicGARD.bin
