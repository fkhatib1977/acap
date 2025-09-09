docker run -it --rm -v C:\AXIS\Firas\src:/app acap-builder /bin/bash
docker run --rm -v C:\AXIS\Firas\src:/app acap-builder
make clean && make
acap-build . -a ./libmicrohttpd.so -a ./libmicrohttpd.so.12 -a LogicGARD.bin
