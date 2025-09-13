TARGET = LogicGARD.bin
SRC = LogicGARD.c cJSON.c

CC = aarch64-linux-gnu-gcc
SYSROOT = /opt/axis/acapsdk/sysroots/aarch64
CFLAGS = -O2 -Wall -g -pipe --sysroot=$(SYSROOT) \
  -I$(SYSROOT)/usr/include \
  -I$(SYSROOT)/usr/include/axsdk \
  -I$(SYSROOT)/usr/include/glib-2.0 \
  -I$(SYSROOT)/usr/lib/glib-2.0/include

LDFLAGS = -Wl,-O1 -Wl,--hash-style=gnu -Wl,--as-needed \
  -Wl,-z,relro,-z,now -Wl,--disable-new-dtags --sysroot=$(SYSROOT) \
  -L$(SYSROOT)/usr/lib -lmicrohttpd -laxevent -lglib-2.0

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $(SRC) -o $(TARGET) $(LDFLAGS)

clean:
	rm -f $(TARGET)