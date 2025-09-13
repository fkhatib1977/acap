# Use the official Axis ACAP SDK base image
FROM axisecp/acap-native-sdk:12.5.0-aarch64

# Install build tools and dependencies
RUN apt update && apt install -y \
    autoconf automake libtool make gcc-aarch64-linux-gnu pkg-config

# Set build directory for libmicrohttpd
WORKDIR /opt/build

# Copy libmicrohttpd source archive from local context
COPY libmicrohttpd-0.9.76.tar.gz /opt/build/

# Extract and build libmicrohttpd
RUN tar -xzf libmicrohttpd-0.9.76.tar.gz && \
    cd libmicrohttpd-0.9.76 && \
    ./configure --host=aarch64-linux-gnu \
                --prefix=/opt/axis/acapsdk/sysroots/aarch64/usr \
                --enable-shared --disable-static --disable-doc && \
    make && \
    make install