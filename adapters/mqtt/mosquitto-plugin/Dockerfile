# Build the authn plugin against the same Mosquitto 2.0.22 ABI as the runtime image.
# Alpine's mosquitto-dev may drift (e.g. 2.0.20); pin headers + link against the runtime lib.
ARG MOSQUITTO_VERSION=2.0.22

FROM eclipse-mosquitto:2.0.22-openssl AS runtime

FROM alpine:3.21 AS build
ARG MOSQUITTO_VERSION
RUN apk add --no-cache build-base openssl-dev curl
WORKDIR /deps
RUN curl -fsSL \
        "https://github.com/eclipse-mosquitto/mosquitto/archive/refs/tags/v${MOSQUITTO_VERSION}.tar.gz" \
    | tar xz \
 && mkdir -p /usr/include \
 && cp "mosquitto-${MOSQUITTO_VERSION}/include/mosquitto.h" /usr/include/ \
 && cp "mosquitto-${MOSQUITTO_VERSION}/include/mosquitto_broker.h" /usr/include/ \
 && cp "mosquitto-${MOSQUITTO_VERSION}/include/mosquitto_plugin.h" /usr/include/ \
 && cp "mosquitto-${MOSQUITTO_VERSION}/include/mqtt_protocol.h" /usr/include/
# Property helpers live in libmosquitto; link the exact runtime soname.
COPY --from=runtime /usr/lib/libmosquitto.so.1 /usr/lib/libmosquitto.so.1
RUN ln -s libmosquitto.so.1 /usr/lib/libmosquitto.so
WORKDIR /src
COPY plugin.c /src/plugin.c
# Broker APIs resolve from the mosquitto process at plugin load time.
# libmosquitto covers shared property helpers. Allow unresolved broker symbols at link time.
RUN cc -std=c17 -O2 -D_FORTIFY_SOURCE=2 -fstack-protector-strong \
    -Wall -Wextra -Werror -fPIC -shared /src/plugin.c \
    -Wl,-z,relro -Wl,--allow-shlib-undefined \
    -lcrypto -lmosquitto -o /rss_mqtt_authn.so

FROM eclipse-mosquitto:2.0.22-openssl
COPY --from=build /rss_mqtt_authn.so /usr/lib/rss_mqtt_authn.so
