FROM zephyrprojectrtos/zephyr-build

ARG ZEPHYR_VER=v3.4.0
ENV ZEPHYR_BASE=/opt/zephyr
ENV ZEPHYR_SDK_INSTALL_DIR=/opt/toolchains/zephyr-sdk-0.16.3-rc1
USER root

# setup Zephyr
RUN west init --mr ${ZEPHYR_VER} $(dirname ${ZEPHYR_BASE})
WORKDIR /workdir
RUN west update