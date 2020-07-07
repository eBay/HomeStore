# ##########   #######   ############
FROM ecr.vip.ebayc3.com/sds/sds_develop:3.15
LABEL description="Automated HomeStore compilation"

ARG CONAN_CHANNEL
ARG CONAN_USER
ARG BUILD_TYPE
ENV CONAN_USER=${CONAN_USER:-sds}
ENV CONAN_CHANNEL=${CONAN_CHANNEL:-develop}
ENV BUILD_TYPE=${BUILD_TYPE:-default}

WORKDIR /output
RUN set -eux; \
    eval $(grep 'name =' conanfile.py | sed 's, ,,g' | sed 's,name,PKG_NAME,'); \
    eval $(grep -m 1 'version =' conanfile.py | sed 's, ,,g' | sed 's,version,PKG_VERSION,'); \
    if [ "sanitize" = "${BUILD_TYPE}" ]; then \
      conan install -pr debug ${PKG_NAME}/${PKG_VERSION}@${CONAN_USER}/${CONAN_CHANNEL}; \
    else \
      conan install -pr ${BUILD_TYPE} -o homestore:sanitize=False ${PKG_NAME}/${PKG_VERSION}@${CONAN_USER}/${CONAN_CHANNEL}; \
    fi; \
    conan remove -f '*';

RUN set -eux; \
    apt-get update; \
    apt-get upgrade -y; \
    apt-get install iputils-ping; \
    apt-get install net-tools; \
    rm -rf /var/lib/apt/lists/*;

EXPOSE 5000
# ##########   #######   ############
