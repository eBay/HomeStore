# ##########   #######   ############
FROM ecr.vip.ebayc3.com/sds/sds_develop:latest
LABEL description="Automated HomeStore compilation"

ARG PKG_NAME
ARG BUILD_TYPE
ENV BUILD_TYPE=${BUILD_TYPE:-default}

WORKDIR /output
RUN set -eux; \
    eval $(grep 'name =' conanfile.py | sed 's, ,,g' | sed 's,name,PKG_NAME,'); \
    eval $(grep -m 1 'version =' conanfile.py | sed 's, ,,g' | sed 's,version,PKG_VERSION,'); \
    if [ "sanitize" = "${BUILD_TYPE}" ]; then \
      conan install -pr debug ${PKG_NAME}; \
    else \
      conan install -pr ${BUILD_TYPE} -o homestore:sanitize=False ${PKG_NAME}; \
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
