# ##########   #######   ############
FROM ecr.vip.ebayc3.com/sds/sds_cpp_base:2.8 as build
LABEL description="Automated SDS compilation"

ARG CONAN_CHANNEL
ARG CONAN_USER
ARG CONAN_PASS=${CONAN_USER}
ARG HOMESTORE_BUILD_TAG
ENV CONAN_USER=${CONAN_USER:-sds}
ENV CONAN_CHANNEL=${CONAN_CHANNEL:-testing}
ENV CONAN_PASS=${CONAN_PASS:-password}
ENV HOMESTORE_BUILD_TAG=${HOMESTORE_BUILD_TAG:-release}
ENV SOURCE_PATH=/tmp/source/

COPY .git/ ${SOURCE_PATH}.git
RUN cd ${SOURCE_PATH}; git reset --hard

WORKDIR /output
ENV ASAN_OPTIONS=detect_leaks=0

# Build the variants we will publish
RUN conan create -pr debug ${SOURCE_PATH} "${CONAN_USER}"/"${CONAN_CHANNEL}"
RUN conan create ${SOURCE_PATH} "${CONAN_USER}"/"${CONAN_CHANNEL}"
RUN conan create -pr nosanitize ${SOURCE_PATH} "${CONAN_USER}"/"${CONAN_CHANNEL}"

# Generates coverage reports
RUN set -eux; \
    if [ "nosanitize" = "${BUILD_TYPE}" ]; then \
      eval $(grep 'name =' ${SOURCE_PATH}conanfile.py | sed 's, ,,g' | sed 's,name,PKG_NAME,'); \
      eval $(grep -m 1 'version =' ${SOURCE_PATH}conanfile.py | sed 's, ,,g' | sed 's,version,PKG_VERSION,'); \
      /usr/local/bin/build-wrapper-linux-x86-64 --out-dir /tmp/sonar conan create --build missing -o ${PKG_NAME}:coverage=True -pr ${BUILD_TYPE} ${SOURCE_PATH} sds/debug; \
      BUILD_BASE=~/.conan/data/${PKG_NAME}/${PKG_VERSION}/sds/debug/build; \
      BUILD_DIR=`find ${BUILD_BASE} -maxdepth 1 -type d \( ! -wholename ${BUILD_BASE} \) -print`; \
      cp ${SOURCE_PATH}sonar-project.properties ${BUILD_DIR}; \
      find ${BUILD_DIR} -name "*.gcno" -exec gcov {} \; ; \
      /usr/local/bin/sonar-scanner -Dsonar.projectBaseDir=${BUILD_DIR} -Dsonar.projectVersion="${PKG_VERSION}"; \
    fi

CMD set -eux; \
    eval $(grep 'name =' ${SOURCE_PATH}conanfile.py | sed 's, ,,g' | sed 's,name,PKG_NAME,'); \
    eval $(grep 'version =' ${SOURCE_PATH}conanfile.py | sed 's, ,,g' | sed 's,version,PKG_VERSION,'); \
    conan user -r ebay-sds -p "${CONAN_PASS}" sds; \
    conan upload ${PKG_NAME}/"${PKG_VERSION}"@"${CONAN_USER}"/"${CONAN_CHANNEL}" --all -r ebay-sds;
# ##########   #######   ############
