# ##########   #######   ############
FROM ecr.vip.ebayc3.com/sds/sds_cpp_base:1.21
LABEL description="Automated SDS compilation"

ARG CONAN_CHANNEL
ARG CONAN_USER
ARG CONAN_PASS=${CONAN_USER}
ENV CONAN_USER=${CONAN_USER:-sds}
ENV CONAN_CHANNEL=${CONAN_CHANNEL:-testing}
ENV CONAN_PASS=${CONAN_PASS:-password}
ENV SOURCE_PATH=/tmp/source/

COPY conanfile.py ${SOURCE_PATH}
COPY cmake/ ${SOURCE_PATH}cmake
COPY CMakeLists.txt ${SOURCE_PATH}
COPY src/ ${SOURCE_PATH}src

WORKDIR /output

# Build the variants we will publish
ENV ASAN_OPTIONS=detect_leaks=0
RUN conan create -pr debug ${SOURCE_PATH} "${CONAN_USER}"/"${CONAN_CHANNEL}"
RUN conan create ${SOURCE_PATH} "${CONAN_USER}"/"${CONAN_CHANNEL}"
RUN conan create -pr bionic_nosanitize ${SOURCE_PATH} "${CONAN_USER}"/"${CONAN_CHANNEL}"

# Generates coverage reports
RUN set -eux; \
    eval $(grep 'name =' ${SOURCE_PATH}conanfile.py | sed 's, ,,g' | sed 's,name,PKG_NAME,'); \
    conan install -o ${PKG_NAME}:coverage=True -pr bionic_nosanitize ${SOURCE_PATH}; \
    conan build ${SOURCE_PATH};

CMD set -eux; \
    eval $(grep 'name =' ${SOURCE_PATH}conanfile.py | sed 's, ,,g' | sed 's,name,PKG_NAME,'); \
    eval $(grep 'version =' ${SOURCE_PATH}conanfile.py | sed 's, ,,g' | sed 's,version,PKG_VERSION,'); \
    conan user -r ebay-sds -p "${CONAN_PASS}" sds; \
    conan upload ${PKG_NAME}/"${PKG_VERSION}"@"${CONAN_USER}"/"${CONAN_CHANNEL}" --all -r ebay-sds;
# ##########   #######   ############
