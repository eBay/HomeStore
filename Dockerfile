# ##########   #######   ############
FROM ecr.vip.ebayc3.com/sds/sds_cpp_base:0.11
LABEL description="Automated compilation for SDS HomeStore"

ARG CONAN_CHANNEL
ARG CONAN_USER
ENV CONAN_USER=${CONAN_USER:-demo}
ENV CONAN_CHANNEL=${CONAN_CHANNEL:-dev}

COPY conanfile.py /tmp/source/

RUN set -eux; \
    PKG_VERSION=$(grep 'version =' /tmp/source/conanfile.py | awk '{print $3}'); \
    PKG_VERSION="${PKG_VERSION%\"}"; \
    PKG_VERSION="${PKG_VERSION#\"}"; \
    echo ${PKG_VERSION} > /tmp/VERSION; \
    conan install -u /tmp/source

COPY CMakeLists.txt /tmp/source/
COPY src/ /tmp/source/src

RUN conan create /tmp/source homestore/${PKG_VERSION}@"${CONAN_USER}"/"${CONAN_CHANNEL}";
RUN conan create -pr debug /tmp/source homestore/${PKG_VERSION}@"${CONAN_USER}"/"${CONAN_CHANNEL}";

ARG CONAN_PASS=${CONAN_USER}
RUN conan user -r origin -p "${CONAN_PASS}" sds;

CMD set -eux; \
    PKG_VERSION=$(cat /tmp/VERSION); \
    conan upload homestore/${PKG_VERSION}@"${CONAN_USER}"/"${CONAN_CHANNEL}" --all -r origin;
# ##########   #######   ############
