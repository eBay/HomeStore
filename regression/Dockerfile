# ##########   #######   ############
FROM ecr.vip.ebayc3.com/sds/sds_develop:2.1
LABEL description="Automated HomeStore compilation"

ARG CONAN_CHANNEL
ARG CONAN_USER
ENV CONAN_USER=${CONAN_USER:-sds}
ENV CONAN_CHANNEL=${CONAN_CHANNEL:-develop}
ENV SOURCE_PATH=/tmp/source/

COPY conanfile.py ${SOURCE_PATH}
COPY cmake/ ${SOURCE_PATH}cmake
COPY CMakeLists.txt ${SOURCE_PATH}
COPY src/ ${SOURCE_PATH}src
COPY regression/run_regression /usr/local/bin

WORKDIR /output
RUN conan install --build missing ${SOURCE_PATH}

# Build the variants we will publish
ENV ASAN_OPTIONS=detect_leaks=0
RUN conan create -pr debug ${SOURCE_PATH} "${CONAN_USER}"/"${CONAN_CHANNEL}"

RUN find /root/.conan/data/homestore -name "test_*" -exec mv {} /usr/local/bin \
RUN find /root/.conan/data/homestore -name "perf_*" -exec mv {} /usr/local/bin \
RUN find /root/.conan/data/homestore -name "obj_allocator_benchmark" -exec mv {} /usr/local/bin \
RUN find /root/.conan/data/homestore -name "vol_test.py" -exec mv {} /usr/local/bin \

EXPOSE 5000

# ##########   #######   ############
