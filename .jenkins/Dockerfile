# ##########   #######   ############
FROM ecr.vip.ebayc3.com/sds/sds_develop:latest
LABEL description="Automated HomeStore compilation"

WORKDIR /output

RUN set -eux; \
    apt-get update; \
    apt-get upgrade -y; \
    apt-get install iputils-ping; \
    apt-get install net-tools; \
    rm -rf /var/lib/apt/lists/*;

COPY scripts /usr/local/bin/home_blks_scripts
COPY test_load /usr/local/bin/test_load
COPY test_mapping /usr/local/bin/test_mapping
COPY test_volume /usr/local/bin/test_volume
COPY check_btree /usr/local/bin/check_btree
COPY vol_test.py /usr/local/bin/vol_test.py

EXPOSE 5000
# ##########   #######   ############
