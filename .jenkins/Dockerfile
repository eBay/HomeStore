# ##########   #######   ############
FROM hub.tess.io/sds/sds_develop:4.x-latest
LABEL description="Automated HomeStore compilation"

WORKDIR /output

RUN set -eux; \
    sed -i 's/master/latest/g' /etc/apt/sources.list; \
    apt-get update; \
    apt-get upgrade -y; \
    apt-get install iputils-ping; \
    apt-get install net-tools; \
    rm -rf /var/lib/apt/lists/*;

COPY test_index_btree /usr/local/bin/test_index_btree
COPY btree_test.py /usr/local/bin/scripts/btree_test.py

EXPOSE 5000
# ##########   #######   ############