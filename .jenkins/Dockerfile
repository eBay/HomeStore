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
COPY test_index_crash_recovery /usr/local/bin/test_index_crash_recovery
COPY test_meta_blk_mgr /usr/local/bin/test_meta_blk_mgr
COPY test_log_store /usr/local/bin/test_log_store
COPY test_home_raft_logstore /usr/local/bin/test_home_raft_logstore
COPY test_log_store_long_run /usr/local/bin/test_log_store_long_run
COPY test_data_service /usr/local/bin/test_data_service
COPY test_raft_repl_dev /usr/local/bin/test_raft_repl_dev
COPY test_solo_repl_dev /usr/local/bin/test_solo_repl_dev
COPY index_test.py /usr/local/bin/scripts/index_test.py
COPY log_meta_test.py /usr/local/bin/scripts/log_meta_test.py
COPY data_test.py /usr/local/bin/scripts/data_test.py
COPY long_running.py /usr/local/bin/scripts/long_running.py


EXPOSE 5000
# ##########   #######   ############
