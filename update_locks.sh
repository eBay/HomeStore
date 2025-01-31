#!/bin/bash

LOCK_DIR=./locks
BASE_LOCK=${LOCK_DIR}/base.lock
DEBUG_LOCK=${LOCK_DIR}/debug_deps.lock
RELEASE_LOCK=${LOCK_DIR}/release_deps.lock
SANITIZE_LOCK=${LOCK_DIR}/sanitize_deps.lock

if [ ! -r ${BASE_LOCK} ]; then
    echo "No exisiting base lock! Incorrect working directory?"
    exit 1
fi

echo -n "Updating Base Lock..."
conan lock create --lockfile-out=${BASE_LOCK} --base ./conanfile.py  1>/dev/null 2>&1
echo "done"

echo -n "Updating Debug Lock..."
conan lock create --lockfile-out ${DEBUG_LOCK} --lockfile ${BASE_LOCK} -o sisl:prerelease=True -s:h build_type=Debug ./conanfile.py > /dev/null
echo "done"

echo -n "Updating Sanitize Lock..."
conan lock create --lockfile-out ${SANITIZE_LOCK} --lockfile ${BASE_LOCK} -o homestore:sanitize=True -o sisl:prerelease=True -s:h build_type=Debug ./conanfile.py > /dev/null
echo "done"

echo -n "Updating Release Lock..."
conan lock create --lockfile-out ${RELEASE_LOCK} --lockfile ${BASE_LOCK} -o sisl:prerelease=False -s:h build_type=RelWithDebInfo ./conanfile.py > /dev/null
echo "done"
