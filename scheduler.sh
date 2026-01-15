#!/usr/bin/sh

SCRIPT_DIR="$(dirname "$0")"

sudo sh -c "PATH=$PATH java --enable-native-access=ALL-UNNAMED -jar $SCRIPT_DIR/target/concurrency-fuzz-scheduler-0.1-SNAPSHOT-jar-with-dependencies.jar $*" -- "$@"
