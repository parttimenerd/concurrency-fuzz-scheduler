#!/usr/bin/sh

sudo -E PATH=$PATH zsh -c "java --enable-native-access=ALL-UNNAMED '-agentlib:jdwp=transport=dt_socket,server=y,suspend=y,address=*:5005' -jar target/concurrency-fuzz-scheduler-0.1-SNAPSHOT-jar-with-dependencies.jar $*" -- "$@"
