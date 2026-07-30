#!/bin/sh
set -eu

base_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
jar=${TLA2TOOLS_JAR:-}
java_bin=${JAVA_BIN:-java}

if [ -z "$jar" ]; then
  echo "TLA2TOOLS_JAR must name a verified tla2tools.jar." >&2
  exit 2
fi
if [ ! -f "$jar" ]; then
  echo "TLA2TOOLS_JAR does not exist: $jar" >&2
  exit 2
fi
if ! command -v "$java_bin" >/dev/null 2>&1 && [ ! -x "$java_bin" ]; then
  echo "JAVA_BIN is not executable: $java_bin" >&2
  exit 2
fi

cd "$base_dir"
exec "$java_bin" -XX:+UseParallelGC -cp "$jar" tlc2.TLC \
  -cleanup \
  -config DurableGate.cfg \
  DurableGate.tla
