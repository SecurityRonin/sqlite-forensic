#!/usr/bin/env bash
#
# run-tap.sh — headless oracle wrapper around fqlite's carving engine.
#
# Usage:   FQLITE_JAVA=<jdk25>/bin/java tools/fqlite/run-tap.sh <database.db>
#          tools/fqlite/run-tap.sh <database.db>          # uses `java` on PATH
#
# Emits CSV of recovered DELETED rows on stdout, one per line:
#     rowid,col1,col2,...        (rowid is -1 when the engine cannot recover it)
#
# Requires a one-time build (engine classes under tools/fqlite/build, the OpenJFX
# 22.0.2 SDK under tools/fqlite/sdk, the Maven jars under tools/fqlite/lib). See
# tools/fqlite/SETUP.md for the full build recipe; the engine is JavaFX-coupled so
# the JVM boots the FX toolkit headlessly (no window is ever shown).
#
set -euo pipefail

# Directory of this script (tools/fqlite), regardless of caller's cwd.
TAP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ "$#" -lt 1 ]; then
    echo "usage: run-tap.sh <database.db>" >&2
    exit 2
fi
DB="$1"
if [ ! -f "$DB" ]; then
    echo "run-tap.sh: not a file: $DB" >&2
    exit 2
fi

JAVA="${FQLITE_JAVA:-java}"

SDK="$TAP_DIR/sdk/javafx-sdk-22.0.2/lib"
BUILD="$TAP_DIR/build"
LIB="$TAP_DIR/lib"

if [ ! -f "$BUILD/HeadlessTap.class" ]; then
    echo "run-tap.sh: tap not built ($BUILD/HeadlessTap.class missing)." >&2
    echo "            Build it first — see $TAP_DIR/SETUP.md." >&2
    exit 3
fi

CP="$BUILD:$LIB/commons-codec-1.17.1.jar:$LIB/jspecify-1.0.0.jar:$LIB/antlr4-runtime-4.8.jar:$LIB/sqlite-jdbc-3.51.1.0.jar"

# -Dprism.order=sw            : software rasteriser, no GPU/display needed
# -Djavafx.macosx.embedded=true + -Dmonocle/headless are not used: the default macOS
#   Glass backend initialises the FX toolkit offscreen fine. Keeping prism=sw avoids
#   any GPU dependency. No Stage is ever created, so no window appears.
exec "$JAVA" \
    -Djava.awt.headless=true \
    -Dprism.order=sw \
    -Djavafx.macosx.embedded=true \
    --enable-native-access=javafx.graphics \
    --add-modules javafx.base,javafx.graphics,javafx.controls,javafx.swing,javafx.web \
    -p "$SDK" \
    -cp "$CP" \
    HeadlessTap "$DB"
