#!/usr/bin/env bash
# SentinelGuard 24/7 Daemon Runner

WORKSPACE_DIR="/data/workspaces/sentinelguard-marketplace-saas"
cd "$WORKSPACE_DIR" || exit 1

LOG_FILE="$WORKSPACE_DIR/sentinelguard.log"
PID_FILE="$WORKSPACE_DIR/sentinelguard.pid"

if [ -f "$PID_FILE" ]; then
    OLD_PID=$(cat "$PID_FILE")
    if kill -0 "$OLD_PID" 2>/dev/null; then
        echo "SentinelGuard is already running with PID $OLD_PID"
        exit 0
    fi
fi

echo "Starting SentinelGuard Daemon at $(date)..." >> "$LOG_FILE"
NODE_ENV=production PORT=3000 HOST=0.0.0.0 nohup node dist/server.js >> "$LOG_FILE" 2>&1 &
NEW_PID=$!
echo "$NEW_PID" > "$PID_FILE"
echo "SentinelGuard started with PID $NEW_PID"
