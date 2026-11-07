#!/bin/sh
# MODE=router (default): generate a self-signed certificate, write a config and run the router.
# MODE=load: run wamp_load against $ROUTER_HOST:$ROUTER_PORT with the arguments in $LOAD_ARGS.
# MODE=plain: run the plain-TCP profiling router (what wamp_load can talk to) on :8080.
# MODE=info: print the container's CPU limits and exit.
set -e

print_cpu_info() {
    echo "--- container CPU view ---"
    echo "nproc: $(nproc)"
    for f in /sys/fs/cgroup/cpu.max /sys/fs/cgroup/cpu/cpu.cfs_quota_us /sys/fs/cgroup/cpu/cpu.cfs_period_us /sys/fs/cgroup/cpuset.cpus.effective; do
        [ -r "$f" ] && echo "$f: $(cat $f)"
    done
    grep -m1 "model name" /proc/cpuinfo || true
    lscpu 2>/dev/null | grep -E "^(Thread|Core|Socket|CPU\(s\)|On-line)" || true
    env | grep -E "^ECS_|^AWS_EXECUTION_ENV" | sed 's/=.*TOKEN.*/=<redacted>/' || true
    if [ -n "$ECS_CONTAINER_METADATA_URI_V4" ]; then
        echo "task metadata limits: $(curl -s -m 2 "$ECS_CONTAINER_METADATA_URI_V4/task" | grep -o '"Limits":{[^}]*}')"
    fi
    echo "--------------------------"
}

case "${MODE:-router}" in
  info)
    print_cpu_info
    ;;
  plain)
    print_cpu_info
    exec /opt/wamp/wamp_profile_router --port 8080
    ;;
  load)
    print_cpu_info
    exec /opt/wamp/wamp_load --host "${ROUTER_HOST:?ROUTER_HOST is required}" --port "${ROUTER_PORT:-8080}" ${LOAD_ARGS}
    ;;
  router)
    print_cpu_info
    dir=/tmp/wamp
    mkdir -p "$dir"
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
        -keyout "$dir/key.pem" -out "$dir/cert.pem" -days 30 -subj "/CN=wamp-router" 2>/dev/null
    cat > "$dir/config.toml" <<CFG
[server]
port = 8080
[server.tls]
cert = "$dir/cert.pem"
key = "$dir/key.pem"
[server.rpc]
max_pending_invocations = 10000
[logging]
level = "${LOG_LEVEL:-info}"
CFG
    exec /opt/wamp/wamp_router --config "$dir/config.toml"
    ;;
  *)
    echo "unknown MODE" >&2; exit 2
    ;;
esac
