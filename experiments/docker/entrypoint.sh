#!/bin/sh
set -eu

if [ -n "${SILK_NODE_NEIGHBORS:-}" ]; then
    printf '%s\n' "${SILK_NODE_NEIGHBORS}" |
        while IFS='|' read -r address mac; do
            [ -n "${address}" ] || continue
            ip neigh replace "${address}" lladdr "${mac}" dev eth0 nud permanent
        done
fi

if [ "${SILK_NETEM_ENABLED:-0}" = "1" ]; then
    : "${SILK_NETEM_INTERFACE:?missing SILK_NETEM_INTERFACE}"
    : "${SILK_NETEM_BANDWIDTH_MBIT:?missing SILK_NETEM_BANDWIDTH_MBIT}"
    : "${SILK_NETEM_MODE:?missing SILK_NETEM_MODE}"

    if [ "${SILK_NETEM_MODE}" = "uniform" ]; then
        : "${SILK_NETEM_DELAY_MS:?missing SILK_NETEM_DELAY_MS}"
        : "${SILK_NETEM_JITTER_MS:?missing SILK_NETEM_JITTER_MS}"
        : "${SILK_NETEM_DISTRIBUTION:?missing SILK_NETEM_DISTRIBUTION}"
        : "${SILK_NETEM_LOSS_PERCENT:?missing SILK_NETEM_LOSS_PERCENT}"
        : "${SILK_NETEM_REORDER_PERCENT:?missing SILK_NETEM_REORDER_PERCENT}"
        : "${SILK_NETEM_DUPLICATE_PERCENT:?missing SILK_NETEM_DUPLICATE_PERCENT}"
        : "${SILK_NETEM_SEED:?missing SILK_NETEM_SEED}"

        if [ "${SILK_NETEM_DISTRIBUTION}" != "uniform" ]; then
            echo "unsupported netem distribution: ${SILK_NETEM_DISTRIBUTION}" >&2
            exit 64
        fi

        # netem's default jitter distribution is uniform. Passing
        # "distribution uniform" would incorrectly request a uniform.dist file.
        tc qdisc replace dev "${SILK_NETEM_INTERFACE}" root netem \
            delay "${SILK_NETEM_DELAY_MS}ms" "${SILK_NETEM_JITTER_MS}ms" \
            loss "${SILK_NETEM_LOSS_PERCENT}%" \
            reorder "${SILK_NETEM_REORDER_PERCENT}%" \
            duplicate "${SILK_NETEM_DUPLICATE_PERCENT}%" \
            rate "${SILK_NETEM_BANDWIDTH_MBIT}mbit" \
            seed "${SILK_NETEM_SEED}"
    elif [ "${SILK_NETEM_MODE}" = "region-matrix" ]; then
        : "${SILK_NETEM_RULES:?missing SILK_NETEM_RULES}"
        tc qdisc replace dev "${SILK_NETEM_INTERFACE}" root handle 1: htb \
            default 999 r2q 10000
        tc class add dev "${SILK_NETEM_INTERFACE}" parent 1: classid 1:1 htb \
            rate "${SILK_NETEM_BANDWIDTH_MBIT}mbit" \
            ceil "${SILK_NETEM_BANDWIDTH_MBIT}mbit"
        tc class add dev "${SILK_NETEM_INTERFACE}" parent 1:1 classid 1:999 htb \
            rate "${SILK_NETEM_BANDWIDTH_MBIT}mbit" \
            ceil "${SILK_NETEM_BANDWIDTH_MBIT}mbit"

        printf '%s\n' "${SILK_NETEM_RULES}" | while IFS='|' read -r class_id delay_ms destinations; do
            [ -n "${class_id}" ] || continue
            tc class add dev "${SILK_NETEM_INTERFACE}" parent 1:1 \
                classid "1:${class_id}" htb \
                rate "${SILK_NETEM_BANDWIDTH_MBIT}mbit" \
                ceil "${SILK_NETEM_BANDWIDTH_MBIT}mbit"
            tc qdisc add dev "${SILK_NETEM_INTERFACE}" parent "1:${class_id}" \
                handle "${class_id}:" netem delay "${delay_ms}ms"
            old_ifs=${IFS}
            IFS=','
            for destination in ${destinations}; do
                tc filter add dev "${SILK_NETEM_INTERFACE}" protocol ip parent 1: \
                    prio 10 u32 match ip dst "${destination}" flowid "1:${class_id}"
            done
            IFS=${old_ifs}
        done
    else
        echo "unsupported netem mode: ${SILK_NETEM_MODE}" >&2
        exit 64
    fi
    tc -details qdisc show dev "${SILK_NETEM_INTERFACE}" >&2
fi

exec experiment-runner "$@"
