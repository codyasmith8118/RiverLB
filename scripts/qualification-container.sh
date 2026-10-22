# Sourced by VM/media helpers; limits apply only inside an admitted qualification.
qualification_args=()
if [[ -n ${RIVERLB_QUALIFICATION_ID:-} ]]; then
    [[ "$RIVERLB_QUALIFICATION_ID" =~ ^[0-9]+-[0-9]+-(bios|uefi)-[a-f0-9]{16}$ ]] || { echo 'Invalid qualification identity.' >&2; exit 1; }
    [[ ${1:-} =~ ^(build|boot|installer|iso)$ ]] || { echo 'Invalid qualification stage.' >&2; exit 1; }
    qualification_args=(--name "riverlb-q-$RIVERLB_QUALIFICATION_ID-$1"
        --label "io.riverlb.qualification=$RIVERLB_QUALIFICATION_ID"
        --memory=8g --memory-swap=8g --cpus=2 --pids-limit=256
        --ulimit nofile=4096:4096 --stop-timeout=15)
fi
