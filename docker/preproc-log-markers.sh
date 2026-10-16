# Shared by the preprocessing-store docker suites. Source it; do not run it.
#
# The suites assert on the lines a party logs when it commits material to, or
# draws material from, a `--preproc-store` volume. Hard-coding those phrases is
# how `assert_no_party_committed_from_a_live_execution` came to grep for a
# string that nothing in the Rust sources tied it to: reword either engine's
# message and the assertion passes forever while witnessing nothing.
#
# So the phrase lives in exactly one place — `PREPROC_COMMIT_LOG_MARKER` and
# `PREPROC_LOAD_LOG_MARKER` in crates/stoffel-vm/src/storage/preproc.rs, which
# both engines interpolate — and these helpers read it from there. The tie has
# two halves and neither is a shell script's job alone:
#
#   * this half fails CLOSED. Rename, move or delete a constant and
#     `read_preproc_log_marker` exits non-zero, so a suite stops instead of
#     asserting nothing.
#   * the other half is the unit test
#     `both_engines_interpolate_the_preprocessing_store_log_markers`, which
#     fails if an engine spells the phrase out instead of interpolating the
#     constant.

# Print the value of one marker constant, or fail.
#
# $1 - the constant's name
# $2 - the repository root (defaults to ${ROOT_DIR})
read_preproc_log_marker() {
    local name="$1"
    local root="${2:-${ROOT_DIR:?Set ROOT_DIR or pass the repository root}}"
    local source_file="${root}/crates/stoffel-vm/src/storage/preproc.rs"
    local value

    if [[ ! -f "${source_file}" ]]; then
        echo "Cannot read ${name}: ${source_file} does not exist" >&2
        return 1
    fi

    value="$(sed -n "s/^pub const ${name}: &str = \"\(.*\)\";\$/\1/p" "${source_file}")"
    if [[ -z "${value}" ]]; then
        echo "Cannot read ${name} from ${source_file}." >&2
        echo "The suites grep container logs for its value, so a renamed or deleted" >&2
        echo "constant must stop the run rather than leave an assertion vacuous." >&2
        return 1
    fi
    if [[ "${value}" == *$'\n'* ]]; then
        echo "Read more than one value for ${name} from ${source_file}: ${value}" >&2
        return 1
    fi

    printf '%s' "${value}"
}

# Print every byte prefix a preprocessing volume is refused for holding, one per
# line, or fail.
#
# Same discipline as the markers above, for the same reason. The one-shot suite
# counts occurrences of these prefixes inside each party's volume. The prefixes
# are a closed set in the Rust sources — `CondemnedNamespace` in
# crates/stoffel-vm/src/storage/preproc.rs — and that set has already grown
# once: `rsv:` joined `pp:` when the reservation registry stopped reaching disk
# at all. A suite that spelled one prefix out would have kept passing while
# measuring half the set.
#
# The extraction is scoped to `impl CondemnedNamespace` on purpose. The same
# file also holds `BlobNamespace::as_bytes`, whose prefixes this binary DOES
# write, and a file-wide match would condemn a live namespace and refuse every
# healthy volume.
#
# $1 - the repository root (defaults to ${ROOT_DIR})
read_condemned_preproc_prefixes() {
    local root="${1:-${ROOT_DIR:?Set ROOT_DIR or pass the repository root}}"
    local source_file="${root}/crates/stoffel-vm/src/storage/preproc.rs"
    local prefixes

    if [[ ! -f "${source_file}" ]]; then
        echo "Cannot read the condemned prefixes: ${source_file} does not exist" >&2
        return 1
    fi

    prefixes="$(awk '
        /^impl CondemnedNamespace \{/ { inside = 1; next }
        inside && /^\}/ { inside = 0 }
        inside && match($0, /=> b"[^"]*"/) {
            print substr($0, RSTART + 5, RLENGTH - 6)
        }
    ' "${source_file}")"

    if [[ -z "${prefixes}" ]]; then
        echo "Cannot read any condemned namespace prefix from ${source_file}." >&2
        echo "The one-shot suite counts these prefixes inside each party's volume, so a" >&2
        echo "renamed enum must stop the run rather than leave the count vacuous." >&2
        return 1
    fi

    printf '%s\n' "${prefixes}"
}
