#!/bin/sh
# SPDX-License-Identifier: Apache-2.0

# Writes seed inputs for the fuzz targets into fuzz/corpus, from the examples
# in this repository and, if VERIFIED_CONFORMANCE_DIR is set, from the
# published conformance corpus (the test-vectors directory of dekrops/wvp).
#
# Seeds are generated, not committed: the corpus is not copied into this
# repository (conformance/README.md). Each target's documentation states its
# input format. Requires jq.

set -eu

here=$(cd "$(dirname "$0")" && pwd)
out=$here/corpus
examples=$here/../examples/invoice-posting

# Reads seeds from standard input, one JSON string per line, and writes each
# to its own file for a target.
emit() {
    mkdir -p "$out/$1"
    n=0
    while IFS= read -r seed; do
        n=$((n + 1))
        printf '%s' "$seed" | jq -rj . > "$out/$1/$2-$n"
    done
}

for package in "$examples"/*.json; do
    [ "${package##*/}" = trust.json ] && continue
    jq -n --slurpfile trust "$examples/trust.json" --rawfile package "$package" \
        '$package, ($trust[0] | tojson) + "\n" + $package' -c
done | {
    # Alternating lines: the package alone, then the package under trust.
    mkdir -p "$out/canonical" "$out/package"
    n=0
    while IFS= read -r alone && IFS= read -r trusted; do
        n=$((n + 1))
        printf '%s' "$alone" | jq -rj . > "$out/canonical/example-$n"
        printf '%s' "$trusted" | jq -rj . > "$out/package/example-$n"
    done
}

corpus=${VERIFIED_CONFORMANCE_DIR:-}
if [ -z "$corpus" ]; then
    echo "VERIFIED_CONFORMANCE_DIR is not set: seeded from the examples only" >&2
    exit 0
fi
registration=$corpus/claim-registration/v1

jq -c '.packageJson' "$corpus"/wvp/v0.*/*/*.json | emit canonical package
jq -c '(.registry | tojson) + "\n" + .packageJson' \
    "$corpus"/wvp/v0.*/*/*.json | emit package wvp
jq -c '.[] | (.registry | tojson) + "\n" + .packageJson' \
    "$corpus/wvp/v0.2/expectations.json" | emit package expectations

jq -c '(.contract | tojson) + "\n" + (.environment | tojson)' \
    "$corpus"/work-contract/v1/cases/*.json | emit contract case

for vector in "$corpus"/evidence-statement/v1/*/*.json; do
    jq -c '
        .input as $in
        | {
            tenant: ($in.tenant.value? // null),
            claimed: [$in.claim.evidence[]?.value],
            bodies: ($in.bodies? // []),
            anchor: ($in.anchor? // null)
          } as $context
        | [.registry | tojson] + [$context | tojson]
            + ($in.statements? // [$in.signedStatementJson])
        | join("\n")' "$vector"
done | emit statement vector

trust=$(jq -c '.trust' "$registration/vectors.json")

jq -c --argjson trust "$trust" '
    .cases[] | [($trust | tojson), .agreementJson, .claimJson, .receiptJson] | join("\n")
    ' "$registration/vectors.json" | emit registration case

jq -c --argjson trust "$trust" '
    .cases[]
    | [($trust | tojson), .anchorJson // "", .heldJson // ""] + .receiptsJson
    | join("\n")' "$registration/log.json" | emit registry_log case

# A file of audits states its own trust configuration and shared documents,
# or uses those of vectors.json.
for file in audit notice dispute; do
    jq -c --argjson trust "$trust" '
        . as $file
        | ["agreementsJson", "claimsJson", "responsesJson", "noticesJson", "documentsJson"] as $lists
        | .cases[]
        | . as $case
        | [($file.trust // $trust) | tojson] + .entriesJson + [""]
            + [$lists[] | ($case[.] // []) + ($file[.] // []) | .[]]
        | join("\n")' "$registration/$file.json" | emit registry_audit "$file"
done

jq -c '.cases[] | [.unitKeyHex, .agreementJson, .claimJson, .inputsJson] | join("\n")' \
    "$registration/unit.json" | emit registered_unit case

for target in "$out"/*; do
    echo "${target##*/}: $(find "$target" -type f | wc -l | tr -d ' ') seeds"
done
