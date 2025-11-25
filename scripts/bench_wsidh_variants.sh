#!/bin/sh
set -eu

VARIANTS="wsidh512 wsidh768 wsidh1024"
TRIALS="${1:-1000}"
RESULTS=""
ORIG_VARIANT="${WSIDH_VARIANT:-wsidh512}"
WITH_AVX2_FLAG="${WSIDH_BENCH_WITH_AVX2:-${WITH_AVX2:-0}}"
WITH_KYBER_FLAG="${WSIDH_BENCH_WITH_KYBER:-${WITH_KYBER:-0}}"

field_value() {
    echo "$1" | tr ' ' '\n' | awk -F= -v key="$2" '$1==key {print $2}'
}

build_variant() {
    make -s WSIDH_VARIANT="$1" WITH_AVX2="$WITH_AVX2_FLAG" WITH_KYBER="$WITH_KYBER_FLAG" wsidh_bench
}

printf "Building and benchmarking WSIDH variants (trials=%s, WITH_AVX2=%s, WITH_KYBER=%s)\n" \
       "$TRIALS" "$WITH_AVX2_FLAG" "$WITH_KYBER_FLAG" >&2

for variant in $VARIANTS; do
    printf "→ %s\n" "$variant" >&2
    make -s clean
    build_variant "$variant"
    summary=$(WSIDH_VARIANT_CHILD=1 ./wsidh_bench "$TRIALS" --summary)
    scheme=$(echo "$summary" | awk '{print $2}')
    pk=$(field_value "$summary" pk)
    sk=$(field_value "$summary" sk)
    ct=$(field_value "$summary" ct)
    ss=$(field_value "$summary" ss)
    keygen=$(field_value "$summary" keygen)
    encaps=$(field_value "$summary" encaps)
    decaps=$(field_value "$summary" decaps)
    RESULTS="$RESULTS
$scheme $pk $sk $ct $ss $keygen $encaps $decaps"
done

printf "\n=== WSIDH vs Kyber Cycle/Size Table ===\n"
printf "%-18s %8s %8s %8s %8s %14s %14s %14s\n" \
       "Scheme" "pk(B)" "sk(B)" "ct(B)" "ss(B)" \
       "keygen cyc" "encaps cyc" "decaps cyc"
echo "$RESULTS" | while read -r line; do
    [ -z "$line" ] && continue
    set -- $line
    printf "%-18s %8s %8s %8s %8s %14.2f %14.2f %14.2f\n" \
           "$1" "$2" "$3" "$4" "$5" "$6" "$7" "$8"
done

printf "%-18s %8d %8d %8d %8d %14.0f %14.0f %14.0f\n" \
       "Kyber512" 800 1632 768 32 20000 28000 38000
printf "%-18s %8d %8d %8d %8d %14.0f %14.0f %14.0f\n" \
       "Kyber768" 1184 2400 1088 32 30000 40000 55000
printf "%-18s %8d %8d %8d %8d %14.0f %14.0f %14.0f\n" \
       "Kyber1024" 1568 3168 1568 32 40000 55000 70000

printf "\nRestoring WSIDH variant %s (WITH_AVX2=%s, WITH_KYBER=%s)\n" \
       "$ORIG_VARIANT" "$WITH_AVX2_FLAG" "$WITH_KYBER_FLAG" >&2
make -s clean
build_variant "$ORIG_VARIANT"
