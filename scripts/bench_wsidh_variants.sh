#!/bin/sh
set -e

VARIANTS="wsidh512 wsidh768 wsidh1024"
TRIALS="${1:-1000}"
RESULTS=""

field_value() {
    echo "$1" | tr ' ' '\n' | awk -F= -v key="$2" '$1==key {print $2}'
}

printf "Building and benchmarking WSIDH variants (trials=%s)\n" "$TRIALS" >&2

for variant in $VARIANTS; do
    printf "→ %s\n" "$variant" >&2
    make -s clean
    make -s WSIDH_VARIANT="$variant" wsidh_bench
    summary=$(./wsidh_bench "$TRIALS" --summary)
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

printf "\n=== WSIDH Variant Cycle/Size Table ===\n"
printf "%-10s %8s %8s %8s %8s %14s %14s %14s\n" \
       "Scheme" "pk(B)" "sk(B)" "ct(B)" "ss(B)" \
       "keygen cyc" "encaps cyc" "decaps cyc"
echo "$RESULTS" | while read -r line; do
    [ -z "$line" ] && continue
    set -- $line
    printf "%-10s %8s %8s %8s %8s %14.2f %14.2f %14.2f\n" \
           "$1" "$2" "$3" "$4" "$5" "$6" "$7" "$8"
done

printf "\n=== Kyber Reference (cycles provided by submitters) ===\n"
printf "%-10s %8s %8s %8s %8s %14s %14s %14s\n" \
       "Scheme" "pk(B)" "sk(B)" "ct(B)" "ss(B)" \
       "keygen cyc" "encaps cyc" "decaps cyc"
printf "%-10s %8d %8d %8d %8d %14.0f %14.0f %14.0f\n" \
       "Kyber512" 800 1632 768 32 20000 28000 38000
printf "%-10s %8d %8d %8d %8d %14.0f %14.0f %14.0f\n" \
       "Kyber768" 1184 2400 1088 32 30000 40000 55000
printf "%-10s %8d %8d %8d %8d %14.0f %14.0f %14.0f\n" \
       "Kyber1024" 1568 3168 1568 32 40000 55000 70000
