#!/usr/bin/env bash
# Fetch + normalize the detection-benchmark corpus into data/bench/.
#
# Requires network, `curl`, `jq`, and a built `helmet-bench` binary.
# Pulls only VENDORABLE datasets (see docs/benchmark/detection-benchmark-spec.md).
# Re-runnable; each dataset overwrites its own data/bench/<split>/<source>.jsonl.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RAW="$ROOT/data/bench/raw"
BENCH="$ROOT/data/bench"
BIN="${HELMET_BENCH_BIN:-$ROOT/target/debug/helmet-bench}"
DS="https://datasets-server.huggingface.co/rows"

mkdir -p "$RAW"
[ -x "$BIN" ] || { echo "build first: cargo build -p helmet-bench (or set HELMET_BENCH_BIN)"; exit 1; }

# Read-only HF token from .env (for gated datasets, e.g. hackaprompt).
# Gated="auto" datasets also require accepting their terms once on huggingface.co.
if [ -z "${HF_TOKEN:-}" ] && [ -f "$ROOT/.env" ]; then
  set -a; . "$ROOT/.env"; set +a
fi
AUTH=()
[ -n "${HF_TOKEN:-}" ] && AUTH=(-H "Authorization: Bearer $HF_TOKEN")

# hf_pull <dataset> <config> <split> <out.jsonl> [max]
# Pages the datasets-server API and flattens .rows[].row to one JSON object per line.
hf_pull() {
  local dataset="$1" config="$2" split="$3" out="$4" max="${5:-100000}"
  local offset=0 length=100 got
  : > "$out"
  while [ "$offset" -lt "$max" ]; do
    local resp
    resp="$(curl -sS --max-time 60 "${AUTH[@]}" \
      "$DS?dataset=${dataset}&config=${config}&split=${split}&offset=${offset}&length=${length}")"
    got="$(printf '%s' "$resp" | jq '.rows | length')"
    [ "$got" = "null" ] && { echo "  ! API error for $dataset/$config/$split: $(printf '%s' "$resp" | head -c200)"; break; }
    [ "$got" -eq 0 ] && break
    printf '%s' "$resp" | jq -c '.rows[].row' >> "$out"
    offset=$((offset + got))
    [ "$got" -lt "$length" ] && break
  done
  echo "  fetched $(wc -l < "$out") rows -> $out"
}

echo "== NotInject (MIT) -> benign_hard =="
: > "$RAW/notinject.jsonl"
for sp in NotInject_one NotInject_two NotInject_three; do
  hf_pull "leolee99/NotInject" "default" "$sp" "$RAW/notinject_$sp.jsonl"
  cat "$RAW/notinject_$sp.jsonl" >> "$RAW/notinject.jsonl"
done
"$BIN" ingest --input "$RAW/notinject.jsonl" --text-field prompt --label-const 0 \
  --split benign_hard --source notinject --out "$BENCH"

echo "== JBB-Behaviors (MIT) -> direct + benign_easy =="
hf_pull "JailbreakBench/JBB-Behaviors" "behaviors" "harmful" "$RAW/jbb_harmful.jsonl"
hf_pull "JailbreakBench/JBB-Behaviors" "behaviors" "benign"  "$RAW/jbb_benign.jsonl"
"$BIN" ingest --input "$RAW/jbb_harmful.jsonl" --text-field Goal --label-const 1 \
  --split direct --source jbb --out "$BENCH"
"$BIN" ingest --input "$RAW/jbb_benign.jsonl" --text-field Goal --label-const 0 \
  --split benign_easy --source jbb --out "$BENCH"

# hackaprompt (MIT, huge): sample a slice rather than the full corpus.
echo "== hackaprompt (MIT) -> direct (sampled) =="
hf_pull "hackaprompt/hackaprompt-dataset" "default" "train" "$RAW/hackaprompt.jsonl" 2000 || true
if [ -s "$RAW/hackaprompt.jsonl" ]; then
  "$BIN" ingest --input "$RAW/hackaprompt.jsonl" --text-field user_input --label-const 1 \
    --split direct --source hackaprompt --out "$BENCH" || \
    echo "  ! adjust --text-field for hackaprompt (inspect $RAW/hackaprompt.jsonl)"
fi

echo "== SPML (MIT) -> direct (labeled) =="
hf_pull "reshabhs/SPML_Chatbot_Prompt_Injection" "default" "train" "$RAW/spml.jsonl" 2000
"$BIN" ingest --input "$RAW/spml.jsonl" --text-field "User Prompt" --label-field "Prompt injection" \
  --split direct --source spml --out "$BENCH"

echo "== yanismiraoui (Apache-2.0) -> multilingual =="
hf_pull "yanismiraoui/prompt_injections" "default" "train" "$RAW/yani.jsonl"
"$BIN" ingest --input "$RAW/yani.jsonl" --text-field prompt_injections --label-const 1 \
  --split multilingual --source yanismiraoui --lang multi --out "$BENCH"

echo "== Lakera/gandalf_summarization (MIT) -> indirect =="
hf_pull "Lakera/gandalf_summarization" "default" "train" "$RAW/gandalf_summ.jsonl"
"$BIN" ingest --input "$RAW/gandalf_summ.jsonl" --text-field text --label-const 1 \
  --split indirect --source gandalf_summ --channel indirect --out "$BENCH"

echo "== microsoft/llmail-inject-challenge (MIT) -> indirect (sampled) =="
hf_pull "microsoft/llmail-inject-challenge" "default" "Phase1" "$RAW/llmail.jsonl" 1000
"$BIN" ingest --input "$RAW/llmail.jsonl" --text-field body --label-const 1 \
  --split indirect --source llmail --channel indirect --out "$BENCH"

echo
echo "Done. Regenerate obfuscation split from the new direct attacks, e.g.:"
echo "  $BIN augment --input $BENCH/direct/jbb.jsonl --source jbb --out $BENCH"
echo "NOTE: BIPIA (CC-BY-SA-4.0, indirect) is a git repo -> add separately with attribution."
