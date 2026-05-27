#!/bin/sh

MODELS="qwen2.5-coder:7b gemma3:12b"
WINDOWS=2048 4096 8192 16384"

if [ $# -ne 1 ]; then
  echo "$0: <application>" 1>&2
  exit 1
fi

cd harness
for model in $MODELS ; do
  for window in $WINDOWS ; do
    ./scan.py -c ${window} -m ${model} $1 > $(basename $1).${window}.json
  done
done
