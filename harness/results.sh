#!/usr/bin/env bash

if [ $# -lt 1 ]; then
  echo "$0 <modelresult.json> ..." 1>&2
  exit 1
fi

for f in $@ ; do
  cat $f | jq '{ "repository": .repository, "model_name": .model, "context_window": { "size": .context_size, "exceeded": .metrics.context_window_exceeded }, "tokens": { "eval": .metrics.eval_count, "context_window": .metrics.prompt_eval_count }  }'
  echo

  cat $f | jq -r '.response'
  echo
  echo
done
