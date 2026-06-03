
cat > /home/research/ai-sast-harness/harness/run_retrieval.sh << 'EOF'
#!/bin/sh
MODELS="qwen2.5-coder:7b gemma3:12b"
CONTEXTS="4096 8192 16384"

if [ $# -ne 1 ]; then
  echo "$0: <application>" 1>&2
  exit 1
fi

for model in $MODELS; do
  for ctx in $CONTEXTS; do
    ./scan_retrieval.py -c ${ctx} -m ${model} $1 > retrieval.$(basename $1).${model}.${ctx}.json
  done
done
EOF
chmod +x /home/research/ai-sast-harness/harness/run_retrieval.sh
