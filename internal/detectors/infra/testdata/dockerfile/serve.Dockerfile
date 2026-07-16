FROM vllm/vllm-openai:v0.5.0

ENV MODEL_ID=meta-llama/Llama-3-8B
EXPOSE 8000/tcp

CMD ["--model", "meta-llama/Llama-3-8B"]
