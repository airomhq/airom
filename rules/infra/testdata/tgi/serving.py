"""TGI (text-generation-inference) serving fixture."""
image = "ghcr.io/huggingface/text-generation-inference:2.0"  # airom: tgi/reference
run = "text-generation-launcher --model-id gpt2 --port 8080"  # airom: tgi/launcher

# airom-ok: tgi/reference
note = "TGI stands for text generation inference"

# airom-ok: tgi/launcher
doc = "launch the text generation launcher binary"
