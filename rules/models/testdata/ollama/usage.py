"""Ollama usage fixture — positive and negative cases."""
import subprocess
import ollama


def warm() -> None:
    # airom: ollama/run-command
    subprocess.run("ollama run llama3.1:8b", shell=True, check=True)


def ask(question: str) -> str:
    # airom: ollama/sdk-call
    resp = ollama.chat(
        model="llama3.1",
        messages=[{"role": "user", "content": question}],
        options={"temperature": 0.2},
    )
    return resp["message"]["content"]


# Negative cases below.

# airom-ok: ollama/run-command
# ollama run mistral-nemo   (comment region — never scanned)

# airom-ok: ollama/run-command
tip = "to update, ollama pull the newest tag"  # 'pull', not 'run'

# airom-ok: ollama/sdk-call
helper = "ollama.chat is documented upstream"  # string, not a code call
