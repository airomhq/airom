"""Hugging Face transformers usage fixture — positive and negative cases."""
from transformers import AutoModelForCausalLM, pipeline
from sklearn.pipeline import Pipeline

# airom: huggingface/from-pretrained
model = AutoModelForCausalLM.from_pretrained("meta-llama/Meta-Llama-3-8B-Instruct")

# airom: huggingface/pipeline
generator = pipeline("text-generation", model="distilgpt2")


# Negative cases below.

# airom-ok: huggingface/from-pretrained
# AutoModel.from_pretrained("bigscience/bloom-560m")   (comment — never scanned)

# airom-ok: huggingface/from-pretrained
tok = AutoModelForCausalLM.from_pretrained("bert-base-uncased")  # no org/name slash

# airom-ok: huggingface/pipeline
flow = Pipeline(steps=[])  # sklearn Pipeline is capitalized, keyword is lowercase


def documented():
    """Load a checkpoint.

    The example below is documentation, not a call. Before docstrings were
    classified apart from strings, lines like this made up 42% of a scan of
    huggingface/transformers.

    >>> model = AutoModel.from_pretrained("facebook/esmfold_v1")
    """
    # airom-ok: huggingface/from-pretrained
    return None
