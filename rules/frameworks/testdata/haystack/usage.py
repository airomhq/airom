"""Haystack usage fixture — positive and negative cases."""
from haystack import Pipeline  # airom: haystack/import
from haystack.components.generators import OpenAIGenerator  # airom: haystack/import

# airom: haystack/pipeline
pipe = Pipeline()

# airom-ok: haystack/import
txt = "a needle in a haystack"

# airom-ok: haystack/pipeline
name = "Pipeline stage overview"
