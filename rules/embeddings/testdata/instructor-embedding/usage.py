"""INSTRUCTOR embeddings usage fixture — positive and negative cases."""
from InstructorEmbedding import INSTRUCTOR

# airom: instructor-embedding/constructor
# airom: instructor-embedding/model-literal
model = INSTRUCTOR("hkunlp/instructor-large")


# airom: instructor-embedding/model-literal
XL = {"model": "hkunlp/instructor-xl"}


# Negative cases below.

# airom-ok: instructor-embedding/constructor
# INSTRUCTOR("hkunlp/instructor-base")   (comment region — never scanned)

# airom-ok: instructor-embedding/model-literal
doc = "hkunlp/instructor is the org/repo prefix"  # no '-<variant>' after 'instructor'

# airom-ok: instructor-embedding/constructor
label = "INSTRUCTOR_EMBEDDING_DIM"  # constant name, not a constructor call
