"""Cohere embeddings usage fixture — positive and negative cases."""
import cohere

co = cohere.ClientV2(api_key="KEY")


def embed(texts: list[str]) -> list[list[float]]:
    resp = co.embed(
        texts=texts,
        # airom: cohere-embed/model-literal
        model="embed-english-v3.0",
        input_type="search_document",
    )
    return resp.embeddings.float


# airom: cohere-embed/model-literal
MULTI = {"model": "embed-multilingual-light-v3.0"}


# Negative cases below.

# airom-ok: cohere-embed/model-literal
# model="embed-english-light-v3.0"   (comment region — never scanned)

# airom-ok: cohere-embed/model-literal
verb = "embed-a-video-player"  # 'embed-' but not an english/multilingual embedding id
