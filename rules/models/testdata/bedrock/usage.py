"""Amazon Bedrock usage fixture — positive and negative cases."""
import json
import boto3

# airom: bedrock/runtime-call
client = boto3.client("bedrock-runtime", region_name="us-east-1")


def ask(prompt: str) -> str:
    # airom: bedrock/model-literal
    model_id = "anthropic.claude-3-5-sonnet-20240620-v1:0"
    # airom: bedrock/runtime-call
    resp = client.invoke_model(
        modelId=model_id,
        body=json.dumps({"prompt": prompt}),
    )
    return resp["body"].read().decode()


# airom: bedrock/model-literal
TITAN = "amazon.titan-text-express-v1"
# airom: bedrock/model-literal
LLAMA = "us.meta.llama3-1-70b-instruct-v1:0"


# Negative cases below.

# airom-ok: bedrock/model-literal
# "anthropic.claude-instant-v1"   (comment region — never scanned)

# airom-ok: bedrock/model-literal
pkg = "org.apache.commons.lang3"  # dotted, but not a bedrock vendor prefix

# airom-ok: bedrock/runtime-call
note = "call list_foundation_models to enumerate ids"

# ── Regression: a dotted tail is not a model id ────────────────────────────
# All of these were reported as Bedrock hosted LLMs by a scan of one laptop.
# They are postMessage RPC names out of Claude Desktop's minified bundle.

# airom-ok: bedrock/model-literal
rpc1 = "anthropic.claude.usercontent.mcpapp.bridgetohost"

# airom-ok: bedrock/model-literal
rpc2 = "anthropic.claude.usercontent.sandbox.setcontent"

# airom-ok: bedrock/model-literal
host = "anthropic.com"                      # a domain, not a model

# airom-ok: bedrock/model-literal
helper = "anthropic.sdk.stainlesshelper"    # an internal class path

# A short-form id with no version suffix is still a real Bedrock alias.
# airom: bedrock/model-literal
ALIAS = "anthropic.claude-haiku-4-5"
