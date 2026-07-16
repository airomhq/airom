"""Azure OpenAI usage fixture — positive and negative cases."""
import os
from openai import AzureOpenAI

# airom: azure-openai/client-construct
client = AzureOpenAI(
    api_version="2024-06-01",
    azure_endpoint=os.environ["AZURE_OPENAI_ENDPOINT"],
    # airom: azure-openai/deployment-literal
    azure_deployment="prod-gpt4o",
)


def ask(question: str) -> str:
    # airom: azure-openai/deployment-literal
    params = {"deployment_name": "gpt4o-eastus"}
    return client.chat.completions.create(model=params["deployment_name"], messages=[]).choices[0].message.content


# Negative cases below.

# airom-ok: azure-openai/deployment-literal
# azure_deployment="staging-gpt4"   (comment region — never scanned)

# airom-ok: azure-openai/deployment-literal
region = "eastus2"  # not a deployment field

# airom-ok: azure-openai/client-construct
factory = "AzureOpenAIFactory"  # string, not a constructor call
