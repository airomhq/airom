"""Google Gemini usage fixture — positive and negative cases."""
import google.generativeai as genai

genai.configure(api_key="KEY")

# airom: gemini/sdk-call
# airom: gemini/model-literal
model = genai.GenerativeModel("gemini-1.5-pro")


def ask(question: str) -> str:
    # airom: gemini/sdk-call
    resp = model.generate_content(question)
    return resp.text


# airom: gemini/model-literal
CONFIG = {"model": "models/gemini-2.0-flash"}


# Negative cases below.

# airom-ok: gemini/model-literal
# "gemini-1.0-pro"   (comment region — never scanned)

# airom-ok: gemini/model-literal
zodiac = "gemini season starts in may"  # no gemini- token, keyword miss

# airom-ok: gemini/sdk-call
loader = "GenerativeModelLoader"  # bare identifier, no call
