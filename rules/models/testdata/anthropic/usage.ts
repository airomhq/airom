// Anthropic usage fixture — positive and negative cases.
import Anthropic from "@anthropic-ai/sdk";

const client = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY! });

export async function ask(question: string): Promise<string> {
  // airom: anthropic/messages-call
  const resp = await client.messages.create({
    // airom: anthropic/model-literal
    model: "claude-opus-4-20250514",
    max_tokens: 512,
    messages: [{ role: "user", content: question }],
  });
  return resp.content[0].type === "text" ? resp.content[0].text : "";
}

// Negative cases below.

// airom-ok: anthropic/model-literal
const codename = "claude-desktop-build"; // not a model= position

// airom-ok: anthropic/messages-call
const batch = client.messages.batches.create;
