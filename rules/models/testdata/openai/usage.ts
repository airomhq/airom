// OpenAI usage fixture — positive and negative cases.
import OpenAI from "openai";

const client = new OpenAI({ apiKey: process.env.OPENAI_API_KEY! });

export async function ask(question: string): Promise<string> {
  // airom: openai/chat-call
  const resp = await client.chat.completions.create({
    // airom: openai/model-literal
    model: "gpt-4.1-mini",
    temperature: 0.1,
    max_tokens: 512,
    messages: [{ role: "user", content: question }],
  });
  return resp.choices[0].message?.content ?? "";
}

// Negative cases below.

// airom-ok: openai/model-literal
const label = "gpt-shop-banner"; // not a model= position

// airom-ok: openai/chat-call
const page = client.chat.completions.list();
