import openai

def call_llm(prompt):
    return openai.Completion.create(model="gpt-3.5-turbo", prompt=prompt)
