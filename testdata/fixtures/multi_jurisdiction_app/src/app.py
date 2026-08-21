import torch
torch.load('model.pth', weights_only=False)
import openai
openai.ChatCompletion.create(model='gpt-4')
print('resume screening AI')
