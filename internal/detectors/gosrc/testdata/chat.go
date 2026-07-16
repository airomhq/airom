package sample

import (
	"context"

	"github.com/ollama/ollama/api"
	openai "github.com/sashabaranov/go-openai"
)

func chat(ctx context.Context, c *openai.Client) (string, error) {
	req := openai.ChatCompletionRequest{
		Model: "gpt-4o",
	}
	req.Model = "gpt-4o-mini"
	_ = api.Message{}
	resp, err := c.CreateChatCompletion(ctx, req)
	if err != nil {
		return "", err
	}
	return resp.Choices[0].Message.Content, nil
}
