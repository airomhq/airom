package sample

import (
	"context"

	"github.com/milvus-io/milvus-sdk-go/v2/client"
	"github.com/pinecone-io/go-pinecone/pinecone"
	"github.com/qdrant/go-client/qdrant"
	"github.com/tmc/langchaingo/chains"
)

func retrieve(ctx context.Context) {
	_ = chains.Chain(nil)
	_ = pinecone.Client{}
	_ = qdrant.PointsClient(nil)
	_, _ = client.NewClient(ctx, client.Config{})
}
