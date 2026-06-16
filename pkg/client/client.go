package client

import (
	"context"
	"net/http"
)

type Client struct {
	BaseURL    string
	HTTPClient *http.Client
}

func New(baseURL string) *Client {
	return &Client{
		BaseURL:    baseURL,
		HTTPClient: http.DefaultClient,
	}
}

func (c *Client) Health(ctx context.Context) error {
	return ctx.Err()
}
