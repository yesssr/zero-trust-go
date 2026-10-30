package nilai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

type TranskripClient struct {
	GatewayURL   string
	ClientID     string
	ClientSecret string
	HTTPClient   *http.Client
}

type apiResponse struct {
	Success bool            `json:"success"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data"`
}

type serviceTokenData struct {
	Token       string `json:"token"`
	AccessToken string `json:"access_token"`
}

func NewTranskripClient(
	gatewayURL string,
	clientID string,
	clientSecret string,
) *TranskripClient {
	return &TranskripClient{
		GatewayURL:   strings.TrimRight(gatewayURL, "/"),
		ClientID:     clientID,
		ClientSecret: clientSecret,
		HTTPClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

func (c *TranskripClient) Sync(ctx context.Context) error {
	if c.GatewayURL == "" ||
		c.ClientID == "" ||
		c.ClientSecret == "" {
		return fmt.Errorf("transcript client configuration is incomplete")
	}

	token, err := c.getServiceToken(ctx)
	if err != nil {
		return fmt.Errorf("failed to obtain service token: %w", err)
	}

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		c.GatewayURL+"/transkrip/sinkron",
		nil,
	)
	if err != nil {
		return fmt.Errorf("failed to create sync request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to call transcript service: %w", err)
	}
	defer resp.Body.Close()

	var result apiResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("failed to decode sync response: %w", err)
	}

	if resp.StatusCode < 200 ||
		resp.StatusCode >= 300 ||
		!result.Success {
		return fmt.Errorf(
			"transcript synchronization rejected: HTTP %d, %s",
			resp.StatusCode,
			result.Message,
		)
	}

	return nil
}

func (c *TranskripClient) getServiceToken(
	ctx context.Context,
) (string, error) {
	payload := map[string]string{
		"client_id":     c.ClientID,
		"client_secret": c.ClientSecret,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("failed to encode credentials: %w", err)
	}

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		c.GatewayURL+"/auth/service",
		bytes.NewReader(body),
	)
	if err != nil {
		return "", fmt.Errorf("failed to create token request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to request service token: %w", err)
	}
	defer resp.Body.Close()

	var result apiResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("failed to decode token response: %w", err)
	}

	if resp.StatusCode < 200 ||
		resp.StatusCode >= 300 ||
		!result.Success {
		return "", fmt.Errorf(
			"service authentication rejected: HTTP %d, %s",
			resp.StatusCode,
			result.Message,
		)
	}

	var tokenData serviceTokenData
	if err := json.Unmarshal(result.Data, &tokenData); err != nil {
		return "", fmt.Errorf("invalid service token response: %w", err)
	}

	token := tokenData.AccessToken
	if token == "" {
		token = tokenData.Token
	}

	if token == "" {
		return "", fmt.Errorf("service token missing from response")
	}

	return token, nil
}
