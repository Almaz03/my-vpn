package telegram

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type HTTPDoer interface {
	Do(*http.Request) (*http.Response, error)
}

type apiClient struct {
	baseURL     string
	http        HTTPDoer
	pollSeconds int
}

func newAPIClient(token, baseURL string, client HTTPDoer, pollTimeout time.Duration) (*apiClient, error) {
	if strings.ContainsAny(token, "/?#\r\n") {
		return nil, errors.New("Telegram token contains invalid characters")
	}
	if baseURL == "" {
		baseURL = "https://api.telegram.org"
	}
	parsed, err := url.Parse(baseURL)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" || parsed.User != nil {
		return nil, errors.New("invalid Telegram API base URL")
	}
	if client == nil {
		client = &http.Client{Timeout: 45 * time.Second}
	}
	if pollTimeout <= 0 {
		pollTimeout = 30 * time.Second
	}
	if pollTimeout > 40*time.Second {
		pollTimeout = 40 * time.Second
	}
	return &apiClient{
		baseURL: strings.TrimRight(baseURL, "/") + "/bot" + token,
		http:    client, pollSeconds: int(pollTimeout.Seconds()),
	}, nil
}

type apiUpdate struct {
	ID       int64             `json:"update_id"`
	Message  *apiMessage       `json:"message"`
	Callback *apiCallbackQuery `json:"callback_query"`
}

type apiMessage struct {
	MessageID int64    `json:"message_id"`
	From      *apiUser `json:"from"`
	Chat      apiChat  `json:"chat"`
	Text      string   `json:"text"`
}

type apiUser struct {
	ID int64 `json:"id"`
}

type apiChat struct {
	ID int64 `json:"id"`
}

type apiCallbackQuery struct {
	ID      string      `json:"id"`
	From    *apiUser    `json:"from"`
	Message *apiMessage `json:"message"`
	Data    string      `json:"data"`
}

type inlineKeyboard struct {
	InlineKeyboard [][]inlineButton `json:"inline_keyboard"`
}

type inlineButton struct {
	Text         string          `json:"text"`
	CallbackData string          `json:"callback_data,omitempty"`
	CopyText     *copyTextButton `json:"copy_text,omitempty"`
}

type copyTextButton struct {
	Text string `json:"text"`
}

type apiResponse[T any] struct {
	OK     bool `json:"ok"`
	Result T    `json:"result"`
}

func (c *apiClient) getUpdates(ctx context.Context, offset int64) ([]apiUpdate, error) {
	payload := map[string]any{
		"offset": offset, "timeout": c.pollSeconds,
		"allowed_updates": []string{"message", "callback_query"},
	}
	var response apiResponse[[]apiUpdate]
	if err := c.call(ctx, "getUpdates", payload, &response, &response.OK); err != nil {
		return nil, err
	}
	return response.Result, nil
}

func (c *apiClient) sendMessage(ctx context.Context, chatID int64, text string, keyboard *inlineKeyboard) error {
	payload := map[string]any{"chat_id": chatID, "text": truncate(text), "disable_web_page_preview": true}
	if keyboard != nil {
		payload["reply_markup"] = keyboard
	}
	var response apiResponse[json.RawMessage]
	return c.call(ctx, "sendMessage", payload, &response, &response.OK)
}

func (c *apiClient) answerCallback(ctx context.Context, callbackID, text string) error {
	payload := map[string]any{"callback_query_id": callbackID, "text": text, "show_alert": false}
	var response apiResponse[bool]
	return c.call(ctx, "answerCallbackQuery", payload, &response, &response.OK)
}

func (c *apiClient) call(ctx context.Context, method string, payload any, target any, ok *bool) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("encode Telegram %s request: %w", method, err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/"+method, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create Telegram %s request: %w", method, err)
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := c.http.Do(request)
	if err != nil {
		return fmt.Errorf("Telegram %s request failed", method)
	}
	defer response.Body.Close()
	limited := io.LimitReader(response.Body, 1<<20)
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		_, _ = io.Copy(io.Discard, limited)
		return fmt.Errorf("Telegram %s returned HTTP %d", method, response.StatusCode)
	}
	if err := json.NewDecoder(limited).Decode(target); err != nil {
		return fmt.Errorf("decode Telegram %s response: %w", method, err)
	}
	if !*ok {
		return fmt.Errorf("Telegram %s rejected request", method)
	}
	return nil
}
