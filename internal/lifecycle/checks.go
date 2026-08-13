package lifecycle

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"time"
)

type HTTPCheck struct {
	URL    string
	Client *http.Client
}

func (c HTTPCheck) Check(ctx context.Context) error {
	if c.URL == "" {
		return fmt.Errorf("endpoint is not configured")
	}
	client := c.Client
	if client == nil {
		client = &http.Client{Timeout: 2 * time.Second}
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodHead, c.URL, nil)
	if err != nil {
		return err
	}
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode >= 500 {
		return fmt.Errorf("endpoint returned %d", response.StatusCode)
	}
	return nil
}

type FileCheck string

func (path FileCheck) Check(context.Context) error {
	if path == "" {
		return fmt.Errorf("material path is not configured")
	}
	if _, err := os.Stat(string(path)); err != nil {
		return fmt.Errorf("check pinned material: %w", err)
	}
	return nil
}
