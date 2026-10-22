package telegram

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
)

type OffsetStore interface {
	Load(ctx context.Context) (int64, error)
	Save(ctx context.Context, offset int64) error
}

type MemoryOffsetStore struct {
	mu     sync.Mutex
	offset int64
}

func NewMemoryOffsetStore() *MemoryOffsetStore { return &MemoryOffsetStore{} }

func (s *MemoryOffsetStore) Load(context.Context) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.offset, nil
}

func (s *MemoryOffsetStore) Save(_ context.Context, offset int64) error {
	if offset < 0 {
		return errors.New("negative Telegram offset")
	}
	s.mu.Lock()
	s.offset = offset
	s.mu.Unlock()
	return nil
}

// FileOffsetStore persists only the update offset, never the bot token or
// message contents.
type FileOffsetStore struct{ Path string }

func (s FileOffsetStore) Load(context.Context) (int64, error) {
	data, err := os.ReadFile(s.Path)
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	offset, err := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
	if err != nil || offset < 0 {
		return 0, errors.New("invalid Telegram offset file")
	}
	return offset, nil
}

func (s FileOffsetStore) Save(_ context.Context, offset int64) error {
	if offset < 0 || s.Path == "" {
		return errors.New("invalid Telegram offset destination")
	}
	if err := os.MkdirAll(filepath.Dir(s.Path), 0o750); err != nil {
		return fmt.Errorf("create Telegram offset directory: %w", err)
	}
	temporary, err := os.CreateTemp(filepath.Dir(s.Path), ".telegram-offset-*")
	if err != nil {
		return fmt.Errorf("create Telegram offset file: %w", err)
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return err
	}
	if _, err := fmt.Fprintf(temporary, "%d\n", offset); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporaryPath, s.Path)
}
