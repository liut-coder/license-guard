package licensecore

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
)

var ErrStoreNotFound = errors.New("store not found")

type Store interface {
	Load() (Data, error)
	Save(Data) error
	Name() string
}

type JSONStore struct {
	path string
}

func NewJSONStore(dataDir string) (*JSONStore, error) {
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return nil, err
	}
	return &JSONStore{path: filepath.Join(dataDir, "store.json")}, nil
}

func (s *JSONStore) Name() string {
	return "json:" + s.path
}

func (s *JSONStore) Load() (Data, error) {
	raw, err := os.ReadFile(s.path)
	if err == nil {
		var data Data
		if err := json.Unmarshal(raw, &data); err != nil {
			return Data{}, err
		}
		return data, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return Data{}, ErrStoreNotFound
	}
	return Data{}, err
}

func (s *JSONStore) Save(data Data) error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return err
	}
	payload, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.path, payload, 0o600)
}
