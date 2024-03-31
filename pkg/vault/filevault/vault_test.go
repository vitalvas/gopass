package filevault

import (
	"os"
	"testing"
)

func TestNew(t *testing.T) {
	storagePath, err := os.MkdirTemp("", "gopass")
	if err != nil {
		t.Errorf("Error creating temp dir: %v", err)
	}

	defer os.RemoveAll(storagePath)

	v := New(storagePath)

	if v.storagePath != storagePath {
		t.Errorf("Expected storagePath to be %s, got %s", storagePath, v.storagePath)
	}
}

func TestClose(t *testing.T) {
	v := New("")

	err := v.Close()

	if err != nil {
		t.Errorf("Expected Close() to return nil, got %v", err)
	}
}
