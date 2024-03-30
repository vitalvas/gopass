package filevault

import "testing"

func TestGetKeyPath(t *testing.T) {
	key := []byte{0x01, 0x02, 0x03, 0x04}
	expectedPath := "01/02/03/01020304.txt"
	expectedDir := "01/02/03"

	filePath, fileDir := getKeyPath(key)
	if filePath != expectedPath {
		t.Errorf("Expected path %s, got %s", expectedPath, filePath)
	}

	if fileDir != expectedDir {
		t.Errorf("Expected dir %s, got %s", expectedDir, fileDir)
	}
}
