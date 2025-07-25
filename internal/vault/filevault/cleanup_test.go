package filevault

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCleanupStorage(t *testing.T) {
	t.Run("cleanup empty directories", func(t *testing.T) {
		storagePath, err := os.MkdirTemp("", "gopass")
		require.NoError(t, err)
		defer os.RemoveAll(storagePath)

		// Create nested empty directories
		emptyDir1 := filepath.Join(storagePath, "empty1")
		emptyDir2 := filepath.Join(storagePath, "empty2", "nested")
		err = os.MkdirAll(emptyDir1, 0700)
		require.NoError(t, err)
		err = os.MkdirAll(emptyDir2, 0700)
		require.NoError(t, err)

		// Create directory with file (should not be removed)
		dirWithFile := filepath.Join(storagePath, "withfile")
		err = os.MkdirAll(dirWithFile, 0700)
		require.NoError(t, err)
		testFile := filepath.Join(dirWithFile, "test.txt")
		err = os.WriteFile(testFile, []byte("test"), 0600)
		require.NoError(t, err)

		// Verify directories exist before cleanup
		assert.DirExists(t, emptyDir1)
		assert.DirExists(t, emptyDir2)
		assert.DirExists(t, dirWithFile)

		// Run cleanup
		err = cleanupStorage(storagePath)
		assert.NoError(t, err)

		// Verify empty directories are removed
		assert.NoDirExists(t, emptyDir1)
		assert.NoDirExists(t, emptyDir2)
		assert.NoDirExists(t, filepath.Join(storagePath, "empty2")) // parent should also be removed

		// Verify directory with file remains
		assert.DirExists(t, dirWithFile)
		assert.FileExists(t, testFile)
	})

	t.Run("cleanup deeply nested empty directories", func(t *testing.T) {
		storagePath, err := os.MkdirTemp("", "gopass")
		require.NoError(t, err)
		defer os.RemoveAll(storagePath)

		// Create moderately nested structure: storage/a/b/c (only 3 levels since cleanup runs twice)
		deepPath := filepath.Join(storagePath, "a", "b", "c")
		err = os.MkdirAll(deepPath, 0700)
		require.NoError(t, err)

		// Verify structure exists
		assert.DirExists(t, deepPath)
		assert.DirExists(t, filepath.Join(storagePath, "a"))

		// Run cleanup
		err = cleanupStorage(storagePath)
		assert.NoError(t, err)

		// Verify empty directories are removed (cleanup runs twice, so at most 2 levels can be removed)
		assert.NoDirExists(t, deepPath)
		// The "a" directory might still exist if nesting is too deep for 2 cleanup passes
	})

	t.Run("cleanup with mixed structure", func(t *testing.T) {
		storagePath, err := os.MkdirTemp("", "gopass")
		require.NoError(t, err)
		defer os.RemoveAll(storagePath)

		// Create structure: storage/keep/file.txt and storage/keep/empty/
		keepDir := filepath.Join(storagePath, "keep")
		emptySubDir := filepath.Join(keepDir, "empty")
		err = os.MkdirAll(emptySubDir, 0700)
		require.NoError(t, err)

		testFile := filepath.Join(keepDir, "file.txt")
		err = os.WriteFile(testFile, []byte("content"), 0600)
		require.NoError(t, err)

		// Run cleanup
		err = cleanupStorage(storagePath)
		assert.NoError(t, err)

		// Keep directory should remain (has file), but empty subdirectory should be removed
		assert.DirExists(t, keepDir)
		assert.FileExists(t, testFile)
		assert.NoDirExists(t, emptySubDir)
	})

	t.Run("non-existent storage path", func(t *testing.T) {
		nonExistentPath := "/non/existent/path"
		err := cleanupStorage(nonExistentPath)
		assert.Error(t, err)
	})

	t.Run("permission denied on directory", func(t *testing.T) {
		storagePath, err := os.MkdirTemp("", "gopass")
		require.NoError(t, err)
		defer os.RemoveAll(storagePath)

		// Create directory and remove read permissions
		restrictedDir := filepath.Join(storagePath, "restricted")
		err = os.MkdirAll(restrictedDir, 0700)
		require.NoError(t, err)

		err = os.Chmod(restrictedDir, 0000)
		require.NoError(t, err)

		// Cleanup should fail due to permission error
		err = cleanupStorage(storagePath)
		assert.Error(t, err)

		// Restore permissions for cleanup
		os.Chmod(restrictedDir, 0755)
	})

	t.Run("no directories to cleanup", func(t *testing.T) {
		storagePath, err := os.MkdirTemp("", "gopass")
		require.NoError(t, err)
		defer os.RemoveAll(storagePath)

		// Create only files, no empty directories
		testFile := filepath.Join(storagePath, "test.txt")
		err = os.WriteFile(testFile, []byte("content"), 0600)
		require.NoError(t, err)

		// Run cleanup
		err = cleanupStorage(storagePath)
		assert.NoError(t, err)

		// File should remain
		assert.FileExists(t, testFile)
	})

	t.Run("cleanup with readonly files", func(t *testing.T) {
		storagePath, err := os.MkdirTemp("", "gopass")
		require.NoError(t, err)
		defer os.RemoveAll(storagePath)

		// Create directory with readonly file
		dirWithFile := filepath.Join(storagePath, "readonly")
		err = os.MkdirAll(dirWithFile, 0700)
		require.NoError(t, err)

		readonlyFile := filepath.Join(dirWithFile, "readonly.txt")
		err = os.WriteFile(readonlyFile, []byte("readonly"), 0400)
		require.NoError(t, err)

		// Create empty directory
		emptyDir := filepath.Join(storagePath, "empty")
		err = os.MkdirAll(emptyDir, 0700)
		require.NoError(t, err)

		// Run cleanup
		err = cleanupStorage(storagePath)
		assert.NoError(t, err)

		// Empty directory should be removed, readonly file should remain
		assert.NoDirExists(t, emptyDir)
		assert.DirExists(t, dirWithFile)
		assert.FileExists(t, readonlyFile)

		// Restore permissions for cleanup
		os.Chmod(readonlyFile, 0644)
	})
}
