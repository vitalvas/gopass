package filevault

import (
	"os"
	"path/filepath"
)

func cleanupStorage(storagePath string) error {
	var err error
	for range 2 {
		err = filepath.Walk(storagePath, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if info.IsDir() {
				entries, err := os.ReadDir(path)
				if err != nil {
					return err
				}

				if len(entries) == 0 {
					return os.Remove(path)
				}
			}

			return nil
		})

		if err != nil {
			return err
		}
	}
	return err
}
