// 定义共享的基类和方法
package bpfschain

import (
	"fmt"
	"path/filepath"

	"github.com/spf13/afero"
)

// FileStore 封装了文件存储的操作
type FileStore struct {
	Fs       afero.Fs
	BasePath string
}

// NewFileStore 创建一个新的FileStore实例
func NewFileStore(basePath string) (*FileStore, error) {
	fs := afero.NewOsFs()
	if err := fs.MkdirAll(basePath, 0755); err != nil {
		return nil, fmt.Errorf("failed to create base directory: %w", err)
	}
	return &FileStore{Fs: fs, BasePath: basePath}, nil
}

// CreateFile 在指定子目录创建一个新文件
func (fs *FileStore) CreateFile(subDir, fileName string) error {
	filePath := filepath.Join(fs.BasePath, subDir, fileName)
	file, err := fs.Fs.Create(filePath)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	return file.Close()
}
