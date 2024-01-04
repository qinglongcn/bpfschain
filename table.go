package bpfschain

import "fmt"

const (
	DbFile = "database.db"
)

// InitDBTable 数据库表
func (db *SqliteDB) InitDBTable() error {
	// 创建资产数据库表
	if err := db.createAssetInfoTable(); err != nil {
		return err
	}

	return nil
}

// createAssetInfoTable 创建资产数据库表
func (s *SqliteDB) createAssetInfoTable() error {
	table := []string{
		"id INTEGER PRIMARY KEY AUTOINCREMENT", // 自增长主键
		"assetID VARCHAR(60)",                  // 文件资产的唯一标识
		"pkScript VARCHAR(200) ",               // 脚本语言
	}

	// 创建表
	if err := s.CreateTable("asset", table); err != nil {
		return fmt.Errorf("数据库操作失败")
	}

	return nil
}
