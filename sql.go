package bpfschain

import (
	"fmt"
)

// 资产的数据库对象
type AssetDatabase struct {
	Id       int    // 自增长主键
	AssetID  string // 资产的唯一标识
	PKScript string // 脚本语言
}

// ExistsAssetDatabase 判断资产数据库对象是否存在
func ExistsAssetDatabase(s *SqliteDB, assetID string) (bool, error) {
	conditions := []string{"assetID=?"} // 查询条件
	args := []interface{}{assetID}      // 查询条件对应的值
	exists, err := s.Exists("asset", conditions, args)
	if err != nil {
		return exists, fmt.Errorf("数据库操作失败")
	}

	return exists, nil
}

// 保存上传记录到数据库
func (ad *AssetDatabase) CreateFileDatabase(s *SqliteDB) error {
	data := map[string]interface{}{
		"assetID":  ad.AssetID,  // 资产的唯一标识
		"pkScript": ad.PKScript, // 脚本语言(内部标识)
	}

	if err := s.Insert("asset", data); err != nil {
		return fmt.Errorf("数据库操作失败")
	}

	return nil
}
