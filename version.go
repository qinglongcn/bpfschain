package bpfschain

import (
	"fmt"
	"strconv"
	"strings"
)

// CompareVersions 比较两个版本号，如果v1 < v2返回-1，如果v1 == v2返回0，如果v1 > v2返回1
func CompareVersions(v1, v2 string) int {
	v1Parts := strings.Split(v1, ".")
	v2Parts := strings.Split(v2, ".")

	for i := 0; i < len(v1Parts) || i < len(v2Parts); i++ {
		var v1Part, v2Part int
		var err error

		if i < len(v1Parts) {
			v1Part, err = strconv.Atoi(v1Parts[i])
			if err != nil {
				fmt.Printf("版本解析错误: %v\n", err)
				return 0
			}
		}

		if i < len(v2Parts) {
			v2Part, err = strconv.Atoi(v2Parts[i])
			if err != nil {
				fmt.Printf("版本解析错误: %v\n", err)
				return 0
			}
		}

		if v1Part < v2Part {
			return -1
		} else if v1Part > v2Part {
			return 1
		}
	}

	return 0
}

// func main() {
//     localVersion := "1.0.1"
//     newVersion := "1.2.0"

//     result := CompareVersions(localVersion, newVersion)
//     switch result {
//     case -1:
//         fmt.Printf("%s 是较旧的版本，%s 是最新版本\n", localVersion, newVersion)
//     case 1:
//         fmt.Printf("%s 是最新的版本\n", localVersion)
//     case 0:
//         fmt.Printf("两个版本号相同\n")
//     }
// }
