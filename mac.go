// MAC 地址

package bpfschain

import (
	"fmt"
	"net"
	"strings"
)

// GetPrimaryMACAddress 返回电脑上的主要MAC地址。
func GetPrimaryMACAddress() (string, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}

	// 定义一个匿名结构体来存储接口信息和权重
	var bestIface struct {
		mac    string
		weight int
	}

	for _, iface := range interfaces {
		if iface.HardwareAddr == nil || iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		info := struct {
			mac    string
			weight int
		}{mac: iface.HardwareAddr.String()}

		// 为非虚拟接口增加权重
		if !strings.Contains(iface.Name, "vmnet") && !strings.Contains(iface.Name, "vboxnet") {
			info.weight += 10
		}

		// 为状态为"up"的接口增加权重
		if iface.Flags&net.FlagUp != 0 {
			info.weight += 10
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		// 为有IPv4地址的接口增加权重
		for _, addr := range addrs {
			if ipNet, ok := addr.(*net.IPNet); ok && !ipNet.IP.IsLoopback() && ipNet.IP.To4() != nil {
				info.weight += 10
				break
			}
		}

		// 选择权重最高的接口
		if info.weight > bestIface.weight {
			bestIface = info
		}
	}

	if bestIface.mac == "" {
		return "", fmt.Errorf("no MAC address found")
	}

	return bestIface.mac, nil
}
