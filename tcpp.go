// tcpp
package main

import (
	"flag"
	"fmt"
	"tcpproxy/client"
	"tcpproxy/common"
	"tcpproxy/server"
)

func main() {
	var ver = 1.1
	version_str := fmt.Sprintf("tcp proxy, version %v", ver)
	fmt.Println(version_str)
	role := flag.String("role", "clnt", "specify the role, svr/clnt")
	data_port := flag.Uint("data_port", 8892, "specify the port for receiving control msg")
	ctl_port := flag.Uint("ctl_port", 8893, "specify the port for data packet from client")
	svr_port := flag.Uint("svr_port", 0, "specify the target server port")
	svr_ip := flag.String("svr_ip", "", "specify the target server ip")
	san_check := flag.Bool("san_chk", false, "server certificate SAN check")
	lifetime := flag.Uint("holdon", 300, "holdon time in seconds after data connection is closed")
	flag.Parse()
	if *svr_ip == "" || int(*svr_port) == 0 {
		common.ErrLog.Println("target server ip or port is not specified")
		return
	}

	conf_dir := common.GetConfDir()
	switch *role {
	case "svr":
		svr, err := server.NewTCPProxyServer(int(*data_port), int(*ctl_port), *svr_ip, int(*svr_port), conf_dir, int(*lifetime))
		if err != nil {
			common.ErrLog.Panicln(err)
			return
		}
		svr.Start()

	case "clnt":
		common.InfoLog.Println("act as client")
		err := client.AuthMyself(*svr_ip, int(*svr_port), conf_dir, *san_check)
		if err != nil {
			common.ErrLog.Printf("auth failed, %v", err)
		} else {
			common.InfoLog.Println("auth succeed")
		}
		return

	default:
		common.ErrLog.Printf("unknown role %v", *role)
		return
	}
}
