// client
package client

import (
	"crypto/tls"
	"crypto/x509"
	"io/ioutil"
	"path/filepath"
	"strconv"
	"tcpproxy/common"
)

func AuthMyself(svr_ip string, svr_port int, conf_dir string, check_san bool) error {

	cert_path := filepath.Join(conf_dir, "clnt_cert")
	key_path := filepath.Join(conf_dir, "clnt_key")
	ca_cert_path := filepath.Join(conf_dir, "ca_cert")

	cer, err := tls.LoadX509KeyPair(cert_path, key_path)
	if err != nil {
		return common.MakeErr(err)
	}
	root_pem, err := ioutil.ReadFile(ca_cert_path)
	if err != nil {
		return common.MakeErr(err)
	}
	roots := x509.NewCertPool()
	ok := roots.AppendCertsFromPEM(root_pem)
	if ok != true {
		return common.MakeErrviaStr("error parsing root CA cert file")
	}
	var cfg *tls.Config
	if check_san == false {
		cfg = &tls.Config{Certificates: []tls.Certificate{cer}, RootCAs: roots, InsecureSkipVerify: false, ServerName: "1.1.1.1", MinVersion: tls.VersionTLS12}
	} else {
		cfg = &tls.Config{Certificates: []tls.Certificate{cer}, RootCAs: roots, InsecureSkipVerify: false, ServerName: svr_ip, MinVersion: tls.VersionTLS12}
	}

	conn, err := tls.Dial("tcp", svr_ip+":"+strconv.Itoa(svr_port), cfg)
	common.InfoLog.Printf("try to get authed by %v", svr_ip+":"+strconv.Itoa(svr_port))
	if err != nil {
		return common.MakeErr(err)
	}
	//ioutil.ReadAll(conn)
	conn.Write([]byte("hello"))
	conn.Close()
	return nil
}
