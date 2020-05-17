// server
package server

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"tcpproxy/common"
	"time"
)

type AuthIP struct {
	addr          string
	creation_time time.Time
	connCount     *uint32
	del_chan      chan string
	timeout       time.Duration
}

func NewAuthIP(addrstr string, delchan chan string, holdon time.Duration) *AuthIP {
	r := new(AuthIP)
	r.addr = addrstr
	r.creation_time = time.Now()
	r.connCount = new(uint32)
	r.del_chan = delchan
	r.timeout = holdon
	atomic.StoreUint32(r.connCount, 0)
	go r.closeMe()
	return r
}

func (self *AuthIP) closeMe() {
	timer1 := time.NewTimer(self.timeout)
	defer timer1.Stop()
	for {
		<-timer1.C
		if atomic.LoadUint32(self.connCount) == 0 {
			self.del_chan <- self.addr
			return
		}
		timer1.Reset(self.timeout)
	}

}

//func (aip AuthIP) SetStart(b bool) {
//	aip.started = b
//}

type AuthIPQuery struct {
	addr   string
	result chan bool
}

type AuthList struct {
	list           map[string]*AuthIP
	add_chan       chan string
	del_chan       chan string
	query_chan     chan AuthIPQuery
	connclose_chan chan string
	list_lock      *sync.RWMutex
	timeout        time.Duration
}

const AUTHLIST_CHANDEPTH = 8

func NewAuthList(lifetime int) *AuthList {
	n := new(AuthList)
	n.list = make(map[string]*AuthIP)
	n.add_chan = make(chan string, AUTHLIST_CHANDEPTH)
	n.del_chan = make(chan string, AUTHLIST_CHANDEPTH)
	n.connclose_chan = make(chan string, AUTHLIST_CHANDEPTH)
	n.query_chan = make(chan AuthIPQuery, AUTHLIST_CHANDEPTH)
	n.list_lock = new(sync.RWMutex)
	n.timeout = time.Duration(lifetime) * time.Second
	go n.housekeeping()
	return n
}

func (alist *AuthList) housekeeping() {
	var tgt_addr string
	var query AuthIPQuery
	common.InfoLog.Println("start house keeping")
	for {
		select {
		case tgt_addr = <-alist.add_chan:
			alist.list_lock.Lock()
			alist.list[tgt_addr] = NewAuthIP(tgt_addr, alist.del_chan, alist.timeout)
			alist.list_lock.Unlock()
			common.InfoLog.Printf("client %v authed", tgt_addr)
		case tgt_addr = <-alist.del_chan:
			alist.list_lock.Lock()
			delete(alist.list, tgt_addr)
			alist.list_lock.Unlock()
			common.InfoLog.Printf("client %v removed", tgt_addr)
		case query = <-alist.query_chan:
			alist.list_lock.RLock()
			_, r := alist.list[query.addr]
			alist.list_lock.RUnlock()
			if r == true {
				atomic.AddUint32(alist.list[query.addr].connCount, 1)
				common.InfoLog.Printf("client %v has now %d connections", query.addr, atomic.LoadUint32(alist.list[query.addr].connCount))
			}
			query.result <- r
		case tgt_addr = <-alist.connclose_chan:
			alist.list_lock.RLock()
			_, r := alist.list[query.addr]
			alist.list_lock.RUnlock()
			if r == true {
				atomic.AddUint32(alist.list[query.addr].connCount, ^uint32(0))
				common.InfoLog.Printf("client %v has now %d connections", query.addr, atomic.LoadUint32(alist.list[tgt_addr].connCount))
			}
		}
	}
}

type TCPProxyServer struct {
	data_ln net.Listener
	ctl_ln  net.Listener
	//client_ctl_conn net.Conn
	//svr_conn        net.Conn
	target_ip    string
	target_port  int
	auth_ip_list *AuthList
	lifetime     int
}

func NewTCPProxyServer(data_port int, ctl_port int, target_ip string, target_port int, conf_dir string, lifetime int) (*TCPProxyServer, error) {
	cert_path := filepath.Join(conf_dir, "svr_cert")
	key_path := filepath.Join(conf_dir, "svr_key")
	cer, err := tls.LoadX509KeyPair(cert_path, key_path)
	if err != nil {
		return nil, common.MakeErr(err)
	}
	new_svr := new(TCPProxyServer)
	ca_cert_path := filepath.Join(conf_dir, "ca_cert")
	root_pem, err := ioutil.ReadFile(ca_cert_path)
	if err != nil {
		return nil, common.MakeErr(err)
	}
	roots := x509.NewCertPool()
	ok := roots.AppendCertsFromPEM(root_pem)
	if ok != true {
		return nil, common.MakeErrviaStr("error parsing root CA cert file")
	}

	cfg := &tls.Config{Certificates: []tls.Certificate{cer}, ClientCAs: roots, ClientAuth: tls.RequireAndVerifyClientCert}
	new_svr.ctl_ln, err = tls.Listen("tcp", ":"+strconv.Itoa(ctl_port), cfg)
	if err != nil {
		return nil, common.MakeErr(err)
	}
	new_svr.data_ln, err = net.Listen("tcp", ":"+strconv.Itoa(data_port))
	if err != nil {
		return nil, common.MakeErr(err)
	}
	new_svr.target_ip = target_ip
	new_svr.target_port = target_port
	new_svr.auth_ip_list = NewAuthList(lifetime)
	new_svr.lifetime = lifetime
	return new_svr, nil
}

func (svr *TCPProxyServer) Start() {
	defer svr.ctl_ln.Close()
	defer svr.data_ln.Close()
	common.InfoLog.Println("starting server ...")
	common.InfoLog.Printf("listen on control port %v", svr.ctl_ln.Addr())
	common.InfoLog.Printf("listen on data port %v", svr.data_ln.Addr())
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for {
			conn, err := svr.ctl_ln.Accept()
			if err != nil {
				common.WarnLog.Printf("error accpeting new control connection, %v", err)
				continue
			}

			go svr.handleControlConnection(conn)

		}
	}()
	go func() {
		defer wg.Done()
		for {
			conn, err := svr.data_ln.Accept()
			if err != nil {
				common.WarnLog.Printf("error accpeting new data connection, %v", err)
				continue
			}
			go svr.handleDataConnection(conn)

		}
	}()

	wg.Wait()
}

func (svr *TCPProxyServer) handleControlConnection(conn net.Conn) {
	common.InfoLog.Printf("accpeting a new control connection from %v ", conn.RemoteAddr())
	//svr.client_ctl_conn = conn
	//	if svr.svr_conn != nil {
	//		svr.svr_conn.Close()
	//	}
	//var err error
	conn.Write([]byte("authed"))
	remote_ip, _, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		common.WarnLog.Println((common.MakeErrviaStr(fmt.Sprintf("unusual error: can't parse remoteaddr,%v", conn.RemoteAddr()))))
		return
	}
	svr.auth_ip_list.add_chan <- remote_ip
	//svr.auth_ip_list[remote_ip] = true
	//            To BE FINISHED                  //
	conn.Write([]byte("authed"))
	conn.Close()
}

func (svr *TCPProxyServer) handleDataConnection(conn net.Conn) {
	common.InfoLog.Printf("getting a new data connection from %v ", conn.RemoteAddr())
	remote_ip, _, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		common.WarnLog.Println((common.MakeErrviaStr(fmt.Sprintf("unusual error: can't parse remoteaddr,%v", conn.RemoteAddr()))))
		return
	}
	defer func(c chan string, i string) { c <- i }(svr.auth_ip_list.connclose_chan, remote_ip)
	q := AuthIPQuery{addr: remote_ip, result: make(chan bool)}
	svr.auth_ip_list.query_chan <- q
	r := <-q.result
	if r == false {
		common.WarnLog.Printf("%v is not authed yet, closed connection", remote_ip)
		conn.Close()
		return
	}
	svr_conn, err := net.Dial("tcp", svr.target_ip+":"+strconv.Itoa(svr.target_port))
	if err != nil {
		common.WarnLog.Println(common.MakeErrviaStr(fmt.Sprintf("can't connect to target server %v,%v", svr.target_ip+":"+strconv.Itoa(svr.target_port), err)))
		return
	}
	common.InfoLog.Printf("start passing data beteen %v and target %v", conn.RemoteAddr(), svr_conn.RemoteAddr())
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		io.Copy(svr_conn, conn)
		defer conn.Close()
		defer svr_conn.Close()
		wg.Done()
	}()
	go func() {
		io.Copy(conn, svr_conn)
		defer conn.Close()
		defer svr_conn.Close()
		wg.Done()
	}()
	wg.Wait()
}
