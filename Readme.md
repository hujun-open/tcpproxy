# tcpproxy ver1.0
tcpproxy is a simple TCP proxy, with ability to authenticate client;

## how does it work?
First run tcpproxy as server role on remote host with specified target IP and port, which is  listening on following two ports
* data_port: default 8892
* ctl_port: default 8893

The ports could be changed by command line parameters.

Before client application to use tcpproxy server, it needs to use tcpproxy client to authenticate its IP address to tcpproxy server by using TLS certificate authentication, otherwise, the tcpproxy server won't accept client's data connection;

Any packets received on data_port will be forwarded to target ip and port


## security

tcpproxy use TLS to authenticate client, so its uses TLS client certificate authentication mechanism; 

note: tcpproxy by default use a hard coded "1.1.1.1" in SAN of server certificate, this is to avoid hassle to create a different certificate for each tcpproxy server; since main point here is for sever to authenticate client, I think it is acceptable; if you don't like it, and do want to use a certificate with correct SAN, use `-san_chk` for the client to check server certificate's SAN;

## build
tcpproxy is coded with golang ver1.9, just use "go build" in the source directory to build the binary;


## install
since rclip use TLS and its own CA, so following key and certificates are needed to generated before installation:
* root CA cert/key
* server key/cert
* client key/cert

note: if you don't want SAN check, when you generate server certificate, make sure there is SubjectAltName extension, "1.1.1.1" as ip address; otherwise put correct server FQDN/address in server's certificate;


tcpproxy expect above key/certs located in following directory:
* Windows: [windows_user_dir]\appdata\AppData\Roaming\tcpp
* Linux/OSX: $HOME/.tcpp/


On tcpproxy server, following cert/keys with expected file name are needed:
* root CA cert: ca_cert
* server cert/key: svr_cert/svr_key


on tcpproxy client, following cert/keys are needed:
* root CA cert: ca_cert
* client cert/key: clnt_cert/clnt_key

all cert/key files's permission should be set that only owner could read


## usage
on server:
* start tcpproxy server process: 
```
tcpproxy -role svr -svr_ip <target_addr> -svr_port  <target_tcp_port>
```


on client:
* authentication itself before connect to the data_port:
```
tcpproxy  -svr_ip <tcpproxy_svr_addr> -svr_port  <tcpproxy_svr_ctl_port>
```
note: add `-san_check` to check server certificate's SAN

After above command, you could now use the application (e.g. a SSH client) to connect to the tcpproxy server's data_port;
note: it is need to be done within 30 seconds after authentication, otherwise you have to redo the authentication again.

## CLI Parameter
```
tcp proxy, version 1
flag provided but not defined: -?
Usage of tcpproxy:
  -ctl_port uint
        specify the port for data packet from client (default 8893)
  -data_port uint
        specify the port for receiving control msg (default 8892)
  -role string
        specify the role, svr/clnt (default "clnt")
  -san_chk
        server certificate SAN check
  -svr_ip string
        specify the target server ip
  -svr_port uint
        specify the target server port
```

## license
MIT; https://opensource.org/licenses/MIT
