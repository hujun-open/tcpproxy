// common
package common

import (
	"bytes"
	"errors"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

var InfoLog = log.New(os.Stdout, "TCPPROXY-INFO: ", log.Ldate|log.Ltime|log.Lshortfile)
var WarnLog = log.New(os.Stdout, "TCPPROXY-WARNING: ", log.Ldate|log.Ltime|log.Lshortfile)
var ErrLog = log.New(os.Stderr, "TCPPROXY-ERROR: ", log.Ldate|log.Ltime|log.Lshortfile)

func MakeErr(ierr error) error {
	var buf bytes.Buffer
	pc, _, line, _ := runtime.Caller(1)
	logger := log.New(&buf, "", 0)
	logger.Printf("[%s:%d]: %v", runtime.FuncForPC(pc).Name(), line, ierr)
	return errors.New(buf.String())
}

func MakeErrviaStr(errs string) error {
	var buf bytes.Buffer
	pc, _, line, _ := runtime.Caller(1)
	logger := log.New(&buf, "", 0)
	logger.Printf("[%s:%d]: %v", runtime.FuncForPC(pc).Name(), line, errs)
	return errors.New(buf.String())
}

func GetConfDir() string {
	var defDir string
	switch runtime.GOOS {
	case "windows":
		defDir = filepath.Join(os.Getenv("APPDATA"), "tcpp")
	case "linux", "darwin":
		defDir = filepath.Join(os.Getenv("HOME"), ".tcpp")
	}
	redirectfilename := filepath.Join(defDir, "redirection.conf")
	redir, err := ioutil.ReadFile(redirectfilename)
	if err != nil {
		return defDir
	} else {
		redir_str := strings.TrimRight(string(redir), " 	\n\r")
		return redir_str
	}
	return ""
}
