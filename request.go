package sls

import (
	"bytes"
	"crypto/md5"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"sync"
	"time"

	"encoding/json"
	"io/ioutil"

	"github.com/golang/glog"
)

func PrintLocalDial(network, addr string) (net.Conn, error) {
	dial := net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
	}

	conn, err := dial.Dial(network, addr)
	if err != nil {
		return conn, err
	}

	glog.Info("connect done, use ", conn.LocalAddr().String())
	glog.Flush()

	return conn, err
}

var globalAllClientCache = make(map[*http.Client]time.Time)
var globallClientCacheLock = sync.Mutex{}

func getHttpClient() *http.Client {
	globallClientCacheLock.Lock()
	defer globallClientCacheLock.Unlock()
	for client, lastTime := range globalAllClientCache {
		if lastTime.IsZero() {
			globalAllClientCache[client] = time.Now()
			return client
		}
	}
	glog.Info("create http client")
	client := &http.Client{
		Transport: &http.Transport{
			Dial:                PrintLocalDial,
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 10,
		},
	}
	globalAllClientCache[client] = time.Now()
	return client
}
func returnHttpClient(client *http.Client, req *http.Request, resp *http.Response) {
	globallClientCacheLock.Lock()
	defer globallClientCacheLock.Unlock()
	lastTime := globalAllClientCache[client]
	duration := time.Now().Sub(lastTime)
	if duration > time.Millisecond*500 {
		glog.Warning("|||request too slow|||", duration.Seconds(), "|||", req.Host, "|||", req.URL.String(), "|||", req.Method, "|||", resp.Header)
		glog.Flush()
	}
	globalAllClientCache[client] = time.Time{}
}

// request sends a request to alibaba cloud Log Service.
// @note if error is nil, you must call http.Response.Body.Close() to finalize reader
func request(project *LogProject, method, uri string, headers map[string]string,
	body []byte) (*http.Response, error) {

	// The caller should provide 'x-log-bodyrawsize' header
	if _, ok := headers["x-log-bodyrawsize"]; !ok {
		return nil, fmt.Errorf("Can't find 'x-log-bodyrawsize' header")
	}

	// SLS public request headers
	var hostStr string
	if len(project.Name) == 0 {
		hostStr = project.Endpoint
	} else {
		hostStr = project.Name + "." + project.Endpoint
	}
	headers["Host"] = hostStr
	headers["Date"] = nowRFC1123()
	headers["x-log-apiversion"] = version
	headers["x-log-signaturemethod"] = signatureMethod

	// Access with token
	if project.SecurityToken != "" {
		headers["x-acs-security-token"] = project.SecurityToken
	}

	if body != nil {
		bodyMD5 := fmt.Sprintf("%X", md5.Sum(body))
		headers["Content-MD5"] = bodyMD5
		if _, ok := headers["Content-Type"]; !ok {
			return nil, fmt.Errorf("Can't find 'Content-Type' header")
		}
	}

	// Calc Authorization
	// Authorization = "SLS <AccessKeyId>:<Signature>"
	digest, err := signature(project.AccessKeySecret, method, uri, headers)
	if err != nil {
		return nil, err
	}
	auth := fmt.Sprintf("SLS %v:%v", project.AccessKeyID, digest)
	headers["Authorization"] = auth

	// Initialize http request
	reader := bytes.NewReader(body)
	var urlStr string
	if GlobalForceUsingHTTP || project.UsingHTTP {
		urlStr = "http://"
	} else {
		urlStr = "https://"
	}
	urlStr += hostStr + uri
	req, err := http.NewRequest(method, urlStr, reader)
	if err != nil {
		return nil, err
	}
	for k, v := range headers {
		req.Header.Add(k, v)
	}

	// Get ready to do request
	httpClient := getHttpClient()
	req.Header["Connection"] = []string{"Keep-Alive"}

	if glog.V(5) {
		dump, e := httputil.DumpRequest(req, true)
		if e != nil {
			glog.Info(e)
		}
		glog.Infof("HTTP Request:\n%v", string(dump))
	}

	resp, err := httpClient.Do(req)
	defer returnHttpClient(httpClient, req, resp)
	if err != nil {
		return nil, err
	}

	// Parse the sls error from body.
	if resp.StatusCode != http.StatusOK {
		err := &Error{}
		err.HTTPCode = (int32)(resp.StatusCode)
		defer resp.Body.Close()
		buf, _ := ioutil.ReadAll(resp.Body)
		json.Unmarshal(buf, err)
		err.RequestID = resp.Header.Get("x-log-requestid")
		return nil, err
	}

	if glog.V(6) {
		dump, e := httputil.DumpResponse(resp, true)
		if e != nil {
			glog.Info(e)
		}
		glog.Infof("HTTP Response:\n%v", string(dump))
	} else if glog.V(5) {
		glog.Infof("HTTP Response Header:\n%v", resp.Header)
	}

	return resp, nil
}
