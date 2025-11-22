package proxy

import (
	"encoding/base64"
	"errors"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"

	"ehang.io/nps/lib/common"
	"ehang.io/nps/lib/conn"
	"ehang.io/nps/lib/file"
	"github.com/astaxie/beego"
	"github.com/astaxie/beego/logs"
)

type httpProxyTaskService struct {
	tunnel *file.Tunnel
	server *httpProxyPortServer
}

func NewHttpProxyService(bridge NetBridge, t *file.Tunnel) Service {
	return &httpProxyTaskService{
		tunnel: t,
		server: getHttpProxyPortServer(bridge, t.ServerIp, t.Port),
	}
}

func (s *httpProxyTaskService) Start() error {
	return s.server.AddTunnel(s.tunnel)
}

func (s *httpProxyTaskService) Close() error {
	s.server.RemoveTunnel(s.tunnel.Id)
	return nil
}

type httpProxyPortServer struct {
	bridge   NetBridge
	key      string
	ip       string
	port     int
	listener net.Listener

	startOnce sync.Once
	closeOnce sync.Once
	startErr  error

	mu    sync.RWMutex
	users map[string]*httpProxyUserEntry
}

type httpProxyUserEntry struct {
	tunnels []*file.Tunnel
	next    int
}

var (
	httpProxyServersMu sync.Mutex
	httpProxyServers   = make(map[string]*httpProxyPortServer)
)

func getHttpProxyPortServer(bridge NetBridge, ip string, port int) *httpProxyPortServer {
	if ip == "" {
		ip = "0.0.0.0"
	}
	key := net.JoinHostPort(ip, strconv.Itoa(port))
	httpProxyServersMu.Lock()
	defer httpProxyServersMu.Unlock()
	if srv, ok := httpProxyServers[key]; ok {
		return srv
	}
	srv := &httpProxyPortServer{
		bridge: bridge,
		key:    key,
		ip:     ip,
		port:   port,
		users:  make(map[string]*httpProxyUserEntry),
	}
	httpProxyServers[key] = srv
	return srv
}

func (s *httpProxyPortServer) AddTunnel(t *file.Tunnel) error {
	if t.Client == nil || t.Client.Cnf == nil || t.Client.Cnf.U == "" {
		return errors.New("basic_username is required for shared http proxy")
	}
	if t.Port == 0 {
		if p, err := beego.AppConfig.Int("http_proxy_port"); err == nil && p > 0 {
			t.Port = p
		}
	}
	if err := s.start(); err != nil {
		return err
	}
	s.mu.Lock()
	entry, ok := s.users[t.Client.Cnf.U]
	if !ok {
		entry = &httpProxyUserEntry{}
		s.users[t.Client.Cnf.U] = entry
	}
	entry.tunnels = append(entry.tunnels, t)
	s.mu.Unlock()
	logs.Info("http proxy task %s registered on %s with basic_username %s", t.Remark, s.key, t.Client.Cnf.U)
	return nil
}

func (s *httpProxyPortServer) RemoveTunnel(id int) {
	s.mu.Lock()
	for user, entry := range s.users {
		idx := -1
		for i, t := range entry.tunnels {
			if t.Id == id {
				idx = i
				break
			}
		}
		if idx >= 0 {
			entry.tunnels = append(entry.tunnels[:idx], entry.tunnels[idx+1:]...)
			if entry.next >= len(entry.tunnels) {
				entry.next = 0
			}
			if len(entry.tunnels) == 0 {
				delete(s.users, user)
			}
		}
	}
	empty := len(s.users) == 0
	s.mu.Unlock()
	if empty {
		s.close()
		httpProxyServersMu.Lock()
		delete(httpProxyServers, s.key)
		httpProxyServersMu.Unlock()
	}
}

func (s *httpProxyPortServer) start() error {
	s.startOnce.Do(func() {
		l, err := net.Listen("tcp", s.key)
		if err != nil {
			s.startErr = err
			return
		}
		s.listener = l
		go conn.Accept(s.listener, func(c net.Conn) {
			s.handleConn(c)
		})
		logs.Info("shared http proxy listener started on %s", s.key)
	})
	return s.startErr
}

func (s *httpProxyPortServer) close() {
	s.closeOnce.Do(func() {
		if s.listener != nil {
			_ = s.listener.Close()
		}
	})
}

func (s *httpProxyPortServer) handleConn(raw net.Conn) {
	c := conn.NewConn(raw)
	_, addr, rb, err, r := c.GetHost()
	if err != nil || r == nil {
		c.Close()
		logs.Warn("http proxy parse request error: %v", err)
		return
	}
	user, pwd, ok := parseProxyBasicAuth(r)
	if !ok {
		c.Write([]byte(common.UnauthorizedBytes))
		c.Close()
		return
	}
	tunnel, pickErr := s.pickTunnel(user, pwd)
	if pickErr != nil {
		if errors.Is(pickErr, errProxyUnauthorized) {
			c.Write([]byte(common.UnauthorizedBytes))
		} else {
			c.Write([]byte(common.ConnectionFailBytes))
		}
		c.Close()
		return
	}
	if err := checkFlowAndConnNum(tunnel.Client); err != nil {
		logs.Warn("client id %d, http proxy flow/conn limited: %s", tunnel.Client.Id, err.Error())
		c.Write([]byte(common.ConnectionFailBytes))
		c.Close()
		return
	}
	defer tunnel.Client.AddConn()
	if r.Method == "CONNECT" {
		c.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
		rb = nil
	}
	if err := s.dealClient(c, tunnel, addr, rb); err != nil {
		logs.Warn("http proxy forward error: %v", err)
	}
}

func (s *httpProxyPortServer) dealClient(c *conn.Conn, t *file.Tunnel, addr string, rb []byte) error {
	link := conn.NewLink(common.CONN_TCP, addr, t.Client.Cnf.Crypt, t.Client.Cnf.Compress, c.Conn.RemoteAddr().String(), t.Target.LocalProxy)
	target, err := s.bridge.SendLinkInfo(t.Client.Id, link, t)
	if err != nil {
		c.Close()
		return err
	}
	conn.CopyWaitGroup(target, c.Conn, link.Crypt, link.Compress, t.Client.Rate, t.Flow, true, rb)
	return nil
}

var (
	errProxyUnauthorized = errors.New("proxy auth failed")
	errProxyUnavailable  = errors.New("no available tunnel")
)

func (s *httpProxyPortServer) pickTunnel(user, pwd string) (*file.Tunnel, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.users[user]
	if !ok || len(entry.tunnels) == 0 {
		return nil, errProxyUnauthorized
	}
	start := entry.next
	var passwordMatched bool
	for i := 0; i < len(entry.tunnels); i++ {
		idx := (start + i) % len(entry.tunnels)
		t := entry.tunnels[idx]
		if t.Client.Cnf.P != "" && t.Client.Cnf.P != pwd {
			continue
		}
		passwordMatched = true
		entry.next = (idx + 1) % len(entry.tunnels)
		return t, nil
	}
	if !passwordMatched {
		return nil, errProxyUnauthorized
	}
	return nil, errProxyUnavailable
}

func HasHttpProxyPortServer(ip string, port int) bool {
	if ip == "" {
		ip = "0.0.0.0"
	}
	key := net.JoinHostPort(ip, strconv.Itoa(port))
	httpProxyServersMu.Lock()
	defer httpProxyServersMu.Unlock()
	_, ok := httpProxyServers[key]
	return ok
}

func parseProxyBasicAuth(r *http.Request) (user, password string, ok bool) {
	auth := r.Header.Get("Proxy-Authorization")
	if auth == "" {
		auth = r.Header.Get("Authorization")
	}
	if auth == "" {
		return
	}
	parts := strings.SplitN(auth, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "basic") {
		return
	}
	b, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return
	}
	pair := strings.SplitN(string(b), ":", 2)
	if len(pair) != 2 {
		return
	}
	return pair[0], pair[1], true
}

func checkFlowAndConnNum(client *file.Client) error {
	if client.Flow.FlowLimit > 0 && (client.Flow.FlowLimit<<20) < (client.Flow.ExportFlow+client.Flow.InletFlow) {
		return errors.New("traffic exceeded")
	}
	if !client.GetConn() {
		return errors.New("connections exceed the current client limit")
	}
	return nil
}
