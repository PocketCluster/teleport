/*
Copyright 2015 Gravitational, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package sshutils

import (
	"crypto/subtle"
	"net"
	"time"

	"github.com/gravitational/teleport"
	"github.com/gravitational/teleport/lib/limiter"
	"github.com/gravitational/teleport/lib/utils"
	"github.com/gravitational/teleport/lib/defaults"

	log "github.com/Sirupsen/logrus"
	"github.com/gravitational/trace"
	"golang.org/x/crypto/ssh"
)

// Server is a generic implementation of a frame for SSH server
type Server struct {
	component      string
	addr           utils.NetAddr
	listener       net.Listener
	closeC         chan struct{}
	newChanHandler NewChanHandler
	reqHandler     RequestHandler
	cfg            ssh.ServerConfig
	limiter        *limiter.Limiter
	askedToClose   bool
}

// ServerOption is a functional argument for server
type ServerOption func(cfg *Server) error

func SetLimiter(limiter *limiter.Limiter) ServerOption {
	return func(s *Server) error {
		s.limiter = limiter
		return nil
	}
}

func NewServer(
	component string,
	a utils.NetAddr,
	h NewChanHandler,
	hostSigners []ssh.Signer,
	ah AuthMethods,
	opts ...ServerOption) (*Server, error) {

	err := checkArguments(a, h, hostSigners, ah)
	if err != nil {
		return nil, err
	}
	s := &Server{
		component:      component,
		addr:           a,
		newChanHandler: h,
		closeC:         make(chan struct{}),
	}
	s.limiter, err = limiter.NewLimiter(limiter.LimiterConfig{})
	if err != nil {
		return nil, trace.Wrap(err)
	}

	for _, o := range opts {
		if err := o(s); err != nil {
			return nil, err
		}
	}
	for _, signer := range hostSigners {
		(&s.cfg).AddHostKey(signer)
	}
	s.cfg.PublicKeyCallback = ah.PublicKey
	s.cfg.PasswordCallback = ah.Password
	s.cfg.NoClientAuth = ah.NoClient
	return s, nil
}

func SetSSHConfig(cfg ssh.ServerConfig) ServerOption {
	return func(s *Server) error {
		s.cfg = cfg
		return nil
	}
}

func SetRequestHandler(req RequestHandler) ServerOption {
	return func(s *Server) error {
		s.reqHandler = req
		return nil
	}
}

func (s *Server) Addr() string {
	return s.listener.Addr().String()
}

func (s *Server) Start() error {
	s.askedToClose = false
	socket, err := net.Listen(s.addr.AddrNetwork, s.addr.Addr)
	if err != nil {
		return err
	}
	s.listener = socket
	log.Infof("[SSH:%s] listening socket: %v", s.component, socket.Addr())
	go s.acceptConnections()
	return nil
}

func (s *Server) notifyClosed() {
	close(s.closeC)
}

func (s *Server) Wait() {
	<-s.closeC
}

// Close closes listening socket and stops accepting connections
func (s *Server) Close() error {
	s.askedToClose = true
	if s.listener != nil {
		return s.listener.Close()
	}
	return nil
}

func (s *Server) acceptConnections() {
	defer s.notifyClosed()
	addr := s.Addr()
	log.Infof("[SSH:%v] is listening on %v", s.component, addr)
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			if s.askedToClose {
				log.Infof("[SSH:%v] server %v exited", s.component, addr)
				s.askedToClose = false
				return
			}
			// our best shot to avoid excessive logging
			if op, ok := err.(*net.OpError); ok && !op.Timeout() {
				log.Debugf("[SSH:%v] closed socket %v", s.component, op)
				return
			}
			log.Errorf("SSH:%v accept error: %T %v", s.component, err, err)
			return
		}
		go s.handleConnection(conn)
	}
}

func (s *Server) handleConnection(conn net.Conn) {
	// initiate an SSH connection, note that we don't need to close the conn here
	// in case of error as ssh server takes care of this
	remoteAddr, _, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		log.Errorf(err.Error())
	}
	if err := s.limiter.AcquireConnection(remoteAddr); err != nil {
		log.Errorf(err.Error())
		conn.Close()
		return
	}
	defer s.limiter.ReleaseConnection(remoteAddr)

	// setting waiting deadline in case of connection freezing
	err = conn.SetDeadline(time.Now().Add(5 * time.Minute))
	if err != nil {
		log.Errorf(err.Error())
		return
	}
	sconn, chans, reqs, err := ssh.NewServerConn(conn, &s.cfg)
	if err != nil {
		conn.SetDeadline(time.Time{})
		return
	}
	err = conn.SetDeadline(time.Time{})
	if err != nil {
		log.Errorf(err.Error())
		return
	}

	user := sconn.User()
	if err := s.limiter.RegisterRequest(user); err != nil {
		log.Errorf(err.Error())
		sconn.Close()
		conn.Close()
		return
	}
	// Connection successfully initiated
	log.Infof("[SSH:%v] new connection %v -> %v vesion: %v",
		s.component, sconn.RemoteAddr(), sconn.LocalAddr(), string(sconn.ClientVersion()))

	// will be called when the connection is closed
	connClosed := func() {
		log.Infof("[SSH:%v] closed connection", s.component)
	}

	// The keepalive ticket will ensure that SSH keepalive requests are being sent
	// to the client at an interval much shorter than idle connection kill switch
	keepAliveTick := time.NewTicker(defaults.DefaultIdleConnectionDuration / 3)
	defer keepAliveTick.Stop()
	keepAlivePayload := [8]byte{0}

	for {
		select {
		// (2017-06-15) handles server closure. (stkim1: this closure case should terminate accepting connections onward)
		case <-s.closeC: {
			log.Infof("[SSH:%v] server shutting down", s.component)
			connClosed()
			return
		}
		// handle out of band ssh requests
		case req := <-reqs:
			if req == nil {
				connClosed()
				return
			}
			log.Infof("[SSH:%v] recieved out-of-band request: %+v", s.component, req)
			if s.reqHandler != nil {
				go s.reqHandler.HandleRequest(req)
			}
			// handle channels:
		case nch := <-chans:
			if nch == nil {
				connClosed()
				return
			}
			go s.newChanHandler.HandleNewChan(conn, sconn, nch)
			// send keepalive pings to the clients
		case <-keepAliveTick.C:
			const wantReply = true
			sconn.SendRequest(teleport.KeepAliveReqType, wantReply, keepAlivePayload[:])
		}
	}
}

type RequestHandler interface {
	HandleRequest(r *ssh.Request)
}

type RequestHandlerFunc func(*ssh.Request)

func (f RequestHandlerFunc) HandleRequest(r *ssh.Request) {
	f(r)
}

type NewChanHandler interface {
	HandleNewChan(net.Conn, *ssh.ServerConn, ssh.NewChannel)
}

type NewChanHandlerFunc func(net.Conn, *ssh.ServerConn, ssh.NewChannel)

func (f NewChanHandlerFunc) HandleNewChan(conn net.Conn, sshConn *ssh.ServerConn, ch ssh.NewChannel) {
	f(conn, sshConn, ch)
}

type AuthMethods struct {
	PublicKey PublicKeyFunc
	Password  PasswordFunc
	NoClient  bool
}

func checkArguments(a utils.NetAddr, h NewChanHandler, hostSigners []ssh.Signer, ah AuthMethods) error {
	if a.Addr == "" || a.AddrNetwork == "" {
		return trace.BadParameter("addr: specify network and the address for listening socket")
	}

	if h == nil {
		return trace.BadParameter("missing NewChanHandler")
	}
	if len(hostSigners) == 0 {
		return trace.BadParameter("need at least one signer")
	}
	for _, s := range hostSigners {
		if s == nil {
			return trace.BadParameter("host signer can not be nil")
		}
	}
	if ah.PublicKey == nil && ah.Password == nil && ah.NoClient == false {
		return trace.BadParameter("need at least one auth method")
	}
	return nil
}

type PublicKeyFunc func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error)
type PasswordFunc func(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error)

// KeysEqual is constant time compare of the keys to avoid timing attacks
func KeysEqual(ak, bk ssh.PublicKey) bool {
	a := ssh.Marshal(ak)
	b := ssh.Marshal(bk)
	return (len(a) == len(b) && subtle.ConstantTimeCompare(a, b) == 1)
}
