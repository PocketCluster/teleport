package integration

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"strconv"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/gravitational/teleport"
	"github.com/gravitational/teleport/lib/auth"
	"github.com/gravitational/teleport/lib/auth/native"
	"github.com/gravitational/teleport/lib/auth/testauthority"
	"github.com/gravitational/teleport/lib/client"
	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/reversetunnel"
	"github.com/gravitational/teleport/lib/service"
	"github.com/gravitational/teleport/lib/services"
	"github.com/gravitational/trace"
)

// SetTestTimeouts affects global timeouts inside Teleport, making connections
// work faster but consuming more CPU (useful for integration testing)
func SetTestTimeouts(t time.Duration) {
	defaults.ReverseTunnelAgentHeartbeatPeriod = t
	defaults.ServerHeartbeatTTL = t
	defaults.SessionRefreshPeriod = t
}

// TeleInstance represents an in-memory instance of a teleport
// process for testing
type TeleInstance struct {
	// Secrets holds the keys (pub, priv and derived cert) of i instance
	Secrets InstanceSecrets

	// Slice of TCP ports used by Teleport services
	Ports []int

	// Hostname is the name of the host where i isnstance is running
	Hostname string

	// Internal stuff...
	Process *service.TeleportProcess
	Config  *service.Config
	Tunnel  reversetunnel.Server
}

type User struct {
	Username      string      `json:"username"`
	AllowedLogins []string    `json:"logins"`
	Key           *client.Key `json:"key"`
}

type InstanceSecrets struct {
	// instance name (aka "site name")
	SiteName string `json:"site_name"`
	// instance keys+cert (reused for hostCA and userCA)
	PubKey  []byte `json:"pub"`
	PrivKey []byte `json:"priv"`
	Cert    []byte `json:"cert"`
	// ListenPort is a reverse tunnel listening port, allowing
	// other sites to connect to i instance. Set to empty
	// string if i instance is not allowing incoming tunnels
	ListenAddr string `json:"tunnel_addr"`
	// list of users i instance trusts (key in the map is username)
	Users map[string]*User `json:"users"`
}

func (s *InstanceSecrets) String() string {
	bytes, _ := json.MarshalIndent(s, "", "\t")
	return string(bytes)
}

// NewInstance creates a new Teleport process instance
func NewInstance(clusterName string, hostID string, nodeName string, ports []int, priv, pub []byte) *TeleInstance {
	var err error
	if len(ports) < 5 {
		fatalIf(fmt.Errorf("not enough free ports given: %v", ports))
	}
	if nodeName == "" {
		nodeName, err = os.Hostname()
		fatalIf(err)
	}
	// generate instance secrets (keys):
	keygen := native.New()
	if priv == nil || pub == nil {
		priv, pub, _ = keygen.GenerateKeyPair("")
	}
	cert, err := keygen.GenerateHostCert(services.CertParams{
		PrivateCASigningKey: priv,
		PublicHostKey:       pub,
		HostID:              hostID,
		NodeName:            nodeName,
		ClusterName:         clusterName,
		Roles:               teleport.Roles{teleport.RoleAdmin},
		TTL:                 time.Duration(time.Hour * 24),
	})
	fatalIf(err)
	secrets := InstanceSecrets{
		SiteName:   clusterName,
		PrivKey:    priv,
		PubKey:     pub,
		Cert:       cert,
		ListenAddr: net.JoinHostPort(nodeName, strconv.Itoa(ports[4])),
		Users:      make(map[string]*User),
	}
	return &TeleInstance{
		Secrets:  secrets,
		Ports:    ports,
		Hostname: nodeName,
	}
}

// GetCAs return an array of CAs stored by the secrets object. In i
// case we always return hard-coded userCA + hostCA (and they share keys
// for simplicity)
func (s *InstanceSecrets) GetCAs() []services.CertAuthority {
	return []services.CertAuthority{
		{
			DomainName:    s.SiteName,
			Type:          services.HostCA,
			SigningKeys:   [][]byte{s.PrivKey},
			CheckingKeys:  [][]byte{s.PubKey},
			AllowedLogins: s.AllowedLogins(),
		},
		{
			DomainName:    s.SiteName,
			Type:          services.UserCA,
			SigningKeys:   [][]byte{s.PrivKey},
			CheckingKeys:  [][]byte{s.PubKey},
			AllowedLogins: s.AllowedLogins(),
		},
	}
}

func (s *InstanceSecrets) AllowedLogins() []string {
	logins := make([]string, len(s.Users))
	for i := range s.Users {
		logins = append(logins, s.Users[i].AllowedLogins...)
	}
	return logins
}

func (s *InstanceSecrets) AsSlice() []*InstanceSecrets {
	return []*InstanceSecrets{s}
}

func (s *InstanceSecrets) GetIdentity() *auth.Identity {
	i, err := auth.ReadIdentityFromKeyPair(s.PrivKey, s.Cert)
	fatalIf(err)
	return i
}

func (i *TeleInstance) GetPortSSHInt() int {
	return i.Ports[0]
}

func (i *TeleInstance) GetPortSSH() string {
	return strconv.Itoa(i.GetPortSSHInt())
}

func (i *TeleInstance) GetPortAuth() string {
	return strconv.Itoa(i.Ports[1])
}

func (i *TeleInstance) GetPortProxy() string {
	return strconv.Itoa(i.Ports[2])
}

func (i *TeleInstance) GetPortWeb() string {
	return strconv.Itoa(i.Ports[3])
}

// GetSiteAPI() is a helper which returns an API endpoint to a site with
// a given name. i endpoint implements HTTP-over-SSH access to the
// site's auth server.
func (i *TeleInstance) GetSiteAPI(siteName string) auth.ClientI {
	siteTunnel, err := i.Tunnel.GetSite(siteName)
	if err != nil {
		log.Warn(err)
		return nil
	}
	siteAPI, err := siteTunnel.GetClient()
	if err != nil {
		log.Warn(err)
		return nil
	}
	return siteAPI
}

// Create creates a new instance of Teleport which trusts a lsit of other clusters (other
// instances)
func (i *TeleInstance) Create(trustedSecrets []*InstanceSecrets, enableSSH bool, console io.Writer) error {
	tconf := service.MakeDefaultConfig()
	tconf.SSH.Enabled = enableSSH
	tconf.Console = console
	return i.CreateEx(trustedSecrets, tconf)
}

// CreateEx creates a new instance of Teleport which trusts a lsit of other clusters (other
// instances)
//
// Unlike Create() it allows for greater customization because it accepts
// a full Teleport config structure
func (i *TeleInstance) CreateEx(trustedSecrets []*InstanceSecrets, tconf *service.Config) error {
	dataDir, err := ioutil.TempDir("", "cluster-"+i.Secrets.SiteName)
	if err != nil {
		return trace.Wrap(err)
	}
	if tconf == nil {
		tconf = service.MakeDefaultConfig()
	}
	tconf.SeedConfig = true
	tconf.DataDir = dataDir
	tconf.Auth.DomainName = i.Secrets.SiteName
	tconf.Auth.Authorities = append(tconf.Auth.Authorities, i.Secrets.GetCAs()...)
	tconf.Identities = append(tconf.Identities, i.Secrets.GetIdentity())
	for _, trusted := range trustedSecrets {
		tconf.Auth.Authorities = append(tconf.Auth.Authorities, trusted.GetCAs()...)
		tconf.Identities = append(tconf.Identities, trusted.GetIdentity())
		if trusted.ListenAddr != "" {
			tconf.ReverseTunnels = []services.ReverseTunnel{
				{
					DomainName: trusted.SiteName,
					DialAddrs:  []string{trusted.ListenAddr},
				},
			}
		}
	}
	tconf.Proxy.ReverseTunnelListenAddr.Addr = i.Secrets.ListenAddr
	tconf.HostUUID = i.Secrets.GetIdentity().ID.HostUUID
	tconf.SSH.Addr.Addr = net.JoinHostPort(i.Hostname, i.GetPortSSH())
	tconf.Auth.SSHAddr.Addr = net.JoinHostPort(i.Hostname, i.GetPortAuth())
	tconf.Proxy.SSHAddr.Addr = net.JoinHostPort(i.Hostname, i.GetPortProxy())
	tconf.Proxy.WebAddr.Addr = net.JoinHostPort(i.Hostname, i.GetPortWeb())
	tconf.Proxy.DisableWebUI = true
	tconf.AuthServers = append(tconf.AuthServers, tconf.Auth.SSHAddr)
	tconf.ConfigureBolt()
	tconf.Keygen = testauthority.New()
	i.Config = tconf
	i.Process, err = service.NewTeleport(tconf)
	if err != nil {
		return trace.Wrap(err)
	}
	// create users if they don't exist, or sign their keys if they're already present
	auth := i.Process.GetAuthServer()
	for _, user := range i.Secrets.Users {
		err := auth.UpsertUser(&services.TeleportUser{
			Name:          user.Username,
			AllowedLogins: user.AllowedLogins,
		})
		if err != nil {
			return trace.Wrap(err)
		}
		// if user keys are not present, auto-geneate keys:
		if user.Key == nil || len(user.Key.Pub) == 0 {
			priv, pub, _ := tconf.Keygen.GenerateKeyPair("")
			user.Key = &client.Key{
				Priv: priv,
				Pub:  pub,
			}
		}
		// sign user's keys:
		ttl := time.Duration(time.Hour * 24)
		user.Key.Cert, err = auth.GenerateUserCert(user.Key.Pub, user.Username, ttl)
		if err != nil {
			return err
		}
	}
	return nil
}

// Reset re-creates the teleport instance based on the same configuration
// This is needed if you want to stop the instance, reset it and start again
func (i *TeleInstance) Reset() (err error) {
	i.Process, err = service.NewTeleport(i.Config)
	if err != nil {
		return trace.Wrap(err)
	}
	return nil
}

// Adds a new user into i Teleport instance. 'mappings' is a comma-separated
// list of OS users
func (i *TeleInstance) AddUser(username string, mappings []string) *User {
	log.Infof("teleInstance.AddUser(%v) mapped to %v", username, mappings)
	if mappings == nil {
		mappings = make([]string, 0)
	}
	user := &User{
		Username:      username,
		AllowedLogins: mappings,
	}
	i.Secrets.Users[username] = user
	return user
}

func (i *TeleInstance) Start() (err error) {
	proxyReady := make(chan service.Event)
	sshReady := make(chan service.Event)
	tunnelReady := make(chan service.Event)
	allReady := make(chan interface{})

	i.Process.WaitForEvent(service.ProxyIdentityEvent, proxyReady, make(chan struct{}))
	i.Process.WaitForEvent(service.SSHIdentityEvent, sshReady, make(chan struct{}))
	i.Process.WaitForEvent(service.ProxyReverseTunnelServerEvent, tunnelReady, make(chan struct{}))

	if err = i.Process.Start(); err != nil {
		return trace.Wrap(err)
	}

	defer func() {
		close(sshReady)
		close(proxyReady)
	}()

	go func() {
		if i.Config.SSH.Enabled {
			<-sshReady
		}
		<-proxyReady
		te := <-tunnelReady
		ts, ok := te.Payload.(reversetunnel.Server)
		if !ok {
			err = fmt.Errorf("Global event '%v' did not deliver reverseTunenl server pointer as a payload", service.ProxyReverseTunnelServerEvent)
			log.Error(err)
		}
		i.Tunnel = ts
		close(allReady)
	}()

	timeoutTicker := time.NewTicker(time.Second * 5)
	defer timeoutTicker.Stop()

	select {
	case <-allReady:
		time.Sleep(time.Millisecond * 100)
		break
	case <-timeoutTicker.C:
		return fmt.Errorf("failed to start local Teleport instance: timeout")
	}
	log.Infof("Teleport instance '%v' started!", i.Secrets.SiteName)
	return err
}

// NewClient returns a fully configured and pre-authenticated client
// (pre-authenticated with server CAs and signed session key)
func (i *TeleInstance) NewClient(login string, site string, host string, port int) (tc *client.TeleportClient, err error) {
	keyDir, err := ioutil.TempDir(i.Config.DataDir, "tsh")
	if err != nil {
		return nil, err
	}

	// break down proxy address into host, ssh_port and web_port:
	proxyConf := &i.Config.Proxy
	proxyHost, sp, err := net.SplitHostPort(proxyConf.SSHAddr.Addr)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	proxySSHPort, err := strconv.Atoi(sp)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	_, sp, err = net.SplitHostPort(proxyConf.WebAddr.Addr)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	proxyWebPort, err := strconv.Atoi(sp)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	cconf := &client.Config{
		Username:           login,
		Host:               host,
		HostPort:           port,
		HostLogin:          login,
		InsecureSkipVerify: true,
		KeysDir:            keyDir,
		SiteName:           site,
	}
	cconf.SetProxy(proxyHost, proxyWebPort, proxySSHPort)

	tc, err = client.NewClient(cconf)
	if err != nil {
		return nil, err
	}
	// confnigures the client authenticate using the keys from 'secrets':
	user, ok := i.Secrets.Users[login]
	if !ok {
		return nil, trace.Errorf("unknown login '%v'", login)
	}
	if user.Key == nil {
		return nil, trace.Errorf("user %v has no key", login)
	}
	_, err = tc.AddKey(host, user.Key)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	// tell the client to trust given CAs (from secrets). this is the
	// equivalent of 'known hosts' in openssh
	cas := i.Secrets.GetCAs()
	for i := range cas {
		err = tc.AddTrustedCA(&cas[i])
		if err != nil {
			return nil, trace.Wrap(err)
		}
	}
	return tc, nil
}

func (i *TeleInstance) Stop(removeData bool) error {
	if i.Config != nil && removeData {
		err := os.RemoveAll(i.Config.DataDir)
		if err != nil {
			log.Error("failed removing temporary local Teleport directory", err)
		}
	}
	log.Infof("Asking Teleport to stop")
	err := i.Process.Close()
	if err != nil {
		log.Error(err)
		return trace.Wrap(err)
	}
	defer func() {
		log.Infof("Teleport instance '%v' stopped!", i.Secrets.SiteName)
	}()
	return i.Process.Wait()
}

func fatalIf(err error) {
	if err != nil {
		log.Fatal("", err)
	}
}

func makeKey() (priv, pub []byte) {
	priv, pub, _ = native.New().GenerateKeyPair("")
	return priv, pub
}
