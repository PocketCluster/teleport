// +build darwin
package service

import (
    "fmt"

    "github.com/gravitational/teleport/lib/defaults"
    "github.com/gravitational/teleport/lib/utils"

    "github.com/stkim1/pc-core/context"
    . "gopkg.in/check.v1"
)

type PocketConfigSuite struct {
    dataDir     string
}

var _ = Suite(&PocketConfigSuite{})

func (s *PocketConfigSuite) SetUpSuite(c *C) {
    utils.InitLoggerForTests()
}

func (s *PocketConfigSuite) TearDownSuite(c *C) {
}

func (s *PocketConfigSuite) SetUpTest(c *C) {
    context.DebugContextPrepare()

    dataDir, _ := context.SharedHostContext().ApplicationUserDataDirectory()
    s.dataDir = dataDir + "/teleport"
    c.Logf("[INFO] User DataDir %s", dataDir)
}

func (s *PocketConfigSuite) TearDownTest(c *C) {
    context.DebugContextDestroy()

    s.dataDir = ""
}

func (s *PocketConfigSuite) TestDefaultConfig(c *C) {
    config := MakeCoreConfig(true)
    c.Assert(config, NotNil)

    // all 3 services should be enabled by default
    c.Assert(config.Auth.Enabled, Equals, true)
    c.Assert(config.SSH.Enabled, Equals, false)
    c.Assert(config.Proxy.Enabled, Equals, true)
    // FIXME : check if this is necessary for up and running server
    c.Assert(config.Proxy.DisableWebUI, Equals, false)

    localAuthAddr := utils.NetAddr{AddrNetwork: "tcp", Addr: "0.0.0.0:3025"}
    localProxyAddr := utils.NetAddr{AddrNetwork: "tcp", Addr: "0.0.0.0:3023"}
    localSSHAddr := utils.NetAddr{AddrNetwork: "tcp", Addr: "0.0.0.0:3022"}

    // data dir, hostname and auth server
    c.Assert(config.DataDir, Equals, s.dataDir)
    if len(config.Hostname) < 2 {
        c.Error("default hostname wasn't properly set")
    }

    // auth section
    auth := config.Auth
    c.Assert(auth.SSHAddr, DeepEquals, localAuthAddr)
    c.Assert(auth.Limiter.MaxConnections, Equals, int64(defaults.LimiterMaxConnections))
    c.Assert(auth.Limiter.MaxNumberOfUsers, Equals, defaults.LimiterMaxConcurrentUsers)

    c.Assert(auth.KeysBackend.Type, Equals, defaults.CoreBackendType)
    c.Assert(auth.KeysBackend.Params, Equals, fmt.Sprintf(`{"path": "%s/keys.db"}`, s.dataDir))
    c.Assert(auth.EventsBackend.Type, Equals, defaults.CoreBackendType)
    c.Assert(auth.EventsBackend.Params, Equals, fmt.Sprintf(`{"path": "%s/events.db"}`, s.dataDir))
    c.Assert(auth.RecordsBackend.Type, Equals, defaults.CoreBackendType)
    c.Assert(auth.RecordsBackend.Params, Equals, fmt.Sprintf(`{"path": "%s/records.db"}`, s.dataDir))

    // SSH section
    ssh := config.SSH
    c.Assert(ssh.Addr, DeepEquals, localSSHAddr)
    c.Assert(ssh.Limiter.MaxConnections, Equals, int64(defaults.LimiterMaxConnections))
    c.Assert(ssh.Limiter.MaxNumberOfUsers, Equals, defaults.LimiterMaxConcurrentUsers)

    // proxy section
    proxy := config.Proxy
    c.Assert(proxy.AssetsDir, Equals, s.dataDir)
    c.Assert(proxy.SSHAddr, DeepEquals, localProxyAddr)
    c.Assert(proxy.Limiter.MaxConnections, Equals, int64(defaults.LimiterMaxConnections))
    c.Assert(proxy.Limiter.MaxNumberOfUsers, Equals, defaults.LimiterMaxConcurrentUsers)
}
