package client

import (
    "os"

    "github.com/gravitational/teleport/lib/defaults"
    log "github.com/Sirupsen/logrus"
    "github.com/gravitational/trace"
    "golang.org/x/crypto/ssh/agent"
)

// NewPocketClient creates a TeleportClient object and fully configures it
func NewPocketClient(c *Config) (tc *TeleportClient, err error) {
    // validate configuration
    if c.Username == "" {
        c.Username = Username()
        log.Infof("no teleport login given. defaulting to %s", c.Username)
    }
    if c.ProxyHostPort == "" {
        return nil, trace.Errorf("No proxy address specified, missed --proxy flag?")
    }
    if c.HostLogin == "" {
        c.HostLogin = Username()
        log.Infof("no host login given. defaulting to %s", c.HostLogin)
    }
    if c.KeyTTL == 0 {
        c.KeyTTL = defaults.CertDuration
    } else if c.KeyTTL > defaults.MaxCertDuration || c.KeyTTL < defaults.MinCertDuration {
        return nil, trace.Errorf("invalid requested cert TTL")
    }

    tc = &TeleportClient{Config: *c}

    // initialize the local agent (auth agent which uses local SSH keys signed by the CA):
    tc.localAgent, err = newPocketAgent(c.KeysDir, c.Username)
    if err != nil {
        return nil, trace.Wrap(err)
    }

    if tc.Stdout == nil {
        tc.Stdout = os.Stdout
    }
    if tc.Stderr == nil {
        tc.Stderr = os.Stderr
    }
    if tc.Stdin == nil {
        tc.Stdin = os.Stdin
    }
    if tc.HostKeyCallback == nil {
        tc.HostKeyCallback = tc.localAgent.CheckHostSignature
    }

    // sometimes we need to use external auth without using local auth
    // methods, e.g. in automation daemons
    if c.SkipLocalAuth {
        if len(c.AuthMethods) == 0 {
            return nil, trace.BadParameter("SkipLocalAuth is true but no AuthMethods provided")
        }
        return tc, nil
    }
    return tc, nil
}

// NewLocalAgent reads all Teleport certificates from disk (using FSLocalKeyStore),
// creates a LocalKeyAgent, loads all certificates into it, and returns the agent.
func newPocketAgent(keyDir, username string) (a *LocalKeyAgent, err error) {
    keystore, err := NewFSLocalKeyStore(keyDir)
    if err != nil {
        return nil, trace.Wrap(err)
    }

    // TODO : (03/08/2017) add auth method based on pocketcluster auth protocol. we're watching ssh agent for now.
    a = &LocalKeyAgent{
        Agent:    agent.NewKeyring(),
        keyStore: keystore,
        sshAgent: connectToSSHAgent(),
    }

    // read all keys from disk (~/.tsh usually)
    keys, err := a.GetKeys(username)
    if err != nil {
        return nil, trace.Wrap(err)
    }

    // load all keys into the agent
    for _, key := range keys {
        _, err = a.LoadKey(username, key)
        if err != nil {
            return nil, trace.Wrap(err)
        }
    }

    return a, nil
}