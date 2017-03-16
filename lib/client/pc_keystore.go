package client

import (
    "fmt"
    "strings"
    "time"

    "github.com/gravitational/teleport/lib/sshutils"
    "github.com/gravitational/trace"

    log "github.com/Sirupsen/logrus"
    "golang.org/x/crypto/ssh"
)

type MEMLocalKeyStore struct {
    LocalKeyStore
    keyVault        map[string]map[string][]byte
    knownHosts      []string
}

func NewMemLocalKeyStore() (*MEMLocalKeyStore, error) {
    return &MEMLocalKeyStore{
        keyVault: make(map[string]map[string][]byte),
        knownHosts: make([]string, 0),
    }, nil
}

// GetKeys returns all user session keys stored in the store
func (ms *MEMLocalKeyStore) GetKeys(username string) ([]Key, error) {
    var keys []Key
    for host, _ := range ms.keyVault {
        k, err := ms.GetKey(host, username)
        if err != nil {
            // if a key is reported as 'not found' it's probably because it expired
            if !trace.IsNotFound(err) {
                return nil, trace.Wrap(err)
            }
            continue
        }
        keys = append(keys, *k)
    }
    return keys, nil
}

func (ms *MEMLocalKeyStore) AddKey(host string, username string, key *Key) error {
    userCert := map[string][]byte {
        username+fileExtPub:     key.Pub,
        username+fileExtKey:     key.Priv,
        username+fileExtCert:    key.Cert,
    }
    ms.keyVault[host] = userCert
    return nil
}

func (ms *MEMLocalKeyStore) GetKey(host string, username string) (*Key, error) {
    userCert, ok := ms.keyVault[host]
    if !ok {
        return nil, trace.NotFound("Unable to retreive keys for host %s", host)
    }
    pub, ok := userCert[username+fileExtPub]
    if !ok {
        return nil, trace.NotFound("Unable to retreive pubkey for user %s on host %s", username, host)
    }
    priv, ok := userCert[username+fileExtKey]
    if !ok {
        return nil, trace.NotFound("Unable to retreive privkey for user %s on host %s", username, host)
    }
    cert, ok := userCert[username+fileExtCert]
    if !ok {
        return nil, trace.NotFound("Unable to retreive privkey for user %s on host %s", username, host)
    }

    key := &Key{Pub: pub, Priv: priv, Cert: cert, ProxyHost: host}

    // expired certificate? this key won't be accepted anymore, lets delete it:
    certExpiration, err := key.CertValidBefore()
    if err != nil {
        return nil, trace.Wrap(err)
    }
    log.Debugf("returning user cert valid until %v", certExpiration)
    if certExpiration.Before(time.Now()) {
        log.Infof("TTL expired (%v) for user %s", certExpiration, username)
        return nil, trace.NotFound("session keys for %s are not found", host)
    }
    return key, nil
}

func (ms *MEMLocalKeyStore) DeleteKey(host string, username string) error {
    userCert, ok := ms.keyVault[host]
    if !ok {
        return trace.NotFound("Unable to retreive keys for host %s", host)
    }

    delete(userCert, username+fileExtPub)
    delete(userCert, username+fileExtKey)
    delete(userCert, username+fileExtCert)
    return nil
}

// interface to known_hosts file:
func (ms *MEMLocalKeyStore) AddKnownHostKeys(hostname string, hostKeys []ssh.PublicKey) error {
    // read all existing entries into a map (this removes any pre-existing dupes)
    entries := make(map[string]int)
    output := make([]string, 0)
    for _, line := range ms.knownHosts {
        if _, exists := entries[line]; !exists {
            output = append(output, line)
            entries[line] = 1
        }
    }
    // add every host key to the list of entries
    for i := range hostKeys {
        log.Debugf("adding known host %s with key: %v", hostname, sshutils.Fingerprint(hostKeys[i]))
        bytes := ssh.MarshalAuthorizedKey(hostKeys[i])
        line := strings.TrimSpace(fmt.Sprintf("%s %s", hostname, bytes))
        if _, exists := entries[line]; !exists {
            output = append(output, line)
        }
    }
    // re-create the file:
    for _, line := range output {
        log.Debugf("%s\n", line)
    }
    ms.knownHosts = output
    return nil
}

func (ms *MEMLocalKeyStore) GetKnownHostKeys(hostname string) ([]ssh.PublicKey, error) {
    var (
        pubKey    ssh.PublicKey
        retval    []ssh.PublicKey = make([]ssh.PublicKey, 0)
        hosts     []string
        hostMatch bool
        err       error
    )

    for _, entry := range ms.knownHosts {
        _, hosts, pubKey, _, _, err = ssh.ParseKnownHosts([]byte(entry))
        if err == nil {
            hostMatch = (hostname == "")
            if !hostMatch {
                for i := range hosts {
                    if hosts[i] == hostname {
                        hostMatch = true
                        break
                    }
                }
            }
            if hostMatch {
                log.Debugf("hostkey for host %s found and added", hostname)
                retval = append(retval, pubKey)
            }
        }
    }
    return retval, nil
}
