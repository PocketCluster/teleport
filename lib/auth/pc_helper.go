package auth

import (
    "fmt"
    "time"
    "io/ioutil"
    "strings"

    log "github.com/Sirupsen/logrus"
)

// enforceTokenTTL deletes the given token if it's TTL is over. Returns 'false'
// if this token cannot be used
func checkTokenTTL(s *AuthServer, token string) bool {
    // look at the tokens in the token storage
    tok, err := s.Provisioner.GetToken(token)
    if err != nil {
        log.Warn(err)
        return true
    }
    // s.clock is replaced with time.Now()
    now := time.Now().UTC()
    if tok.Expires.Before(now) {
        if err = s.DeleteToken(token); err != nil {
            log.Error(err)
        }
        return false
    }
    return true
}

func writeDockerKeyAndCert(certOpts *PocketCertParam, keys *packedAuthKeyCert) error {
    log.Debugf("write slave docker auth to %v, key to %v, cert from %v", certOpts.DockerAuthFile, certOpts.DockerKeyFile, certOpts.DockerCertFile)
    if err := ioutil.WriteFile(certOpts.DockerAuthFile, keys.Auth, 0600); err != nil {
        return err
    }
    if err := ioutil.WriteFile(certOpts.DockerKeyFile,  keys.Key, 0600); err != nil {
        return err
    }
    if err := ioutil.WriteFile(certOpts.DockerCertFile, keys.Cert, 0600); err != nil {
        return err
    }
    return nil
}

func apiEndpoint(params ...string) string {
    return fmt.Sprintf("http://stub:0/%s/%s", PocketApiVersion, strings.Join(params, "/"))
}