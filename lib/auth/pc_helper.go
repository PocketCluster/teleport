package auth

import (
    "fmt"
    "time"
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

func apiEndpoint(params ...string) string {
    return fmt.Sprintf("http://stub:0/%s/%s", PocketApiVersion, strings.Join(params, "/"))
}
