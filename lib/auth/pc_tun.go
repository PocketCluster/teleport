package auth

import (
    "encoding/json"
    "fmt"
    "os"

    "github.com/gravitational/teleport"
    "github.com/gravitational/teleport/lib/utils"

    log "github.com/Sirupsen/logrus"
    "github.com/gravitational/trace"
    "golang.org/x/crypto/ssh"
)

const (
    AuthAESEncryption = "aesencrypt"
)

func (s *AuthTunnel) passwordAuth(
conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
    var ab *authBucket
    if err := json.Unmarshal(password, &ab); err != nil {
        return nil, err
    }

    log.Infof("[AUTH] login attempt: user '%v' type '%v'", conn.User(), ab.Type)

    switch ab.Type {
    case AuthAESEncryption:
        // TODO : need to check if AES encrypted data is fully decrypted w/o error
        if err := s.authServer.CheckPasswordWOToken(conn.User(), ab.Pass); err != nil {
            log.Warningf("password auth error: %#v", err)
            return nil, trace.Wrap(err)
        }
        perms := &ssh.Permissions{
            Extensions: map[string]string{
                ExtWebPassword: "<password>",
                ExtRole:        string(teleport.RoleUser),
            },
        }
        log.Infof("[AUTH] AES Encryption authenticated user: '%v'", conn.User())
        return perms, nil
    case AuthWebPassword:
        if err := s.authServer.CheckPassword(conn.User(), ab.Pass, ab.HotpToken); err != nil {
            log.Warningf("password auth error: %#v", err)
            return nil, trace.Wrap(err)
        }
        perms := &ssh.Permissions{
            Extensions: map[string]string{
                ExtWebPassword: "<password>",
                ExtRole:        string(teleport.RoleUser),
            },
        }
        log.Infof("[AUTH] password authenticated user: '%v'", conn.User())
        return perms, nil
    case AuthWebSession:
        // we use extra permissions mechanism to keep the connection data
        // after authorization, in this case the session
        perms := &ssh.Permissions{
            Extensions: map[string]string{
                ExtWebSession: string(ab.Pass),
                ExtRole:       string(teleport.RoleWeb),
            },
        }
        if _, err := s.authServer.GetWebSession(conn.User(), string(ab.Pass)); err != nil {
            return nil, trace.Errorf("session resume error: %v", trace.Wrap(err))
        }
        log.Infof("[AUTH] session authenticated user: '%v'", conn.User())
        return perms, nil
    // when a new server tries to use the auth API to register in the cluster,
    // it will use the token as a passowrd (happens only once during registration):
    case AuthToken:
        _, err := s.authServer.ValidateToken(string(ab.Pass))
        if err != nil {
            log.Errorf("token validation error: %v", err)
            return nil, trace.Wrap(err, fmt.Sprintf("invalid token for: %v", ab.User))
        }
        perms := &ssh.Permissions{
            Extensions: map[string]string{
                ExtToken: string(password),
                ExtRole:  string(teleport.RoleProvisionToken),
            }}
        utils.Consolef(os.Stdout, "[AUTH] Successfully accepted token for %v", conn.User())
        return perms, nil
    case AuthSignupToken:
        _, err := s.authServer.GetSignupToken(string(ab.Pass))
        if err != nil {
            return nil, trace.Errorf("token validation error: %v", trace.Wrap(err))
        }
        perms := &ssh.Permissions{
            Extensions: map[string]string{
                ExtToken: string(password),
                ExtRole:  string(teleport.RoleSignup),
            }}
        log.Infof("[AUTH] session authenticated prov. token: '%v'", conn.User())
        return perms, nil
    default:
        return nil, trace.Errorf("unsupported auth method: '%v'", ab.Type)
    }
}

func NewWebAESEncryptionAuth(user string, password []byte, encrypted string) ([]ssh.AuthMethod, error) {
    data, err := json.Marshal(authBucket{
        Type:      AuthAESEncryption,
        User:      user,
        Pass:      password,
        HotpToken: encrypted,
    })
    if err != nil {
        return nil, err
    }
    return []ssh.AuthMethod{ssh.Password(string(data))}, nil
}
