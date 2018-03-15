package auth

import (
    "fmt"

    log "github.com/Sirupsen/logrus"
    "github.com/gravitational/trace"
    "github.com/gravitational/teleport/lib/services"
    "github.com/stkim1/pcrypto"
)

/* --- o --- o --- o --- o --- o --- o --- o --- o --- o --- o --- o --- o --- o --- o --- o --- o --- o --- o --- o --- */
// signup token data
// TODO : apply encryption
type signupTokenPack struct {
    SignupToken   *services.SignupToken    `json:"signuptokendata"`
}

func (a *AuthWithRoles) releaseSignupToken(signupToken string) (*signupTokenPack, error) {
    // TODO : add action perm for getting signup token data
    if err := a.permChecker.HasPermission(a.role, ActionCreateUserWithToken); err != nil {
        return nil, trace.Wrap(err)
    }
    tokenData, err := a.authServer.Identity.GetSignupToken(signupToken)
    if err != nil {
        return nil, trace.Wrap(err)
    }
    return &signupTokenPack{
        SignupToken:    tokenData,
    }, nil
}

/* --- o --- o --- o --- o --- o --- o --- o --- o --- o --- o --- o --- o --- o --- o --- o --- o --- o --- o --- o --- */
// createSignedCertificate generates private key and certificate signed
// by the host certificate authority, listing the role of this server
func createSignedCertificate(certSigner *pcrypto.CaSigner, req *requestOperationParamWithToken) (*PocketResponseAuthKeyCert, error) {
    // TODO : check if signed cert for this uuid exists. If does, return the value

    a := certSigner.CertificateAuthority()
    _, k, _, err := pcrypto.GenerateStrongKeyPair()
    if err != nil {
        return nil, trace.Wrap(err)
    }
    c, err := certSigner.GenerateSignedCertificate(req.Hostname, "", k)
    if err != nil {
        log.Warningf("[AUTH] Node `%v` cannot receive a signed certificate : cert generation error. %v", req.Hostname, err)
        return nil, trace.Wrap(err)
    }
    return &PocketResponseAuthKeyCert{
        Auth: a,
        Key:  k,
        Cert: c,
    }, nil
}

// issueSignedCertificateWithToken adds a new signed certificate for a node to the PocketCluster using previously issued token.
// A node must also request a specific role (and the role must match one of the roles the token was generated for).
//
// If a token was generated with a TTL, it gets enforced (can't register new nodes after TTL expires)
// If a token was generated with a TTL=0, it means it's a single-use token and it gets destroyed
// after a successful registration.
func issueSignedCertificateWithToken(a *AuthWithRoles, certSigner *pcrypto.CaSigner, req *requestOperationParamWithToken) (*PocketResponseAuthKeyCert, error) {
    if len(req.Hostname) == 0 {
        return nil, trace.BadParameter("Hostname cannot be empty")
    }
    if len(req.HostUUID) == 0 {
        return nil, trace.BadParameter("HostID cannot be empty")
    }
    log.Infof("[AUTH] Node `%v`[%v] requests a signed certificate", req.Hostname, req.HostUUID)
    if err := req.Role.Check(); err != nil {
        return nil, trace.Wrap(err)
    }
    // make sure the token is valid:
    roles, err := a.authServer.ValidateToken(req.Token)
    if err != nil {
        msg := fmt.Sprintf("`%v` cannot receive a signed certificate with %s. Token error: %v", req.Hostname, req.Role, err)
        log.Warnf("[AUTH] %s", msg)
        return nil, trace.AccessDenied(msg)
    }
    // make sure the caller is requested wthe role allowed by the token:
    if !roles.Include(req.Role) {
        msg := fmt.Sprintf("'%v' cannot receive a signed certificate, the token does not allow '%s' role", req.Hostname, req.Role)
        log.Warningf("[AUTH] %s", msg)
        return nil, trace.BadParameter(msg)
    }
    if !checkTokenTTL(a.authServer, req.Token) {
        return nil, trace.AccessDenied("'%v' cannot cannot receive a signed certificate. The token has expired", req.Hostname)
    }
    // generate & return the node cert:
    keys, err := createSignedCertificate(certSigner, req)
    if err != nil {
        return nil, trace.Wrap(err)
    }
    log.Infof("[AUTH] A signed Certificate for Node `%v` is issued", req.Hostname)
    return keys, nil
}

func (a *AuthWithRoles) issueSignedCertificateWithToken(certSigner *pcrypto.CaSigner, req *requestOperationParamWithToken) (*PocketResponseAuthKeyCert, error) {
    if err := a.permChecker.HasPermission(a.role, ActionIssueSignedCertificateWithToken); err != nil {
        return nil, trace.Wrap(err)
    }
    return issueSignedCertificateWithToken(a, certSigner, req)
}

/* --- o --- o --- o --- o --- o --- o --- o --- o --- o --- o --- o --- o --- o --- o --- o --- o --- o --- o --- o --- */
func (a *AuthWithRoles) deliverUserInformationWithToken(kiosk UserIdentityKiosk, req *requestOperationParamWithToken) (*PocketResponseUserIdentity, error) {
    if kiosk == nil {
        return nil, trace.BadParameter("cannot proceed with null user kiosk")
    }
    if req == nil {
        return nil, trace.BadParameter("cannot proceed with null request token")
    }
    if len(req.Hostname) == 0 {
        return nil, trace.BadParameter("Hostname cannot be empty")
    }
    if len(req.HostUUID) == 0 {
        return nil, trace.BadParameter("HostID cannot be empty")
    }
    if err := req.Role.Check(); err != nil {
        return nil, trace.Wrap(err)
    }
    if err := a.permChecker.HasPermission(a.role, ActionDeliverUserIdentityWithToken); err != nil {
        return nil, trace.Wrap(err)
    }

    log.Infof("[AUTH] Node `%v`[%v] requests user identity", req.Hostname, req.HostUUID)
    // make sure the token is valid:
    roles, err := a.authServer.ValidateToken(req.Token)
    if err != nil {
        msg := fmt.Sprintf("`%v` cannot receive user identity with %s. Token error: %v", req.Hostname, req.Role, err)
        log.Warnf("[AUTH] %s", msg)
        return nil, trace.AccessDenied(msg)
    }
    // make sure the caller is requested wthe role allowed by the token:
    if !roles.Include(req.Role) {
        msg := fmt.Sprintf("'%v' cannot receive user identity, the token does not allow '%s' role", req.Hostname, req.Role)
        log.Warningf("[AUTH] %s", msg)
        return nil, trace.BadParameter(msg)
    }
    if !checkTokenTTL(a.authServer, req.Token) {
        return nil, trace.AccessDenied("'%v' cannot cannot receive user identity. The token has expired", req.Hostname)
    }

    // TODO record who you sent user information with `req` param
    uinfo, err := kiosk.GetUserIdentity(req.Hostname, req.HostUUID)
    if err != nil {
        return nil, trace.Wrap(err)
    }
    return &PocketResponseUserIdentity {
        LoginName: uinfo.LoginName,
        UID:       uinfo.UID,
        GID:       uinfo.GID,
    }, nil
}