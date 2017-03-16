package client

import (
    "github.com/gravitational/teleport/lib/web"
    "github.com/gravitational/trace"
)

// TODO : (03/14/2017) this is now removed from user login flow. Delete this when it is fine to do so
// directLogin asks for a password + HOTP token, makes a request to CA via proxy
func (tc *TeleportClient) apiDirectLogin(password, encryptedpwd string, pub []byte) (*web.SSHLoginResponse, error) {
    httpsProxyHostPort := tc.Config.ProxyWebHostPort()
    certPool := loopbackPool(httpsProxyHostPort)

    // ping the HTTPs endpoint first:
    if err := web.Ping(httpsProxyHostPort, tc.InsecureSkipVerify, certPool); err != nil {
        return nil, trace.Wrap(err)
    }

    // ask the CA (via proxy) to sign our public key:
    response, err := web.SSHAgentLoginWithAES(httpsProxyHostPort,
        tc.Config.Username,
        password,
        encryptedpwd,
        pub,
        tc.KeyTTL,
        tc.InsecureSkipVerify,
        certPool)

    return response, trace.Wrap(err)
}
