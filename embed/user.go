package embed

import (
    "github.com/gravitational/teleport/lib/auth"
    "github.com/gravitational/teleport/lib/services"
    "github.com/gravitational/trace"
)

func CreateTeleportUser(client *auth.TunClient, user, pass string) error {
    var (
        u = &services.TeleportUser{
            Name:          user,
            AllowedLogins: []string{user},
        }
    )
    token, err := client.CreateSignupToken(u)
    if err != nil {
        return trace.Wrap(err)
    }
    hotpToken, err := auth.RequestHOTPforSignupToken(client, token)
    if err != nil {
        return trace.Wrap(err)
    }
    _, err = client.CreateUserWithToken(token, pass, hotpToken[0])
    if err != nil {
        return trace.Wrap(err)
    }
    return nil
}