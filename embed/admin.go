package embed

import (
    "time"

    "github.com/gravitational/teleport"
    "github.com/gravitational/teleport/lib/auth"
    "github.com/gravitational/trace"
)

const (
    MaxInvitationTLL time.Duration = (time.Minute * 5)
    MinInvitationTLL time.Duration = time.Minute
)

// generates an invitation token which can be used to add another SSH node to a cluster
func GenerateNodeInviationWithTTL(client *auth.TunClient, ttl time.Duration) (string, error) {
    roles, err := teleport.ParseRoles("node")
    if err != nil {
        return "", trace.Wrap(err)
    }

    // adjust ttl
    if ttl < MinInvitationTLL || MaxInvitationTLL < ttl {
        ttl = MaxInvitationTLL
    }
    return client.GenerateToken(roles, ttl)
}
