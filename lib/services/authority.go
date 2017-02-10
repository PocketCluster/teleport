package services

import (
	"time"

	"github.com/gravitational/teleport"
	"github.com/gravitational/trace"
)

// CertParams defines all parameters needed to generate a host certificate.
type CertParams struct {
	PrivateCASigningKey []byte         // PrivateCASigningKey is the private key of the CA that will sign the public key of the host.
	PublicHostKey       []byte         // PublicHostKey is the public key of the host.
	HostID              string         // HostID is used by Teleport to uniquely identify a node within a cluster.
	NodeName            string         // NodeName is the DNS name of the node.
	ClusterName         string         // ClusterName is the name of the cluster within which a node lives.
	Roles               teleport.Roles // Roles identifies the roles of a Teleport instance.
	TTL                 time.Duration  // TTL defines how long a certificate is valid for.
}

func (c *CertParams) Check() error {
	if c.HostID == "" || c.ClusterName == "" {
		return trace.BadParameter("HostID [%q] and ClusterName [%q] are required",
			c.HostID, c.ClusterName)
	}

	if err := c.Roles.Check(); err != nil {
		return trace.Wrap(err)
	}

	return nil
}
