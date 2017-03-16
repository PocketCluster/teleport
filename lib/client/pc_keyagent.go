package client

import (
    "golang.org/x/crypto/ssh"
    "golang.org/x/crypto/ssh/agent"

    "github.com/gravitational/trace"
)

// TODO : (03/14/2017) this is now removed from user login flow. Delete this when it is fine to do so
// convert keys into a format understood by the ssh agent without saving anything.
func certMethodWithUserCertificate(key *Key) (*CertAuthMethod, error) {
    agentKeys, err := key.AsAgentKeys()
    if err != nil {
        return nil, trace.Wrap(err)
    }
    firstKey := agentKeys[0]

    // generate SSH auth method based on the given signed key and return
    // it to the caller:
    signer, err := ssh.NewSignerFromKey(firstKey.PrivateKey)
    if err != nil {
        return nil, trace.Wrap(err)
    }
    if signer, err = ssh.NewCertSigner(firstKey.Certificate, signer); err != nil {
        return nil, trace.Wrap(err)
    }

    return methodForCert(signer), nil
}

// NewLocalAgent reads all Teleport certificates from disk (using FSLocalKeyStore),
// creates a LocalKeyAgent, loads all certificates into it, and returns the agent.
func NewPocketLocalAgent(username string) (a *LocalKeyAgent, err error) {
    keystore, err := NewMemLocalKeyStore()
    if err != nil {
        return nil, trace.Wrap(err)
    }

    a = &LocalKeyAgent{
        Agent:    agent.NewKeyring(),
        keyStore: keystore,
        sshAgent: connectToSSHAgent(),
    }

    // read all keys from memory
    // TODO : (03/14/2017) the keys need to be persisted in database
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
