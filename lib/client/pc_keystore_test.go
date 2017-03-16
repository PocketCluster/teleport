package client

import (
    "fmt"
    "time"
    "reflect"

    "github.com/gravitational/teleport/lib/auth/testauthority"
    "github.com/gravitational/teleport/lib/sshutils"
    "github.com/gravitational/teleport/lib/utils"
    "github.com/gravitational/trace"
    "golang.org/x/crypto/ssh"
    "gopkg.in/check.v1"
)

type PCKeyStoreTestSuite struct {
    store    *MEMLocalKeyStore
    keygen   *testauthority.Keygen
}

var _ = check.Suite(&PCKeyStoreTestSuite{})

func cleanMemLocalKeyStorage(ms *MEMLocalKeyStore) {
    ms.keyVault   = make(map[string]map[string][]byte)
    ms.knownHosts = make([]string, 0)
}

func (s *PCKeyStoreTestSuite) SetUpSuite(c *check.C) {
    utils.InitLoggerForTests()
    var err error
    s.keygen = testauthority.New()
    s.store, err = NewMemLocalKeyStore()
    c.Assert(err, check.IsNil)
    c.Assert(s.store, check.NotNil)
}

func (s *PCKeyStoreTestSuite) TearDownSuite(c *check.C) {
    cleanMemLocalKeyStorage(s.store)
}

func (s *PCKeyStoreTestSuite) SetUpTest(c *check.C) {
    cleanMemLocalKeyStorage(s.store)
}

func (s *PCKeyStoreTestSuite) TestListKeys(c *check.C) {
    const keyNum = 5
    // add 5 keys for "bob"
    keys := make([]Key, keyNum)
    for i := 0; i < keyNum; i++ {
        key := s.makeSignedKey(c, false)
        host := fmt.Sprintf("host-%v", i)
        s.store.AddKey(host, "bob", key)
        key.ProxyHost = host
        keys[i] = *key
    }
    checkExists := func (keyPool []Key, target Key) bool {
        for _, k := range keyPool {
            if reflect.DeepEqual(k, target) {
                return true
            }
        }
        return false
    }

    // add 1 key for "sam"
    samKey := s.makeSignedKey(c, false)
    s.store.AddKey("sam.host", "sam", samKey)

    // read all bob keys:
    keys2, err := s.store.GetKeys("bob")
    c.Assert(err, check.IsNil)
    c.Assert(keys2, check.HasLen, keyNum)
    for _, k2 := range keys2 {
        isExist := checkExists(keys, k2)
        c.Assert(isExist, check.Equals, true)
    }

    // read sam's key and make sure it's the same:
    keys, err = s.store.GetKeys("sam")
    c.Assert(err, check.IsNil)
    c.Assert(keys, check.HasLen, 1)
    c.Assert(samKey.Cert, check.DeepEquals, keys[0].Cert)
    c.Assert(samKey.Pub, check.DeepEquals, keys[0].Pub)
}

func (s *PCKeyStoreTestSuite) TestKeyCRUD(c *check.C) {
    key := s.makeSignedKey(c, false)

    // add key:
    err := s.store.AddKey("host.a", "bob", key)
    c.Assert(err, check.IsNil)

    // load back and compare:
    keyCopy, err := s.store.GetKey("host.a", "bob")
    c.Assert(err, check.IsNil)
    c.Assert(key.EqualsTo(keyCopy), check.Equals, true)

    // Delete & verify that its' gone
    err = s.store.DeleteKey("host.a", "bob")
    c.Assert(err, check.IsNil)
    keyCopy, err = s.store.GetKey("host.a", "bob")
    c.Assert(err, check.NotNil)
    c.Assert(trace.IsNotFound(err), check.Equals, true)

    // Delete non-existing
    err = s.store.DeleteKey("non-existing-host", "non-existing-user")
    c.Assert(err, check.NotNil)
    c.Assert(trace.IsNotFound(err), check.Equals, true)
}

func (s *PCKeyStoreTestSuite) TestKeyExpiration(c *check.C) {
    // make two keys: one is current, and the expire one
    good := s.makeSignedKey(c, false)
    expired := s.makeSignedKey(c, true)

    s.store.AddKey("good.host", "sam", good)
    s.store.AddKey("expired.host", "sam", expired)

    // get all keys back. only "good" key should be returned:
    keys, _ := s.store.GetKeys("sam")
    c.Assert(keys, check.HasLen, 1)
    c.Assert(keys[0].EqualsTo(good), check.Equals, true)
}

func (s *PCKeyStoreTestSuite) TestKnownHosts(c *check.C) {
    pub, _, _, _, err := ssh.ParseAuthorizedKey(CAPub)
    c.Assert(err, check.IsNil)

    _, p2, _ := s.keygen.GenerateKeyPair("")
    pub2, _, _, _, _ := ssh.ParseAuthorizedKey(p2)

    err = s.store.AddKnownHostKeys("example.com", []ssh.PublicKey{pub})
    c.Assert(err, check.IsNil)
    err = s.store.AddKnownHostKeys("example.com", []ssh.PublicKey{pub2})
    c.Assert(err, check.IsNil)
    err = s.store.AddKnownHostKeys("example.org", []ssh.PublicKey{pub2})
    c.Assert(err, check.IsNil)

    keys, err := s.store.GetKnownHostKeys("")
    c.Assert(err, check.IsNil)
    c.Assert(keys, check.HasLen, 3)
    c.Assert(keys, check.DeepEquals, []ssh.PublicKey{pub, pub2, pub2})

    // check against dupes:
    before, _ := s.store.GetKnownHostKeys("")
    s.store.AddKnownHostKeys("example.org", []ssh.PublicKey{pub2})
    s.store.AddKnownHostKeys("example.org", []ssh.PublicKey{pub2})
    after, _ := s.store.GetKnownHostKeys("")
    c.Assert(len(before), check.Equals, len(after))

    // check by hostname:
    keys, _ = s.store.GetKnownHostKeys("badhost")
    c.Assert(len(keys), check.Equals, 0)
    keys, _ = s.store.GetKnownHostKeys("example.org")
    c.Assert(len(keys), check.Equals, 1)
    c.Assert(sshutils.KeysEqual(keys[0], pub2), check.Equals, true)
}

// makeSIgnedKey helper returns all 3 components of a user key (signed by CAPriv key)
func (s *PCKeyStoreTestSuite) makeSignedKey(c *check.C, makeExpired bool) *Key {
    var (
        err             error
        priv, pub, cert []byte
    )
    priv, pub, _ = s.keygen.GenerateKeyPair("")
    username := "vincento"
    allowedLogins := []string{username, "root"}
    ttl := time.Duration(time.Minute * 20)
    if makeExpired {
        ttl = -ttl
    }
    cert, err = s.keygen.GenerateUserCert(CAPriv, pub, username, allowedLogins, ttl)
    c.Assert(err, check.IsNil)
    return &Key{
        Priv: priv,
        Pub:  pub,
        Cert: cert,
    }
}
