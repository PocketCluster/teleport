package sqlitebk

import (
    "path/filepath"
    "testing"

    "github.com/gravitational/teleport/lib/backend/test"
    "github.com/gravitational/teleport/lib/utils"

    . "gopkg.in/check.v1"
)

func TestSqlite(t *testing.T) { TestingT(t) }

type SqliteSuite struct {
    sk     *SQLiteBackend
    suite  test.BackendSuite
    dir    string
}

var _ = Suite(&SqliteSuite{})

func (s *SqliteSuite) SetUpSuite(c *C) {
    utils.InitLoggerForTests()
}

func (s *SqliteSuite) SetUpTest(c *C) {
    s.dir = c.MkDir()

    var err error
    s.sk, err = New(filepath.Join(s.dir, "db"))
    c.Assert(err, IsNil)

    s.suite.ChangesC = make(chan interface{})
    s.suite.B = s.sk
}

func (s *SqliteSuite) TearDownTest(c *C) {
    c.Assert(s.sk.Close(), IsNil)
}

func (s *SqliteSuite) TestBasicCRUD(c *C) {
    s.suite.BasicCRUD(c)
}

func (s *SqliteSuite) TestCompareAndSwap(c *C) {
    s.suite.CompareAndSwap(c)
}

func (s *SqliteSuite) TestExpiration(c *C) {
    s.suite.Expiration(c)
}

func (s *SqliteSuite) TestRenewal(c *C) {
    s.suite.Renewal(c)
}

func (s *SqliteSuite) TestCreate(c *C) {
    s.suite.Create(c)
}

func (s *SqliteSuite) TestLock(c *C) {
    s.suite.Locking(c)
}

func (s *SqliteSuite) TestValueAndTTL(c *C) {
    s.suite.ValueAndTTl(c)
}
