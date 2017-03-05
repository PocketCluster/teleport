package sqlitebk

import (
    "database/sql"
    "fmt"
    "os"
    "path/filepath"
    "sort"
    "sync"
    "time"

    _ "github.com/mattn/go-sqlite3"
    "github.com/gravitational/trace"
    "github.com/mailgun/timetools"
)

//region Helper Structure & Functions
type keyValueMeta struct {
    Table      string
    Created    time.Time
    TTL        time.Duration
    Key        string
    Value      []byte
}

func concatErrors(errs... error) error {
    var (
        err error = nil
    )
    if len(errs) == 0 {
        return err
    }

    for _, e := range errs {
        if e != nil {
            if err == nil {
                err = e
            } else {
                err = fmt.Errorf("%v | %v", err, e)
            }
        }
    }
    return err
}

// check if every table in the list exits
func checkTablesExist(sb *SQLiteBackend, tables []string) error {
    var err error = nil
    for _, tbl := range tables {
        var (
            counter int       = 0
            stmt *sql.Stmt    = nil
        )
        stmt, err = sb.db.Prepare(fmt.Sprintf("SELECT count(name) FROM sqlite_master WHERE type = 'table' AND name = '%s'", tbl))
        if err != nil {
            break
        }
        err = stmt.QueryRow().Scan(&counter);
        err = concatErrors(err, stmt.Close())
        // this is a special error that needs to be treated differently
        if counter == 0 {
            return trace.NotFound("table %v not found", tbl)
        }
        if err != nil {
            break
        }
    }
    return err
}

// this only cares if value for key exists in tables. The only error this returns is `NotFound`
// We don't care wheter this query comes up with error or not. We only cares if it returns value
func getValuesForKey(sb *SQLiteBackend, tables []string, key string) ([]*keyValueMeta, error) {
    var (
        out  []*keyValueMeta = nil
    )
    for _, tbl := range tables {
        var (
            stmt *sql.Stmt
            created time.Time
            ttl time.Duration
            value []byte
            err error
        )
        stmt, err = sb.db.Prepare(fmt.Sprintf("SELECT created, ttl, value FROM %s WHERE key = '%s'", tbl, key))
        if err != nil {
            continue
        }
        stmt.QueryRow().Scan(&created, &ttl, &value);
        if len(value) != 0 {
            out = append(out,
                &keyValueMeta{
                    Table:      tbl,
                    Created:    created,
                    TTL:        ttl,
                    Key:        key,
                    Value:      value,
                })
        }
        stmt.Close()
    }
    if out == nil || len(out) == 0 {
        return nil, trace.NotFound("Value for key %v in %v not found", key, tables)
    }
    return out, nil
}

func getAllKeysFromTables(sb *SQLiteBackend, tables []string) ([]string, error) {
    var (
        out []string
        err error           = nil
    )
    for _, tbl := range tables {
        var (
            stmt *sql.Stmt
            rows *sql.Rows
        )
        stmt, err = sb.db.Prepare(fmt.Sprintf("SELECT key FROM %s", tbl))
        if err != nil {
            return nil, err
        }
        rows, err = stmt.Query();
        if err != nil {
            err = concatErrors(err, stmt.Close())
            break
        }
        for rows.Next() {
            var key string
            err = rows.Scan(&key)
            if err != nil {
                break
            }
            out = append(out, key)
        }
        err = concatErrors(err, rows.Err())
        err = concatErrors(err, rows.Close())
        err = concatErrors(err, stmt.Close())
        if err != nil {
            break
        }
    }
    return out, err
}

func upsertTables(sb *SQLiteBackend, tables []string) error {
    var (
        trans *sql.Tx       = nil
        err error           = nil
    )
    trans, err = sb.db.Begin()
    if err != nil {
        return err
    }
    for _, tbl := range tables {
        var stmt *sql.Stmt
        stmt, err = trans.Prepare(fmt.Sprintf("CREATE TABLE IF NOT EXISTS %s (created DATETIME, ttl BIGINT, key TEXT PRIMARY KEY NOT NULL, value BLOB)", tbl))
        if err != nil {
            break
        }
        _, err = stmt.Exec()
        err = concatErrors(err, stmt.Close())
        if err != nil {
            break
        }
    }
    if err == nil {
        err = trans.Commit()
    } else {
        err = concatErrors(err, trans.Rollback())
    }
    return err
}

// func (b *BoltBackend) upsertVal(path []string, key string, val []byte, ttl time.Duration) error
func upsertValue(sb *SQLiteBackend, tables []string, key string, val []byte, ttl time.Duration) error {
    var (
        trans *sql.Tx       = nil
        err error           = nil
        created time.Time   = sb.clock.UtcNow()
    )
    trans, err = sb.db.Begin()
    if err != nil {
        return trace.Wrap(err)
    }
    for _, tbl := range tables {
        var stmt *sql.Stmt
        stmt, err = trans.Prepare(fmt.Sprintf("INSERT OR REPLACE INTO %s (created, ttl, key, value) values (?, ?, ?, ?)", tbl))
        if err != nil {
            break
        }
        _, err = stmt.Exec(created, ttl, key, val)
        err = concatErrors(err, stmt.Close())
        if err != nil {
            break
        }
    }
    if err == nil {
        err = trans.Commit()
    } else {
        err = concatErrors(err, trans.Rollback())
    }
    return err
}

func updateValue(sb *SQLiteBackend, tables []string, key string, val []byte, ttl time.Duration) error {
    var (
        trans *sql.Tx       = nil
        err error           = nil
        created time.Time   = sb.clock.UtcNow()
    )
    trans, err = sb.db.Begin()
    if err != nil {
        return err
    }
    for _, tbl := range tables {
        var stmt *sql.Stmt
        stmt, err = trans.Prepare(fmt.Sprintf("UPDATE OR IGNORE %s SET created = ?, ttl = ?, value = ? WHERE key = ?", tbl))
        if err != nil {
            break
        }
        _, err = stmt.Exec(created, ttl, val, key)
        err = concatErrors(err, stmt.Close())
        if err != nil {
            break
        }
    }
    if err == nil {
        err = trans.Commit()
    } else {
        err = concatErrors(err, trans.Rollback())
    }
    return err
}

func deleteKeyFromTables(sb *SQLiteBackend, tables []string, key string) error {
    var (
        trans *sql.Tx       = nil
        err error           = nil
    )
    trans, err = sb.db.Begin()
    if err != nil {
        return err
    }
    for _, tbl := range tables {
        var stmt *sql.Stmt
        stmt, err = trans.Prepare(fmt.Sprintf("DELETE FROM %s WHERE key = '%s';", tbl, key))
        if err != nil {
            break
        }
        _, err = stmt.Exec()
        err = concatErrors(err, stmt.Close())
        if err != nil {
            break
        }
    }
    if err == nil {
        err = trans.Commit()
    } else {
        err = concatErrors(err, trans.Rollback())
    }
    return err
}

func deleteTables(sb *SQLiteBackend, tables []string) error {
    var (
        trans *sql.Tx       = nil
        err error           = nil
    )
    trans, err = sb.db.Begin()
    if err != nil {
        return err
    }
    for _, tbl := range tables {
        var stmt *sql.Stmt
        stmt, err = trans.Prepare(fmt.Sprintf("DROP TABLE %s", tbl))
        if err != nil {
            break
        }
        _, err = stmt.Exec()
        err = concatErrors(err, stmt.Close())
        if err != nil {
            break
        }
    }
    if err == nil {
        err = trans.Commit()
    } else {
        err = concatErrors(err, trans.Rollback())
    }
    return err
}
//endregion

type SQLiteBackend struct {
    sync.Mutex

    db    *sql.DB
    clock timetools.TimeProvider
    locks map[string]time.Time
}

// Option sets functional options for the backend
type Option func(b *SQLiteBackend) error

// Clock sets clock for the backend, used in tests
func Clock(clock timetools.TimeProvider) Option {
    return func(b *SQLiteBackend) error {
        b.clock = clock
        return nil
    }
}

func New(path string, opts ...Option) (*SQLiteBackend, error) {
    path, err := filepath.Abs(path)
    if err != nil {
        return nil, trace.Wrap(err, "failed to convert path")
    }
    dir := filepath.Dir(path)
    s, err := os.Stat(dir)
    if err != nil {
        return nil, trace.Wrap(err)
    }
    if !s.IsDir() {
        return nil, trace.BadParameter("path '%v' should be a valid directory", dir)
    }
    b := &SQLiteBackend {
        locks: make(map[string]time.Time),
    }
    for _, option := range opts {
        if err := option(b); err != nil {
            return nil, trace.Wrap(err)
        }
    }
    if b.clock == nil {
        b.clock = &timetools.RealTime{}
    }
    db, err := sql.Open("sqlite3", path)
    if err != nil {
        return nil, trace.Wrap(err)
    }
    b.db = db
    return b, nil
}

// Close releases the resources taken up by this backend
func (sb *SQLiteBackend) Close() error {
    return sb.db.Close()
}

// GetKeys returns a list of keys for a given path
func (sb *SQLiteBackend) GetKeys(tables []string) ([]string, error) {
    var (
        keys []string
        err error = nil
    )
    err = checkTablesExist(sb, tables)
    if err != nil {
        if trace.IsNotFound(err) {
            return nil, nil
        }
        return nil, trace.Wrap(err)
    }
    keys, err = getAllKeysFromTables(sb, tables)
    if err != nil {
        return nil, trace.Wrap(err)
    }
    // now do an iteration to expire keys
    for _, key := range keys {
        sb.GetVal(tables, key)
    }
    // Here, we'll imitate the behavior of the original b.getKeys().
    // Get the last table and collect all the valid keys in the table
    tbl := tables[len(tables) - 1]
    keys, err = getAllKeysFromTables(sb, []string{tbl})
    if err != nil {
        return nil, trace.Wrap(err)
    }
    sort.Sort(sort.StringSlice(keys))
    return keys, nil
}

// GetVal return a value for a given key in the bucket
func (sb *SQLiteBackend) GetVal(tables []string, key string) ([]byte, error) {
    var (
        pruned int      = 0
        err, derr error = nil, nil
        values []*keyValueMeta
        last *keyValueMeta
    )
    err = checkTablesExist(sb, tables)
    if err != nil {
        return nil, trace.Wrap(err)
    }
    values, err = getValuesForKey(sb, tables, key)
    if err != nil {
        perr := checkTablesExist(sb, append(tables, key))
        if perr == nil {
            return nil, trace.BadParameter("key '%v 'is a table name", key)
        }
        // the only type of error getValuesForKey returns is NotFound.
        return nil, trace.Wrap(err)
    }

    // remove old value
    for _, v := range values {
        if v.TTL != 0 && sb.clock.UtcNow().Sub(v.Created) > v.TTL {
            pruned++
            derr = deleteKeyFromTables(sb, []string{v.Table}, key)
            if derr != nil {
                err = concatErrors(err, derr)
            }
        }
    }
    if pruned == len(values) {
        return nil, trace.NotFound("%v: %v not found", tables, key)
    }
    if err != nil {
        return nil, err
    }
    // FIXME : this is stupid as it only takes the last value and assume everything else is the same
    last = values[len(values) - 1]
    return last.Value, nil
}

// GetValAndTTL returns value and TTL for a key in bucket
func (sb *SQLiteBackend) GetValAndTTL(tables []string, key string) ([]byte, time.Duration, error) {
    var (
        pruned int              = 0
        err, derr error         = nil, nil
        newTTL time.Duration    = 0
        values []*keyValueMeta
        last *keyValueMeta
    )
    err = checkTablesExist(sb, tables)
    if err != nil {
        return nil, 0, trace.Wrap(err)
    }
    values, err = getValuesForKey(sb, tables, key)
    if err != nil {
        perr := checkTablesExist(sb, append(tables, key))
        if perr == nil {
            return nil, 0, trace.BadParameter("key '%v 'is a table name", key)
        }
        return nil, 0, trace.Wrap(err)
    }

    for _, v := range values {
        if v.TTL != 0 && sb.clock.UtcNow().Sub(v.Created) > v.TTL {
            pruned++
            derr = deleteKeyFromTables(sb, []string{v.Table}, key)
            if derr != nil {
                err = concatErrors(err, derr)
            }
        }
    }
    if pruned == len(values) {
        return nil, 0, trace.NotFound("%v: %v not found", tables, key)
    }
    if err != nil {
        return nil, 0, trace.Wrap(err)
    }
    // FIXME : this is stupid as it only takes the last value and assume everything else is the same
    last = values[len(values) - 1]
    if last.TTL != 0 {
        newTTL = last.Created.Add(last.TTL).Sub(sb.clock.UtcNow())
    }
    return last.Value, newTTL, nil
}

// CreateVal creates value with a given TTL and key in the bucket
// if the value already exists, returns AlreadyExistsError
func (sb *SQLiteBackend) CreateVal(tables []string, key string, val []byte, ttl time.Duration) error {
    var (
        values []*keyValueMeta  = nil
        err error               = nil
    )
    err = upsertTables(sb, tables)
    if err != nil {
        return trace.Wrap(err)
    }
    values, err = getValuesForKey(sb, tables, key)
    if values != nil {
        return trace.AlreadyExists("'%v' already exists", key)
    }
    err = upsertValue(sb, tables, key, val, ttl)
    if err != nil {
        return trace.Wrap(err)
    }
    return nil
}

// TouchVal updates the TTL of the key without changing the value
func (sb *SQLiteBackend) TouchVal(tables []string, key string, ttl time.Duration) error {
    var (
        values []*keyValueMeta
        err, uerr error         = nil, nil
    )
    err = upsertTables(sb, tables)
    if err != nil {
        return trace.Wrap(err)
    }
    values, err = getValuesForKey(sb, tables, key)
    if err != nil {
        perr := checkTablesExist(sb, append(tables, key))
        if perr == nil {
            return trace.BadParameter("key '%v 'is a table name", key)
        }
        // the only type of error getValuesForKey returns is NotFound.
        return trace.Wrap(err)
    }
    for _, v := range values {
        uerr = updateValue(sb, []string{v.Table}, key, v.Value, ttl)
        if uerr != nil {
            err = concatErrors(err, uerr)
        }
    }
    if err != nil {
        return trace.Wrap(err)
    }
    return nil
}

// UpsertVal updates or inserts value with a given TTL into a bucket
// ForeverTTL for no TTL
func (sb *SQLiteBackend) UpsertVal(tables []string, key string, val []byte, ttl time.Duration) error {
    err := upsertTables(sb, tables)
    if err != nil {
        return trace.Wrap(err)
    }
    err = upsertValue(sb, tables, key, val, ttl)
    if err != nil {
        return trace.Wrap(err)
    }
    return nil
}

// DeleteKey deletes a key in a bucket
func (sb *SQLiteBackend) DeleteKey(tables []string, key string) error {
    sb.Lock()
    defer sb.Unlock()

    err := checkTablesExist(sb, tables)
    if err != nil {
        return trace.Wrap(err)
    }
    _, err = getValuesForKey(sb, tables, key)
    if err != nil {
        return trace.Wrap(err)
    }
    err = deleteKeyFromTables(sb, tables, key)
    if err != nil {
        return trace.Wrap(err)
    }
    return nil
}

// DeleteBucket deletes the bucket by a given path
func (sb *SQLiteBackend) DeleteBucket(tables []string, bucket string) error {
    sb.Lock()
    defer sb.Unlock()

    err := checkTablesExist(sb, tables)
    if err != nil {
        return trace.Wrap(err)
    }
    err = deleteTables(sb, []string{bucket})
    if err != nil {
        return trace.Wrap(err)
    }
    return nil
}

// AcquireLock grabs a lock that will be released automatically in TTL
func (sb *SQLiteBackend) AcquireLock(token string, ttl time.Duration) error {
    for {
        sb.Lock()
        expires, ok := sb.locks[token]
        if ok && (expires.IsZero() || expires.After(sb.clock.UtcNow())) {
            sb.Unlock()
            sb.clock.Sleep(100 * time.Millisecond)
        } else {
            if ttl == 0 {
                sb.locks[token] = time.Time{}
            } else {
                sb.locks[token] = sb.clock.UtcNow().Add(ttl)
            }
            sb.Unlock()
            return nil
        }
    }
}

// ReleaseLock forces lock release before TTL
func (sb *SQLiteBackend) ReleaseLock(token string) error {
    sb.Lock()
    defer sb.Unlock()

    expires, ok := sb.locks[token]
    if !ok || (!expires.IsZero() && expires.Before(sb.clock.UtcNow())) {
        return trace.NotFound("lock %v is deleted or expired", token)
    }
    delete(sb.locks, token)
    return nil
}

// CompareAndSwap implements compare ans swap operation for a key
func (sb *SQLiteBackend) CompareAndSwap(tables []string, key string, val []byte, ttl time.Duration, prevVal []byte) ([]byte, error) {
    sb.Lock()
    defer sb.Unlock()

    storedVal, err := sb.GetVal(tables, key)
    if err != nil && trace.IsNotFound(err) && len(prevVal) != 0 {
        return nil, err
    }
    if len(prevVal) == 0 && err == nil {
        return nil, trace.AlreadyExists("key '%v' already exists", key)
    }
    if string(prevVal) == string(storedVal) {
        err = upsertTables(sb, tables)
        if err != nil {
            return nil, trace.Wrap(err)
        }
        err = upsertValue(sb, tables, key, val, ttl)
        if err != nil {
            return nil, trace.Wrap(err)
        }
        return storedVal, nil
    }
    return storedVal, trace.CompareFailed("expected: %v, got: %v", string(prevVal), string(storedVal))
}
