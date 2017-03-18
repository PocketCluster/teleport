package sqlitebk

import (
    "database/sql"
    "fmt"
    "os"
    "path/filepath"
    "sort"
    "sync"
    "time"

    "github.com/gravitational/trace"
    "github.com/mailgun/timetools"
)

type SQLiteBackend struct {
    sync.Mutex

    onExitCloseDB bool
    db            *sql.DB
    clock         timetools.TimeProvider
    locks         map[string]time.Time
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

func NewBackendFromDB(db *sql.DB, opts ...Option) (*SQLiteBackend, error) {
    if db == nil {
        return nil, trace.Wrap(fmt.Errorf("Invalid, null database"))
    }
    b := &SQLiteBackend {
        onExitCloseDB: false,
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
    b.db = db
    return b, nil
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
        onExitCloseDB: true,
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
    if sb.onExitCloseDB {
        return sb.db.Close()
    }
    return nil
}

// GetKeys returns a list of keys for a given path
func (sb *SQLiteBackend) GetKeys(bucket []string) ([]string, error) {
    var (
        table string            = fullTableName(bucket[0])
        path string             = fullBucketPath(bucket)
        keys []string           = nil
        err error               = nil
    )
    err = checkTablesExist(sb, table)
    if err != nil {
        if trace.IsNotFound(err) {
            return nil, nil
        }
        return nil, trace.Wrap(err)
    }
    err = checkBucketPathExist(sb, table, bucket)
    if err != nil {
        if trace.IsNotFound(err) {
            return nil, nil
        }
        return nil, trace.Wrap(err)
    }
    keys, err = getAllKeysFromTable(sb, table, path)
    if err != nil {
        return nil, trace.Wrap(err)
    }
    // now do an iteration to expire keys
    for _, key := range keys {
        sb.GetVal(bucket, key)
    }
    keys, err = getAllKeysFromTable(sb, table, path)
    if err != nil {
        return nil, trace.Wrap(err)
    }
    sort.Sort(sort.StringSlice(keys))
    return keys, nil
}

// GetVal return a value for a given key in the bucket
func (sb *SQLiteBackend) GetVal(bucket []string, key string) ([]byte, error) {
    var (
        pruned int              = 0
        err, derr error         = nil, nil
        table string            = fullTableName(bucket[0])
        path string             = fullBucketPath(bucket)
        values []*keyValueMeta  = nil
        last []byte             = nil
    )
    err = checkTablesExist(sb, table)
    if err != nil {
        return nil, trace.Wrap(err)
    }
    err = checkBucketPathExist(sb, table, bucket)
    if err != nil {
        return nil, trace.Wrap(err)
    }
    values, err = getValuesForKey(sb, table, path, key)
    if err != nil {
        perr := checkBucketPathExist(sb, table, append(bucket, key))
        if perr == nil {
            return nil, trace.BadParameter("key '%v 'is a bucket name", key)
        }
        // the only type of error getValuesForKey returns is NotFound.
        return nil, trace.Wrap(err)
    }

    // remove old value
    for _, v := range values {
        if v.TTL != 0 && sb.clock.UtcNow().Sub(v.Created) > v.TTL {
            pruned++
            derr = deleteKeyFromTable(sb, v.Table, v.Path, key)
            if derr != nil {
                err = concatErrors(err, derr)
            }
        } else {
            // this will pick up the last valid element
            last = v.Value
        }
    }
    if pruned != 0 && pruned == len(values) {
        return nil, trace.NotFound("Values for key %v not found in bucket %v | pruned %v", key, bucket, pruned)
    }
    if err != nil {
        return nil, err
    }
    return last, nil
}

// GetValAndTTL returns value and TTL for a key in bucket
func (sb *SQLiteBackend) GetValAndTTL(bucket []string, key string) ([]byte, time.Duration, error) {
    var (
        pruned int              = 0
        err, derr error         = nil, nil
        newTTL time.Duration    = 0
        table string            = fullTableName(bucket[0])
        path string             = fullBucketPath(bucket)
        values []*keyValueMeta
        last *keyValueMeta
    )
    err = checkTablesExist(sb, table)
    if err != nil {
        return nil, 0, trace.Wrap(err)
    }
    err = checkBucketPathExist(sb, table, bucket)
    if err != nil {
        return nil, 0, trace.Wrap(err)
    }
    values, err = getValuesForKey(sb, table, path, key)
    if err != nil {
        perr := checkBucketPathExist(sb, table, append(bucket, key))
        if perr == nil {
            return nil, 0, trace.BadParameter("key '%v 'is a bucket name", key)
        }
        return nil, 0, trace.Wrap(err)
    }

    // remove old value
    for _, v := range values {
        if v.TTL != 0 && sb.clock.UtcNow().Sub(v.Created) > v.TTL {
            pruned++
            derr = deleteKeyFromTable(sb, v.Table, v.Path, key)
            if derr != nil {
                err = concatErrors(err, derr)
            }
        } else {
            // this will pick up the last valid element
            last = v
        }
    }
    if pruned == len(values) {
        return nil, 0, trace.NotFound("%v: %v not found", bucket, key)
    }
    if err != nil {
        return nil, 0, trace.Wrap(err)
    }
    if last.TTL != 0 {
        newTTL = last.Created.Add(last.TTL).Sub(sb.clock.UtcNow())
    }
    return last.Value, newTTL, nil
}

// CreateVal creates value with a given TTL and key in the bucket
// if the value already exists, returns AlreadyExistsError
func (sb *SQLiteBackend) CreateVal(bucket []string, key string, val []byte, ttl time.Duration) error {
    var (
        table string            = fullTableName(bucket[0])
        path string             = fullBucketPath(bucket)
        values []*keyValueMeta  = nil
        err error               = nil
    )
    err = upsertTable(sb, table)
    if err != nil {
        return trace.Wrap(err)
    }
    err = upsertBucketPath(sb, table, bucket)
    if err != nil {
        return trace.Wrap(err)
    }
    values, err = getValuesForKey(sb, table, path, key)
    if values != nil {
        return trace.AlreadyExists("'%v' already exists", key)
    }
    err = upsertValue(sb, table, path, key, val, ttl)
    if err != nil {
        return trace.Wrap(err)
    }
    return nil
}

// TouchVal updates the TTL of the key without changing the value
func (sb *SQLiteBackend) TouchVal(bucket []string, key string, ttl time.Duration) error {
    var (
        table string            = fullTableName(bucket[0])
        path string             = fullBucketPath(bucket)
        values []*keyValueMeta  = nil
        err, uerr error         = nil, nil
    )
    err = upsertTable(sb, table)
    if err != nil {
        return trace.Wrap(err)
    }
    err = upsertBucketPath(sb, table, bucket)
    if err != nil {
        return trace.Wrap(err)
    }
    values, err = getValuesForKey(sb, table, path, key)
    if err != nil {
        // the only type of error getValuesForKey returns is NotFound.
        return trace.Wrap(err)
    }
    for _, v := range values {
        uerr = updateValue(sb, v.Table, v.Path, key, v.Value, ttl)
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
func (sb *SQLiteBackend) UpsertVal(bucket []string, key string, val []byte, ttl time.Duration) error {
    var (
        table string            = fullTableName(bucket[0])
        path string             = fullBucketPath(bucket)
        err error               = nil
    )
    err = upsertTable(sb, table)
    if err != nil {
        return trace.Wrap(err)
    }
    err = upsertBucketPath(sb, table, bucket)
    if err != nil {
        return trace.Wrap(err)
    }
    err = upsertValue(sb, table, path, key, val, ttl)
    if err != nil {
        return trace.Wrap(err)
    }
    return nil
}

// DeleteKey deletes a key in a bucket
func (sb *SQLiteBackend) DeleteKey(bucket []string, key string) error {
    sb.Lock()
    defer sb.Unlock()
    var (
        table string            = fullTableName(bucket[0])
        path string             = fullBucketPath(bucket)
        err error               = nil
    )
    err = checkTablesExist(sb, table)
    if err != nil {
        return trace.Wrap(err)
    }
    err = checkBucketPathExist(sb, table, bucket)
    if err != nil {
        return trace.Wrap(err)
    }
    _, err = getValuesForKey(sb, table, path, key)
    if err != nil {
        return trace.Wrap(err)
    }
    err = deleteKeyFromTable(sb, table, path, key)
    if err != nil {
        return trace.Wrap(err)
    }
    return nil
}

// DeleteBucket deletes the bucket by a given path
func (sb *SQLiteBackend) DeleteBucket(bucket []string, bkt string) error {
    sb.Lock()
    defer sb.Unlock()
    var (
        table string            = fullTableName(bucket[0])
        path string             = fullBucketPath(append(bucket, bkt))
        err error               = nil
    )
    err = checkTablesExist(sb, table)
    if err != nil {
        return trace.Wrap(err)
    }
    err = checkBucketPathExist(sb, table, bucket)
    if err != nil {
        return trace.Wrap(err)
    }
    err = deleteBucketPathFromTable(sb, table, path)
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
func (sb *SQLiteBackend) CompareAndSwap(bucket []string, key string, val []byte, ttl time.Duration, prevVal []byte) ([]byte, error) {
    sb.Lock()
    defer sb.Unlock()
    var (
        table string            = fullTableName(bucket[0])
        path string             = fullBucketPath(bucket)
        err error               = nil
    )
    storedVal, err := sb.GetVal(bucket, key)
    if err != nil && trace.IsNotFound(err) && len(prevVal) != 0 {
        return nil, err
    }
    if len(prevVal) == 0 && err == nil {
        return nil, trace.AlreadyExists("key '%v' already exists", key)
    }
    if string(prevVal) == string(storedVal) {
        err = upsertTable(sb, table)
        if err != nil {
            return nil, trace.Wrap(err)
        }
        err = upsertBucketPath(sb, table, bucket)
        if err != nil {
            return nil, trace.Wrap(err)
        }
        err = upsertValue(sb, table, path, key, val, ttl)
        if err != nil {
            return nil, trace.Wrap(err)
        }
        return storedVal, nil
    }
    return storedVal, trace.CompareFailed("expected: %v, got: %v", string(prevVal), string(storedVal))
}
