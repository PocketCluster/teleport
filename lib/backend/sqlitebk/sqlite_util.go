package sqlitebk

import (
    "database/sql"
    "fmt"
    "strings"
    "time"

    _ "github.com/mattn/go-sqlite3"
    "github.com/gravitational/trace"
)

// (03/15/2017)
// These prefix and splitter is selected based on assuptions that
//   1) a final combination would not be disassembled
//   2) it would remain only to be utilized for querying purpose.
// *** Use output products for query only. ***
const (
    pcTablePrefix       = "pcssh_"
    pcPathSplitter      = "/"
    pcPKSplitter        = "_"
)

var (
    bucketTime      = time.Date(1987, 04, 23, 13, 0, 0, 0, time.UTC)
)

//region Helper Structure & Functions
type keyValueMeta struct {
    Table      string
    Created    time.Time
    TTL        time.Duration
    Path       string
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

func fullTableName(root string) string {
    return pcTablePrefix + root
}

func fullBucketPath(bucketPath []string) string {
    return strings.Join(bucketPath, pcPathSplitter)
}

func fullPrimaryKey(path, key string) string {
    return path + pcPKSplitter + key
}
// check if every table in the list exits
func checkTablesExist(sb *SQLiteBackend, table string) error {
    var (
        counter int       = 0
        stmt *sql.Stmt    = nil
        err error         = nil
    )
    stmt, err = sb.db.Prepare(fmt.Sprintf("SELECT count(name) FROM sqlite_master WHERE type = 'table' AND name = '%s'", table))
    if err != nil {
        return err
    }
    err = stmt.QueryRow().Scan(&counter);
    err = concatErrors(err, stmt.Close())
    // this is a special error that needs to be treated differently
    if counter == 0 {
        return trace.NotFound("table %v not found", table)
    }
    return err
}

func checkBucketPathExist(sb *SQLiteBackend, table string, bucketPath []string) error {
    var (
        counter, pathLen int    = 0, len(bucketPath)
        created time.Time       = bucketTime
        key, path, pathKey string = "", "", ""
        err error               = nil
        stmt *sql.Stmt          = nil
    )
    if pathLen == 0 {
        return fmt.Errorf("Unable to query empty buckets")
    }
    switch pathLen {
        case 0: {
            return fmt.Errorf("Unable to query empty buckets")
        }
        case 1: {
            // when bucket length is equal to 1, we should not check path as table name already covers it
            return nil
        }
    }
    key = bucketPath[pathLen - 1]
    path = fullBucketPath(bucketPath[:(pathLen - 1)])
    pathKey = fullPrimaryKey(path, key)
    stmt, err = sb.db.Prepare(fmt.Sprintf("SELECT count(path) FROM %s WHERE created = ? AND ttl = 0 AND pathkey = ?", table))
    if err != nil {
        return err
    }
    err = stmt.QueryRow(created, pathKey).Scan(&counter);
    err = concatErrors(err, stmt.Close())
    // this is a special error that needs to be treated differently
    if counter == 0 {
        return trace.NotFound("Invalid path %v at table %v", path, table)
    }
    return err
}

// this only cares if value for key exists in tables. The only error this returns is `NotFound`
// We don't care wheter this query comes up with error or not. We only cares if it returns value
func getValuesForKey(sb *SQLiteBackend, table, path, key string) ([]*keyValueMeta, error) {
    var (
        created time.Time
        ttl     time.Duration
        pathKey string          = fullPrimaryKey(path, key)
        out     []*keyValueMeta = []*keyValueMeta{}
        stmt    *sql.Stmt       = nil
        rows    *sql.Rows       = nil
        value   []byte          = nil
        err     error           = nil
    )
    stmt, err = sb.db.Prepare(fmt.Sprintf("SELECT created, ttl, value FROM %s WHERE pathkey = '%s'", table, pathKey))
    if err != nil {
        return nil, err
    }
    rows, err = stmt.Query();
    if err != nil {
        return nil, concatErrors(err, stmt.Close())
    }
    for rows.Next() {
        value = nil
        err = rows.Scan(&created, &ttl, &value)
        if err != nil {
            break
        }
        if value != nil && len(value) != 0 {
            out = append(out,
                &keyValueMeta{
                    Table:      table,
                    Created:    created,
                    TTL:        ttl,
                    Path:       path,
                    Key:        key,
                    Value:      value,
                })
        }
    }
    err = concatErrors(err, rows.Err())
    err = concatErrors(err, rows.Close())
    err = concatErrors(err, stmt.Close())
    if len(out) == 0 {
        return nil, trace.NotFound("Value for key %v and path %v not found in %v", key, path, table)
    }
    return out, nil
}

func getAllKeysFromTable(sb *SQLiteBackend, table, path string) ([]string, error) {
    var (
        key string          = ""
        out []string        = []string{}
        stmt *sql.Stmt      = nil
        rows *sql.Rows      = nil
        err error           = nil
    )
    stmt, err = sb.db.Prepare(fmt.Sprintf("SELECT key FROM %s WHERE path = '%s'", table, path))
    if err != nil {
        return nil, err
    }
    rows, err = stmt.Query();
    if err != nil {
        return nil, concatErrors(err, stmt.Close())
    }
    for rows.Next() {
        key = ""
        err = rows.Scan(&key)
        if err != nil {
            break
        }
        if len(key) != 0 {
            out = append(out, key)
        }
    }
    err = concatErrors(err, rows.Err())
    err = concatErrors(err, rows.Close())
    err = concatErrors(err, stmt.Close())
    if len(out) == 0 {
        return nil, trace.NotFound("keys not found for path %v in %v", path, table)
    }
    return out, err
}

func upsertTable(sb *SQLiteBackend, table string) error {
    var (
        stmt *sql.Stmt      = nil
        trans *sql.Tx       = nil
        err error           = nil
    )
    trans, err = sb.db.Begin()
    if err != nil {
        return err
    }
    stmt, err = trans.Prepare(fmt.Sprintf("CREATE TABLE IF NOT EXISTS %s (created DATETIME, ttl BIGINT, pathkey TEXT NOT NULL PRIMARY KEY, path TEXT NOT NULL, key TEXT NOT NULL, value BLOB)", table))
    if err == nil {
        _, err = stmt.Exec()
        err = concatErrors(err, stmt.Close())
    }
    if err == nil {
        err = trans.Commit()
    } else {
        err = concatErrors(err, trans.Rollback())
    }
    return err
}

// func (b *BoltBackend) upsertVal(path []string, key string, val []byte, ttl time.Duration) error
func upsertBucketPath(sb *SQLiteBackend, table string, bucketPath []string) error {
    var (
        created time.Time   = bucketTime
        pathLen int         = len(bucketPath)
        key, path, pathKey string = "", "", ""
        idx int             = 1
        stmt *sql.Stmt      = nil
        trans *sql.Tx       = nil
        err error           = nil
    )
    switch pathLen {
        case 0: {
            return fmt.Errorf("Unable to create empty bucket")
        }
        case 1: {
            // when bucket length is equal to 1, we should not create path as table name already covers it
            return nil
        }
    }
    trans, err = sb.db.Begin()
    if err != nil {
        return err
    }
    stmt, err = trans.Prepare(fmt.Sprintf("INSERT OR REPLACE INTO %s (created, ttl, pathkey, path, key) values (?, 0, ?, ?, ?)", table))
    if err == nil {
        for idx = 1; idx < pathLen; idx++ {
            key = bucketPath[idx]
            path = fullBucketPath(bucketPath[:idx])
            pathKey = fullPrimaryKey(path, key)
            _, err = stmt.Exec(created, pathKey, path, key)
            if err != nil {
                break
            }
        }
        err = concatErrors(err, stmt.Close())
    }
    if err == nil {
        err = trans.Commit()
    } else {
        err = concatErrors(err, trans.Rollback())
    }
    return err
}

// func (b *BoltBackend) upsertVal(path []string, key string, val []byte, ttl time.Duration) error
func upsertValue(sb *SQLiteBackend, table, path, key string, val []byte, ttl time.Duration) error {
    var (
        pathKey string      = fullPrimaryKey(path, key)
        created time.Time   = sb.clock.UtcNow()
        stmt *sql.Stmt      = nil
        trans *sql.Tx       = nil
        err error           = nil
    )
    trans, err = sb.db.Begin()
    if err != nil {
        return err
    }
    stmt, err = trans.Prepare(fmt.Sprintf("INSERT OR REPLACE INTO %s (created, ttl, pathkey, path, key, value) values (?, ?, ?, ?, ?, ?)", table))
    if err == nil {
        _, err = stmt.Exec(created, ttl, pathKey, path, key, val)
        err = concatErrors(err, stmt.Close())
    }
    if err == nil {
        err = trans.Commit()
    } else {
        err = concatErrors(err, trans.Rollback())
    }
    return err
}

func updateValue(sb *SQLiteBackend, table, path, key string, val []byte, ttl time.Duration) error {
    var (
        pathKey string      = fullPrimaryKey(path, key)
        created time.Time   = sb.clock.UtcNow()
        stmt *sql.Stmt      = nil
        trans *sql.Tx       = nil
        err error           = nil
    )
    trans, err = sb.db.Begin()
    if err != nil {
        return err
    }
    stmt, err = trans.Prepare(fmt.Sprintf("UPDATE OR IGNORE %s SET created = ?, ttl = ?, value = ? WHERE pathkey = ?", table))
    if err == nil {
        _, err = stmt.Exec(created, ttl, val, pathKey)
        err = concatErrors(err, stmt.Close())
    }
    if err == nil {
        err = trans.Commit()
    } else {
        err = concatErrors(err, trans.Rollback())
    }
    return err
}

func deleteKeyFromTable(sb *SQLiteBackend, table, path, key string) error {
    var (
        pathKey string      = fullPrimaryKey(path, key)
        stmt *sql.Stmt      = nil
        trans *sql.Tx       = nil
        err error           = nil
    )
    trans, err = sb.db.Begin()
    if err != nil {
        return err
    }
    stmt, err = trans.Prepare(fmt.Sprintf("DELETE FROM %s WHERE pathkey = '%s'", table, pathKey))
    if err == nil {
        _, err = stmt.Exec()
        err = concatErrors(err, stmt.Close())
    }
    if err == nil {
        err = trans.Commit()
    } else {
        err = concatErrors(err, trans.Rollback())
    }
    return err
}

func deleteBucketPathFromTable(sb *SQLiteBackend, table, path string) error {
    var (
        stmt *sql.Stmt      = nil
        trans *sql.Tx       = nil
        err error           = nil
    )
    trans, err = sb.db.Begin()
    if err != nil {
        return err
    }
    stmt, err = trans.Prepare(fmt.Sprintf("DELETE FROM %s WHERE path = '%s'", table, path))
    if err == nil {
        _, err = stmt.Exec()
        err = concatErrors(err, stmt.Close())
    }
    if err == nil {
        err = trans.Commit()
    } else {
        err = concatErrors(err, trans.Rollback())
    }
    return err
}

func deleteTable(sb *SQLiteBackend, table string) error {
    var (
        stmt *sql.Stmt      = nil
        trans *sql.Tx       = nil
        err error           = nil
    )
    trans, err = sb.db.Begin()
    if err != nil {
        return err
    }
    stmt, err = trans.Prepare(fmt.Sprintf("DROP TABLE %s", table))
    if err == nil {
        _, err = stmt.Exec()
        err = concatErrors(err, stmt.Close())
    }
    if err == nil {
        err = trans.Commit()
    } else {
        err = concatErrors(err, trans.Rollback())
    }
    return err
}

