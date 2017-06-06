package defaults

const (
    // Default Host Name
    CoreHostName string = "pc-master"

    // Default DB to use for persisting state. Another options is "etcd"
    CoreBackendType = "sqlite"

    // Name of events bolt database file stored in DataDir
    CoreEventsSqliteFile = "events.db"

    // Name of keys bolt database file stored in DataDir
    CoreKeysSqliteFile = "keys.db"

    // Name of records bolt database file stored in DataDir
    CoreRecordsSqliteFile = "records.db"
)
