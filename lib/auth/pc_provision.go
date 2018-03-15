package auth

type UserIdentity struct {
    LoginName    string
    UID          string
    GID          string
}

// notifies user information incl. user login, uid, gid
type UserIdentityKiosk interface {
    // in order of user login, uid, gid, error
    GetUserIdentity(hostName, hostUUID string) (*UserIdentity, error)
}