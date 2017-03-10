package sqlitebk

import (
    "encoding/json"

    "github.com/gravitational/teleport/lib/backend"
    "github.com/gravitational/teleport/lib/utils"
    "github.com/gravitational/trace"
)

// cfg represents JSON config for bolt backlend
type cfg struct {
    Path string `json:"path"`
}

// FromString initialized the backend from backend-specific string
func FromObject(in interface{}) (backend.Backend, error) {
    if in == nil {
        return nil, trace.Errorf(
            `please supply a valid dictionary, e.g. {"path": "/opt/bolt.db"}`)
    }
    var c *cfg
    if err := utils.ObjectToStruct(in, &c); err != nil {
        return nil, trace.Wrap(err)
    }
    return New(c.Path)
}

func FromJSON(paramsJSON string) (backend.Backend, error) {
    c := cfg{}
    err := json.Unmarshal([]byte(paramsJSON), &c)
    if err != nil {
        return nil, trace.Wrap(err)
    }
    return New(c.Path)
}
