package ping

import "bytes"

type Serializer interface {
	Serialize() *bytes.Buffer
}
