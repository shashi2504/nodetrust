package verifier

import (
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
)

// imaLog builds a binary ima-ng log from (path, content) pairs.
func imaLog(files [][2]string) []byte {
	var out []byte
	le := func(n int) []byte { return binary.LittleEndian.AppendUint32(nil, uint32(n)) }
	for _, f := range files {
		h := sha256.Sum256([]byte(f[1]))
		d := append([]byte("sha256:\x00"), h[:]...)
		n := append([]byte(f[0]), 0)
		tdata := append(append(append(le(len(d)), d...), le(len(n))...), n...)
		td := sha1.Sum(tdata)
		out = append(out, le(10)...)
		out = append(out, td[:]...)
		out = append(out, le(6)...)
		out = append(out, "ima-ng"...)
		out = append(out, le(len(tdata))...)
		out = append(out, tdata...)
	}
	return out
}
