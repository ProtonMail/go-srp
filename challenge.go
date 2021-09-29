package srp

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"

	"golang.org/x/crypto/curve25519"
)

const ECDLPEphemeralSize = 24

func ECDLPChallenge(b64Challenge string) (solution int64, err error) {
	if len(b64Challenge) != 76 { // 56 bytes in base64
		return 0, errors.New("srp:invalid ECDLP challenge length")
	}

	challenge, err := base64.StdEncoding.DecodeString(b64Challenge)
	if err != nil {
		return 0, err
	}

	var i uint64
	buffer := make([]byte, 8)
	point := make([]byte, curve25519.PointSize)

	for i = 0; bytes.Compare(point, challenge[ECDLPEphemeralSize:]) != 0; i++ {
		hash := sha256.New()
		binary.LittleEndian.PutUint64(buffer, i)
		_, _ = hash.Write(buffer) // hash writer interface never returns errors
		_, _ = hash.Write(challenge[:ECDLPEphemeralSize])

		point, err = curve25519.X25519(hash.Sum(nil), curve25519.Basepoint)
		if err != nil {
			return 0, err
		}
	}

	// Last iteration increments i by 1 too much
	// We cast to int64 for gomobile, possible because the challenges don't go above 2^63
	return int64(i - 1), nil
}
