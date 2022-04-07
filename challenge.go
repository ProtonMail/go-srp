package srp

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/curve25519"
)

const ecdlpPRFKeySize = 32

func ECDLPChallenge(b64Challenge string) (b64Solution string, err error) {
	challenge, err := base64.StdEncoding.DecodeString(b64Challenge)
	if err != nil {
		return "", err
	}

	if len(challenge) != 2 * ecdlpPRFKeySize + sha256.Size {
		return "", errors.New("srp: invalid ECDLP challenge length")
	}

	var i uint64
	var point []byte
	buffer := make([]byte, 8)

	for i = 0;; i++ {
		prePRF := hmac.New(sha256.New, challenge[:ecdlpPRFKeySize])
		binary.LittleEndian.PutUint64(buffer, i)
		_, _ = prePRF.Write(buffer)
		point, err = curve25519.X25519(prePRF.Sum(nil), curve25519.Basepoint)
		if err != nil {
			return "", err
		}
		postPRF := hmac.New(sha256.New, challenge[ecdlpPRFKeySize:2*ecdlpPRFKeySize])
		_, _ = postPRF.Write(point)

		if bytes.Equal(postPRF.Sum(nil), challenge[2*ecdlpPRFKeySize:]) {
			break
		}
	}
	solution := []byte{}
	solution = append(solution, buffer...)
	solution = append(solution, point...)

	return base64.StdEncoding.EncodeToString(solution), nil
}

const argon2PRFKeySize = 32

func Argon2PreimageChallenge(b64Challenge string) (b64Solution string, err error) {
	challenge, err := base64.StdEncoding.DecodeString(b64Challenge)
	if err != nil {
		return "", err
	}

	// Argon2 challenges consist of 3 PRF keys, the hash output, and 4 32-bit argon2 parameters
	if len(challenge) !=  3 * argon2PRFKeySize + sha256.Size + 4 * 4 {
		return "", errors.New("srp: invalid Argon2 preimage challenge length")
	}
	prfKeys := challenge[:3*argon2PRFKeySize]
	goal := challenge[3*argon2PRFKeySize:][:sha256.Size]
	argon2Params := challenge[3*argon2PRFKeySize + sha256.Size:]

	threads          := binary.LittleEndian.Uint32(argon2Params[0:])
	argon2OutputSize := binary.LittleEndian.Uint32(argon2Params[4:])
	memoryCost       := binary.LittleEndian.Uint32(argon2Params[8:])
	timeCost         := binary.LittleEndian.Uint32(argon2Params[12:])

	var i uint64
	var stage2 []byte
	buffer := make([]byte, 8)

	for i = 0;; i++ {
		prePRF := hmac.New(sha256.New, prfKeys[:argon2PRFKeySize])
		binary.LittleEndian.PutUint64(buffer, i)
		_, _ = prePRF.Write(buffer)
		stage2 = argon2.IDKey(prePRF.Sum(nil), prfKeys[argon2PRFKeySize:2*argon2PRFKeySize], timeCost, memoryCost, uint8(threads), argon2OutputSize)
		postPRF := hmac.New(sha256.New, prfKeys[2*argon2PRFKeySize:])
		_, _ = postPRF.Write(stage2)

		if bytes.Equal(postPRF.Sum(nil), goal) {
			break
		}
	}
	solution := []byte{}
	solution = append(solution, buffer...)
	solution = append(solution, stage2...)

	return base64.StdEncoding.EncodeToString(solution), nil
}
