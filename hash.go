package srp

import (
	"bytes"
	"crypto/md5"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"

	"github.com/jameskeane/bcrypt"
)

// FIXME: These leak information by using non constant-time encoding

// BCryptHash function pass the password and salt in
func BCryptHash(password string, salt string) (string, error) {
	return bcrypt.Hash(password, salt)
}

// ExpandHash expand hash for srp flow
func ExpandHash(data []byte) []byte {
	part0 := sha512.Sum512(append(data, 0))
	part1 := sha512.Sum512(append(data, 1))
	part2 := sha512.Sum512(append(data, 2))
	part3 := sha512.Sum512(append(data, 3))
	return bytes.Join([][]byte{
		part0[:],
		part1[:],
		part2[:],
		part3[:],
	}, []byte{})
}

func HashPassword(authVersion int, password, userName string, salt, modulus []byte) ([]byte, error) {
	switch authVersion {
	case 4, 3:
		return hashPasswordVersion3(password, salt, modulus)
	case 2:
		return hashPasswordVersion2(password, userName, modulus)
	case 1:
		return hashPasswordVersion1(password, userName, modulus)
	case 0:
		return hashPasswordVersion0(password, userName, modulus)
	default:
		return nil, errors.New("pmapi: unsupported auth version")
	}
}

func cleanUserName(userName string) string {
	userName = strings.Replace(userName, "-", "", -1)
	userName = strings.Replace(userName, ".", "", -1)
	userName = strings.Replace(userName, "_", "", -1)
	return strings.ToLower(userName)
}

func hashPasswordVersion3(password string, salt, modulus []byte) (res []byte, err error) {
	encodedSalt := base64.NewEncoding("./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789").WithPadding(base64.NoPadding).EncodeToString(append(salt, []byte("proton")...))
	crypted, err := bcrypt.Hash(password, "$2y$10$"+encodedSalt)
	if err != nil {
		return
	}

	return ExpandHash(append([]byte(crypted), modulus...)), nil
}

func hashPasswordVersion2(password, userName string, modulus []byte) (res []byte, err error) {
	return hashPasswordVersion1(password, cleanUserName(userName), modulus)
}

func hashPasswordVersion1(password, userName string, modulus []byte) (res []byte, err error) {
	prehashed := md5.Sum([]byte(strings.ToLower(userName)))
	encodedSalt := hex.EncodeToString(prehashed[:])
	crypted, err := bcrypt.Hash(password, "$2y$10$"+encodedSalt)
	if err != nil {
		return
	}

	return ExpandHash(append([]byte(crypted), modulus...)), nil
}

func hashPasswordVersion0(password, userName string, modulus []byte) (res []byte, err error) {
	prehashed := sha512.Sum512([]byte(password))
	return hashPasswordVersion1(base64.StdEncoding.EncodeToString(prehashed[:]), userName, modulus)
}
