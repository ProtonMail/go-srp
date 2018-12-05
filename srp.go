package srp

import (
	"bytes"
	"crypto/rand"
	"crypto/sha512"
	"errors"
	"math/big"

	"github.com/jameskeane/bcrypt"
	"golang.org/x/crypto/openpgp/clearsign"
)

// ReadClearSignedMessage read clear text from signed message which called Modulus from api response
func ReadClearSignedMessage(signedMessage string) (string, error) {
	modulusBlock, rest := clearsign.Decode([]byte(signedMessage))
	if len(rest) != 0 {
		return "", errors.New("mobile: extra data after modulus")
	}
	return string(modulusBlock.Bytes), nil
}

// BCrypt hash function pass the password and salt in
func BCrypt(password string, salt string) (string, error) {
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

// Store random reader in a variable to be able to overwrite it in tests
var randReader = rand.Reader

// SrpProofs object
type SrpProofs struct {
	ClientProof, ClientEphemeral, ExpectedServerProof []byte
}

// GenerateSrpProofs generate auth proofs
func GenerateSrpProofs(length int, modulusArr []byte, serverEphemeralArr []byte, hashedPasswordArr []byte) (res *SrpProofs, err error) {
	toInt := func(arr []byte) *big.Int {
		var reversed = make([]byte, len(arr))
		for i := 0; i < len(arr); i++ {
			reversed[len(arr)-i-1] = arr[i]
		}
		return big.NewInt(0).SetBytes(reversed)
	}

	fromInt := func(num *big.Int) []byte {
		var arr = num.Bytes()
		var reversed = make([]byte, length/8)
		for i := 0; i < len(arr); i++ {
			reversed[len(arr)-i-1] = arr[i]
		}
		return reversed
	}

	generator := big.NewInt(2)
	multiplier := toInt(ExpandHash(append(fromInt(generator), modulusArr...)))

	modulus := toInt(modulusArr)
	serverEphemeral := toInt(serverEphemeralArr)
	hashedPassword := toInt(hashedPasswordArr)

	modulusMinusOne := big.NewInt(0).Sub(modulus, big.NewInt(1))

	if modulus.BitLen() != length {
		return nil, errors.New("mobile: SRP modulus has incorrect size")
	}

	multiplier = multiplier.Mod(multiplier, modulus)

	if multiplier.Cmp(big.NewInt(1)) <= 0 || multiplier.Cmp(modulusMinusOne) >= 0 {
		return nil, errors.New("mobile: SRP multiplier is out of bounds")
	}

	if generator.Cmp(big.NewInt(1)) <= 0 || generator.Cmp(modulusMinusOne) >= 0 {
		return nil, errors.New("mobile: SRP generator is out of bounds")
	}

	if serverEphemeral.Cmp(big.NewInt(1)) <= 0 || serverEphemeral.Cmp(modulusMinusOne) >= 0 {
		return nil, errors.New("mobile: SRP server ephemeral is out of bounds")
	}

	// Check primality
	// Doing exponentiation here is faster than a full call to ProbablyPrime while
	// still perfectly accurate by Pocklington's theorem
	if big.NewInt(0).Exp(big.NewInt(2), modulusMinusOne, modulus).Cmp(big.NewInt(1)) != 0 {
		return nil, errors.New("mobile: SRP modulus is not prime")
	}

	// Check safe primality
	if !big.NewInt(0).Rsh(modulus, 1).ProbablyPrime(10) {
		return nil, errors.New("mobile: SRP modulus is not a safe prime")
	}

	var clientSecret, clientEphemeral, scramblingParam *big.Int
	for {
		for {
			clientSecret, err = rand.Int(randReader, modulusMinusOne)
			if err != nil {
				return
			}

			if clientSecret.Cmp(big.NewInt(int64(length*2))) > 0 { // Very likely
				break
			}
		}

		clientEphemeral = big.NewInt(0).Exp(generator, clientSecret, modulus)
		scramblingParam = toInt(ExpandHash(append(fromInt(clientEphemeral), fromInt(serverEphemeral)...)))
		if scramblingParam.Cmp(big.NewInt(0)) != 0 { // Very likely
			break
		}
	}

	subtracted := big.NewInt(0).Sub(serverEphemeral, big.NewInt(0).Mod(big.NewInt(0).Mul(big.NewInt(0).Exp(generator, hashedPassword, modulus), multiplier), modulus))
	if subtracted.Cmp(big.NewInt(0)) < 0 {
		subtracted.Add(subtracted, modulus)
	}
	exponent := big.NewInt(0).Mod(big.NewInt(0).Add(big.NewInt(0).Mul(scramblingParam, hashedPassword), clientSecret), modulusMinusOne)
	sharedSession := big.NewInt(0).Exp(subtracted, exponent, modulus)

	clientProof := ExpandHash(bytes.Join([][]byte{fromInt(clientEphemeral), fromInt(serverEphemeral), fromInt(sharedSession)}, []byte{}))
	serverProof := ExpandHash(bytes.Join([][]byte{fromInt(clientEphemeral), clientProof, fromInt(sharedSession)}, []byte{}))

	return &SrpProofs{ClientEphemeral: fromInt(clientEphemeral), ClientProof: clientProof, ExpectedServerProof: serverProof}, nil
}

// GenerateVerifier verifier for update pwds and create accounts
func GenerateVerifier(length int, modulus []byte, hashedPassword []byte) ([]byte, error) {
	return nil, errors.New("mobile: the client doesn't need SRP GenerateVerifier")
}
