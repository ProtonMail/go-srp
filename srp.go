//  The MIT License
//
//  Copyright (c) 2019 Proton Technologies AG
//
//  Permission is hereby granted, free of charge, to any person obtaining a copy
//  of this software and associated documentation files (the "Software"), to deal
//  in the Software without restriction, including without limitation the rights
//  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//  copies of the Software, and to permit persons to whom the Software is
//  furnished to do so, subject to the following conditions:
//
//  The above copyright notice and this permission notice shall be included in
//  all copies or substantial portions of the Software.
//
//  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
//  THE SOFTWARE.

package srp

import (
	"bytes"
	"encoding/base64"
	"errors"
	"math/big"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/clearsign"
	"github.com/ProtonMail/go-crypto/rand"
)

var (
	// ErrDataAfterModulus found extra data after decode the modulus
	ErrDataAfterModulus = errors.New("pm-srp: extra data after modulus")

	// ErrInvalidSignature invalid modulus signature
	ErrInvalidSignature = errors.New("pm-srp: invalid modulus signature")

	version    string = "undefined"
	RandReader        = rand.Reader
)

// Store random reader in a variable to be able to overwrite it in tests

// Proofs Srp Proofs object. Changed SrpProofs to Proofs because the name will be used as srp.SrpProofs by other packages and as SrpSrpProofs on mobile
// ClientProof []byte  client proof
// ClientEphemeral []byte  calculated from
// ExpectedServerProof []byte
type Proofs struct {
	ClientProof, ClientEphemeral, ExpectedServerProof, sharedSession []byte
}

// Auth stores byte data for the calculation of SRP proofs.
//  * Changed SrpAuto to Auth because the name will be used as srp.SrpAuto by other packages and as SrpSrpAuth on mobile
//  * Also the data from the API called Auth. it could be match the meaning and reduce the confusion
type Auth struct {
	Modulus, ServerEphemeral, HashedPassword []byte
}

// Amored pubkey for modulus verification
const modulusPubkey = "-----BEGIN PGP PUBLIC KEY BLOCK-----\r\n\r\nxjMEXAHLgxYJKwYBBAHaRw8BAQdAFurWXXwjTemqjD7CXjXVyKf0of7n9Ctm\r\nL8v9enkzggHNEnByb3RvbkBzcnAubW9kdWx1c8J3BBAWCgApBQJcAcuDBgsJ\r\nBwgDAgkQNQWFxOlRjyYEFQgKAgMWAgECGQECGwMCHgEAAPGRAP9sauJsW12U\r\nMnTQUZpsbJb53d0Wv55mZIIiJL2XulpWPQD/V6NglBd96lZKBmInSXX/kXat\r\nSv+y0io+LR8i2+jV+AbOOARcAcuDEgorBgEEAZdVAQUBAQdAeJHUz1c9+KfE\r\nkSIgcBRE3WuXC4oj5a2/U3oASExGDW4DAQgHwmEEGBYIABMFAlwBy4MJEDUF\r\nhcTpUY8mAhsMAAD/XQD8DxNI6E78meodQI+wLsrKLeHn32iLvUqJbVDhfWSU\r\nWO4BAMcm1u02t4VKw++ttECPt+HUgPUq5pqQWe5Q2cW4TMsE\r\n=Y4Mw\r\n-----END PGP PUBLIC KEY BLOCK-----"

// readClearSignedMessage reads the clear text from signed message and verifies
// signature. There must be no data appended after signed message in input string.
// The message must be sign by key corresponding to `modulusPubkey`.
func readClearSignedMessage(signedMessage string) (string, error) {
	modulusBlock, rest := clearsign.Decode([]byte(signedMessage))
	if len(rest) != 0 {
		return "", ErrDataAfterModulus
	}

	modulusKeyring, err := openpgp.ReadArmoredKeyRing(bytes.NewReader([]byte(modulusPubkey)))
	if err != nil {
		return "", errors.New("pm-srp: can not read modulus pubkey")
	}

	_, err = openpgp.CheckDetachedSignature(modulusKeyring, bytes.NewReader(modulusBlock.Bytes), modulusBlock.ArmoredSignature.Body, nil)
	if err != nil {
		return "", ErrInvalidSignature
	}

	return string(modulusBlock.Bytes), nil
}

func GetModulusKey() string {
	return modulusPubkey
}

// NewAuth Creates new Auth from strings input. Salt and server ephemeral are in
// base64 format. Modulus is base64 with signature attached. The signature is
// verified against server key. The version controls password hash algorithm.
//
// Parameters:
//	 - version int: The *x* component of the vector.
//	 - username string: The *y* component of the vector.
//	 - password []byte: The *z* component of the vector.
// 	 - salt string:
// Returns:
//   - auth *Auth: the pre calculated auth information
//   - err error: throw error
// Usage:
//
// Warnings:
//	 - Be careful! Poos can hurt.
func NewAuth(version int, username string, password []byte, b64salt, signedModulus, serverEphemeral string) (auth *Auth, err error) {
	data := &Auth{}

	// Modulus
	var modulus string
	modulus, err = readClearSignedMessage(signedModulus)
	if err != nil {
		return
	}
	data.Modulus, err = base64.StdEncoding.DecodeString(modulus)
	if err != nil {
		return
	}

	// Password
	var decodedSalt []byte
	if version >= 3 {
		decodedSalt, err = base64.StdEncoding.DecodeString(b64salt)
		if err != nil {
			return
		}
	}
	data.HashedPassword, err = HashPassword(version, password, username, decodedSalt, data.Modulus)
	if err != nil {
		return
	}

	// Server ephermeral
	data.ServerEphemeral, err = base64.StdEncoding.DecodeString(serverEphemeral)
	if err != nil {
		return
	}

	auth = data
	return
}

// NewAuthForVerifier Creates new Auth from strings input. Salt and server ephemeral are in
// base64 format. Modulus is base64 with signature attached. The signature is
// verified against server key. The version controls password hash algorithm.
//
// Parameters:
//	 - version int: The *x* component of the vector.
//	 - username string: The *y* component of the vector.
//	 - password []byte: The *z* component of the vector.
// 	 - salt string:
// Returns:
//   - auth *Auth: the pre calculated auth information
//   - err error: throw error
// Usage:
//
// Warnings:
//	 - none.
func NewAuthForVerifier(password []byte, signedModulus string, rawSalt []byte) (auth *Auth, err error) {
	data := &Auth{}

	// Modulus
	var modulus string
	modulus, err = readClearSignedMessage(signedModulus)
	if err != nil {
		return
	}
	data.Modulus, err = base64.StdEncoding.DecodeString(modulus)
	if err != nil {
		return
	}

	// hash version is 4
	data.HashedPassword, err = hashPasswordVersion3(password, rawSalt, data.Modulus)
	if err != nil {
		return
	}
	auth = data
	return
}

func toInt(arr []byte) *big.Int {
	var reversed = make([]byte, len(arr))
	for i := 0; i < len(arr); i++ {
		reversed[len(arr)-i-1] = arr[i]
	}
	return big.NewInt(0).SetBytes(reversed)
}

func fromInt(bitLength int, num *big.Int) []byte {
	var arr = num.Bytes()
	var reversed = make([]byte, bitLength/8)
	for i := 0; i < len(arr); i++ {
		reversed[len(arr)-i-1] = arr[i]
	}
	return reversed
}

func computeMultiplier(generator, modulus *big.Int, bitLength int) (*big.Int, error) {
	modulusMinusOne := big.NewInt(0).Sub(modulus, big.NewInt(1))
	multiplier := toInt(expandHash(append(fromInt(bitLength, generator), fromInt(bitLength, modulus)...)))
	multiplier = multiplier.Mod(multiplier, modulus)

	if multiplier.Cmp(big.NewInt(1)) <= 0 || multiplier.Cmp(modulusMinusOne) >= 0 {
		return nil, errors.New("pm-srp: SRP multiplier is out of bounds")
	}

	return multiplier, nil
}

// GenerateProofs calculates SPR proofs.
func (s *Auth) GenerateProofs(bitLength int) (res *Proofs, err error) {

	generator := big.NewInt(2)

	modulus := toInt(s.Modulus)
	serverEphemeral := toInt(s.ServerEphemeral)
	hashedPassword := toInt(s.HashedPassword)

	modulusMinusOne := big.NewInt(0).Sub(modulus, big.NewInt(1))

	if modulus.BitLen() != bitLength {
		return nil, errors.New("pm-srp: SRP modulus has incorrect size")
	}

	multiplier, err := computeMultiplier(generator, modulus, bitLength)
	if err != nil {
		return nil, err
	}

	if generator.Cmp(big.NewInt(1)) <= 0 || generator.Cmp(modulusMinusOne) >= 0 {
		return nil, errors.New("pm-srp: SRP generator is out of bounds")
	}

	if serverEphemeral.Cmp(big.NewInt(1)) <= 0 || serverEphemeral.Cmp(modulusMinusOne) >= 0 {
		return nil, errors.New("pm-srp: SRP server ephemeral is out of bounds")
	}

	// Check primality
	// Doing exponentiation here is faster than a full call to ProbablyPrime while
	// still perfectly accurate by Pocklington's theorem
	if big.NewInt(0).Exp(big.NewInt(2), modulusMinusOne, modulus).Cmp(big.NewInt(1)) != 0 {
		return nil, errors.New("pm-srp: SRP modulus is not prime")
	}

	// Check safe primality
	if !big.NewInt(0).Rsh(modulus, 1).ProbablyPrime(10) {
		return nil, errors.New("pm-srp: SRP modulus is not a safe prime")
	}

	var clientSecret, clientEphemeral, scramblingParam *big.Int
	for {
		for {
			clientSecret, err = rand.Int(RandReader, modulusMinusOne)
			if err != nil {
				return
			}

			// Prevent g^a from being smaller than the modulus
			if clientSecret.Cmp(big.NewInt(int64(bitLength*2))) > 0 {
				break
			}
		}

		clientEphemeral = big.NewInt(0).Exp(generator, clientSecret, modulus)
		scramblingParam = toInt(expandHash(append(fromInt(bitLength, clientEphemeral), fromInt(bitLength, serverEphemeral)...)))
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

	clientProof := expandHash(bytes.Join([][]byte{fromInt(bitLength, clientEphemeral), fromInt(bitLength, serverEphemeral), fromInt(bitLength, sharedSession)}, []byte{}))
	serverProof := expandHash(bytes.Join([][]byte{fromInt(bitLength, clientEphemeral), clientProof, fromInt(bitLength, sharedSession)}, []byte{}))

	return &Proofs{
		ClientEphemeral: fromInt(bitLength, clientEphemeral),
		ClientProof: clientProof,
		ExpectedServerProof: serverProof,
		sharedSession: fromInt(bitLength, sharedSession),
	}, nil
}

// GenerateVerifier verifier for update pwds and create accounts
func (s *Auth) GenerateVerifier(bitLength int) ([]byte, error) {
	modulus := toInt(s.Modulus)
	generator := big.NewInt(2)

	hashedPassword := toInt(s.HashedPassword)
	calModPow := big.NewInt(0).Exp(generator, hashedPassword, modulus)
	return fromInt(bitLength, calModPow), nil
}

func RandomBits(bits int) ([]byte, error) {
	return RandomBytes(bits / 8)
}

func RandomBytes(byes int) (raw []byte, err error) {
	raw = make([]byte, byes)
	_, err = rand.Read(raw)
	return
}
