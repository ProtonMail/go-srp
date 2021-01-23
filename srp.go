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
	"github.com/coyim/constbn"
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
	ClientProof, ClientEphemeral, ExpectedServerProof []byte
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
//	 - password string: The *z* component of the vector.
// 	 - salt string:
// Returns:
//   - auth *Auth: the pre caculated auth information
//   - err error: throw error
// Usage:
//
// Warnings:
//	 - Be carefull! Poos can hurt.
func NewAuth(version int, username, password, salt, signedModulus, serverEphemeral string) (auth *Auth, err error) {
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
		decodedSalt, err = base64.StdEncoding.DecodeString(salt)
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
//	 - password string: The *z* component of the vector.
// 	 - salt string:
// Returns:
//   - auth *Auth: the pre caculated auth information
//   - err error: throw error
// Usage:
//
// Warnings:
//	 - none.
func NewAuthForVerifier(password, signedModulus string, rawSalt []byte) (auth *Auth, err error) {
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

func toConstInt(arr []byte) *constbn.Int {
	var reversed = make([]byte, len(arr))
	for i := 0; i < len(arr); i++ {
		reversed[len(arr)-i-1] = arr[i]
	}
	num := &constbn.Int{}
	num.SetBytes(reversed)
	return num
}

func fromConstInt(bitLength int, num *constbn.Int) []byte {
	var arr = num.Bytes()
	var reversed = make([]byte, bitLength/8)
	for i := 0; i < len(arr); i++ {
		reversed[len(arr)-i-1] = arr[i]
	}
	return reversed
}

// GenerateProofs calculates SPR proofs.
func (s *Auth) GenerateProofs(bitLength int) (res *Proofs, err error) {
	generator := big.NewInt(2)
	constGenerator := &constbn.Int{}
	constGenerator.SetBigInt(generator)

	multiplier := toInt(expandHash(append(fromInt(bitLength, generator), s.Modulus...)))

	modulus := toInt(s.Modulus)
	serverEphemeral := toInt(s.ServerEphemeral)

	modulusMinusOne := big.NewInt(0).Sub(modulus, big.NewInt(1))

	if modulus.BitLen() != bitLength {
		return nil, errors.New("pm-srp: SRP modulus has incorrect size")
	}

	multiplier = multiplier.Mod(multiplier, modulus)

	if multiplier.Cmp(big.NewInt(1)) <= 0 || multiplier.Cmp(modulusMinusOne) >= 0 {
		return nil, errors.New("pm-srp: SRP multiplier is out of bounds")
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

	var scramblingParam, clientSecret *big.Int
	constClientEphemeral := &constbn.Int{}
	constClientSecret := &constbn.Int{}
	constModulus := toConstInt(s.Modulus)

	for {
		for {
			clientSecret, err = rand.Int(RandReader, modulusMinusOne)
			if err != nil {
				return
			}

			if clientSecret.Cmp(big.NewInt(int64(bitLength*2))) > 0 { // Very likely
				break
			}
		}
		constClientSecret.SetBigInt(clientSecret)
		constClientEphemeral.Exp(constGenerator, constClientSecret, constModulus)

		scramblingParam = toInt(expandHash(append(fromConstInt(bitLength, constClientEphemeral), fromInt(bitLength, serverEphemeral)...)))
		if scramblingParam.Cmp(big.NewInt(0)) != 0 { // Very likely
			break
		}
	}
	constVerifier := constbn.Int{}
	constVerifier.Exp(constGenerator, toConstInt(s.HashedPassword), constModulus)

	subtracted := big.NewInt(0).Sub(
		serverEphemeral,
		big.NewInt(0).Mod(big.NewInt(0).Mul(constVerifier.GetBigInt(), multiplier), modulus),
	)

	if subtracted.Cmp(big.NewInt(0)) < 0 {
		subtracted.Add(subtracted, modulus)
	}
	exponent := big.NewInt(0).Mod(big.NewInt(0).Add(big.NewInt(0).
		Mul(scramblingParam, toInt(s.HashedPassword)), clientSecret), modulusMinusOne)

	constSubtracted := &constbn.Int{}
	constExponent := &constbn.Int{}
	constSharedSession := &constbn.Int{}

	constSubtracted.SetBigInt(subtracted)
	constExponent.SetBigInt(exponent)

	constSharedSession.Exp(constSubtracted, constExponent, constModulus)

	clientProof := expandHash(bytes.Join([][]byte{
		fromConstInt(bitLength, constClientEphemeral),
		fromInt(bitLength, serverEphemeral),
		fromConstInt(bitLength, constSharedSession),
	}, []byte{}))

	serverProof := expandHash(bytes.Join([][]byte{
		fromConstInt(bitLength, constClientEphemeral), clientProof,
		fromConstInt(bitLength, constSharedSession),
	}, []byte{}))

	return &Proofs{
		ClientEphemeral: fromConstInt(bitLength, constClientEphemeral),
		ClientProof: clientProof, ExpectedServerProof: serverProof,
	}, nil
}

// GenerateVerifier verifier for update pwds and create accounts
func (s *Auth) GenerateVerifier(bitLength int) ([]byte, error) {
	generator := &constbn.Int{}
	calModPow := &constbn.Int{}

	generator.SetBigInt(big.NewInt(2))
	modulus := toConstInt(s.Modulus)

	hashedPassword := toConstInt(s.HashedPassword)
	calModPow.Exp(generator, hashedPassword, modulus)
	return fromConstInt(bitLength, calModPow), nil
}
