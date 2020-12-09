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

//+build openpgp

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
	ErrDataAfterModulus = errors.New("pm-srp: extra data after modulus")
	ErrInvalidSignature = errors.New("pm-srp: invalid modulus signature")
)

// Amored pubkey for modulus verification
const modulusPubkey = `-----BEGIN PGP PUBLIC KEY BLOCK-----

xjMEXAHLgxYJKwYBBAHaRw8BAQdAFurWXXwjTemqjD7CXjXVyKf0of7n9Ctm
L8v9enkzggHNEnByb3RvbkBzcnAubW9kdWx1c8J3BBAWCgApBQJcAcuDBgsJ
BwgDAgkQNQWFxOlRjyYEFQgKAgMWAgECGQECGwMCHgEAAPGRAP9sauJsW12U
MnTQUZpsbJb53d0Wv55mZIIiJL2XulpWPQD/V6NglBd96lZKBmInSXX/kXat
Sv+y0io+LR8i2+jV+AbOOARcAcuDEgorBgEEAZdVAQUBAQdAeJHUz1c9+KfE
kSIgcBRE3WuXC4oj5a2/U3oASExGDW4DAQgHwmEEGBYIABMFAlwBy4MJEDUF
hcTpUY8mAhsMAAD/XQD8DxNI6E78meodQI+wLsrKLeHn32iLvUqJbVDhfWSU
WO4BAMcm1u02t4VKw++ttECPt+HUgPUq5pqQWe5Q2cW4TMsE
=Y4Mw
-----END PGP PUBLIC KEY BLOCK-----`

// ReadClearSignedMessage reads the clear text from signed message and verifies
// signature. There must be no data appended after signed message in input string.
// The message must be sign by key corresponding to `modulusPubkey`.
func ReadClearSignedMessage(signedMessage string) (string, error) {
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

// Creates new SrpAuth from strings input. Salt and server ephemeral are in
// base64 format. Modulus is base64 with signature attached. The signature is
// verified against server key. The version controls password hash algorithm.
func NewSrpAuth(version int, username, password, salt, signedModulus, serverEphemeral string) (auth *SrpAuth, err error) {
	data := &SrpAuth{}

	// Modulus
	var modulus string
	modulus, err = ReadClearSignedMessage(signedModulus)
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

// GenerateSrpProofs calculates SPR proofs.
func (s *SrpAuth) GenerateSrpProofs(length int) (res *SrpProofs, err error) {
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
	multiplier := toInt(ExpandHash(append(fromInt(generator), s.Modulus...)))

	modulus := toInt(s.Modulus)
	serverEphemeral := toInt(s.ServerEphemeral)
	hashedPassword := toInt(s.HashedPassword)

	modulusMinusOne := big.NewInt(0).Sub(modulus, big.NewInt(1))

	if modulus.BitLen() != length {
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
func (s *SrpAuth) GenerateVerifier(length int) ([]byte, error) {
	return nil, errors.New("pm-srp: the client doesn't need SRP GenerateVerifier")
}
