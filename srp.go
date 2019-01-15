package srp

import (
	"bytes"
	"encoding/base64"
	"errors"
	"math/big"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/clearsign"
	"golang.org/x/crypto/rand"
)

var (
	// ErrDataAfterModulus found extra data after decode the modulus
	ErrDataAfterModulus = errors.New("pm-srp: extra data after modulus")

	// ErrInvalidSignature invalid modulus signature
	ErrInvalidSignature = errors.New("pm-srp: invalid modulus signature")
)

// Store random reader in a variable to be able to overwrite it in tests
var randReader = rand.Reader

// Proofs Srp Proofs object. Changed SrpProofs to Proofs because the name will be used as srp.SrpProofs by other packages and as SrpSrpProofs on mobile
// ClientProof []byte  client proof
// ClientEphemeral []byte  calculated from
// ExpectedServerProof []byte
type Proofs struct {
	ClientProof, ClientEphemeral, ExpectedServerProof []byte
}

// AuthInfo stores byte data for the calculation of SRP proofs.
//  * Changed SrpAuto to AuthInfo because the name will be used as srp.SrpAuto by other packages and as SrpSrpAuth on mobile
//  * Also the data from the API called AuthInfo. it could be match the meaning and reduce the confusion
type AuthInfo struct {
	Modulus, ServerEphemeral, HashedPassword []byte
}

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

// NewAuthInfo Creates new SrpAuth from strings input. Salt and server ephemeral are in
// base64 format. Modulus is base64 with signature attached. The signature is
// verified against server key. The version controls password hash algorithm.
func NewAuthInfo(version int, username, password, salt, signedModulus, serverEphemeral string) (auth *AuthInfo, err error) {
	data := &AuthInfo{}

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

// GenerateProofs calculates SPR proofs.
func (s *AuthInfo) GenerateProofs(length int) (res *Proofs, err error) {
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

	return &Proofs{ClientEphemeral: fromInt(clientEphemeral), ClientProof: clientProof, ExpectedServerProof: serverProof}, nil
}

// GenerateVerifier verifier for update pwds and create accounts
func (s *AuthInfo) GenerateVerifier(length int) ([]byte, error) {
	return nil, errors.New("pm-srp: the client doesn't need SRP GenerateVerifier")
}
