package srp

import (
	"bytes"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"math/big"

	"crypto/rand"
)

// Server stores the internal state for the validation of SRP proofs.
type Server struct {
	generator, modulus, verifier, serverSecret, serverEphemeral, sharedSession *big.Int
	bitLength                                                                  int
}

// NewServer creates a new server instance from the raw binary data.
func NewServer(modulusBytes, verifier []byte, bitLength int) (*Server, error) {
	var secret *big.Int
	var err error

	modulus := toInt(modulusBytes)
	modulusMinusOne := big.NewInt(0).Sub(modulus, big.NewInt(1))

	for {
		secret, err = rand.Int(RandReader, modulusMinusOne)
		if err != nil {
			return nil, err
		}

		// Prevent g^b from being smaller than the modulus
		if secret.Cmp(big.NewInt(int64(bitLength*2))) > 0 {
			break
		}
	}

	return &Server{
		generator:       big.NewInt(2),
		modulus:         modulus,
		serverSecret:    secret,
		verifier:        toInt(verifier),
		bitLength:       bitLength,
		serverEphemeral: nil,
		sharedSession:   nil,
	}, nil
}

// NewServerWithSecret creates a new server instance without generating a random secret from the raw binary data.
// Use with caution as the secret is not verified.
func NewServerWithSecret(modulusBytes, verifier, secretBytes []byte, bitLength int) (*Server, error) {
	return &Server{
		generator: big.NewInt(2),
		modulus: toInt(modulusBytes),
		serverSecret: toInt(secretBytes),
		verifier: toInt(verifier),
		bitLength: bitLength,
		serverEphemeral: nil,
		sharedSession: nil,
	}, nil
}

// NewServerFromSigned creates a new server instance from the signed modulus and the binary verifier.
func NewServerFromSigned(signedModulus string, verifier []byte, bitLength int) (*Server, error) {
	modulus, err := readClearSignedMessage(signedModulus)
	if err != nil {
		return nil, err
	}
	modulusData, err := base64.StdEncoding.DecodeString(modulus)
	if err != nil {
		return nil, err
	}

	return NewServer(modulusData, verifier, bitLength)
}

// GenerateChallenge is the first step for SRP exchange, and generates a valid challenge for the provided verifier.
func (s *Server) GenerateChallenge() (serverEphemeral []byte, err error) {
	multiplier, err := computeMultiplier(s.generator, s.modulus, s.bitLength)
	if err != nil {
		return nil, err
	}

	s.serverEphemeral = big.NewInt(0).Mod(big.NewInt(0).Add(
		big.NewInt(0).Mul(multiplier, s.verifier),
		big.NewInt(0).Exp(s.generator, s.serverSecret, s.modulus),
	), s.modulus)

	return fromInt(s.bitLength, s.serverEphemeral), nil
}

// VerifyProofs Verifies the client proof and - if valid - generates the shared secret and returnd the server proof.
// It concludes the exchange in valid state if successful.
func (s *Server) VerifyProofs(clientEphemeralBytes, clientProofBytes []byte) (serverProof []byte, err error) {
	if s.serverEphemeral == nil {
		return nil, errors.New("pm-srp: SRP server ephemeral is not generated")
	}

	modulusMinusOne := big.NewInt(0).Sub(s.modulus, big.NewInt(1))
	clientEphemeral := toInt(clientEphemeralBytes)

	if clientEphemeral.Cmp(big.NewInt(1)) <= 0 || clientEphemeral.Cmp(modulusMinusOne) >= 0 {
		return nil, errors.New("pm-srp: SRP client ephemeral is out of bounds")
	}

	scramblingParam := toInt(expandHash(append(clientEphemeralBytes, fromInt(s.bitLength, s.serverEphemeral)...)))
	if scramblingParam.Cmp(big.NewInt(0)) == 0 {
		return nil, errors.New("pm-srp: SRP client ephemeral is invalid")
	}

	s.sharedSession = big.NewInt(0).Exp(
		big.NewInt(0).Mul(
			clientEphemeral,
			big.NewInt(0).Exp(
				s.verifier,
				scramblingParam,
				s.modulus,
			),
		),
		s.serverSecret,
		s.modulus,
	)

	expectedClientProof := expandHash(bytes.Join([][]byte{
		clientEphemeralBytes,
		fromInt(s.bitLength, s.serverEphemeral),
		fromInt(s.bitLength, s.sharedSession),
	}, []byte{}))

	if subtle.ConstantTimeCompare(expectedClientProof, clientProofBytes) == 0 {
		s.sharedSession = nil
		return nil, errors.New("pm-srp: invalid SRP client proof")
	}

	return expandHash(bytes.Join([][]byte{
		clientEphemeralBytes,
		clientProofBytes,
		fromInt(s.bitLength, s.sharedSession),
	}, []byte{})), nil
}

// IsCompleted returns true if the exchange has been concluded in valid state.
func (s *Server) IsCompleted() bool {
	return s.sharedSession != nil
}

// GetSharedSession returns the shared secret as byte if the session has concluded in valid state.
func (s *Server) GetSharedSession() ([]byte, error) {
	if !s.IsCompleted() {
		return nil, errors.New("pm-srp: SRP is not completed")
	}

	return fromInt(s.bitLength, s.sharedSession), nil
}
