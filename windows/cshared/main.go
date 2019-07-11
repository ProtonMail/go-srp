package main

import "C"
import (
	"bytes"
	"encoding/binary"
	srp "go-srp" //this could hange to repo link
	"math/rand"
)

/// SetTest only when do the tests
//export SetTest
func SetTest() {
	srp.RandReader = rand.New(rand.NewSource(42))
}

/// export interfaces

/// GetModulusKey return back the hard coded modulus key
//export GetModulusKey
func GetModulusKey() string {
	return srp.GetModulusKey()
}

/// GenerateProofs return back the raw bytes proofs. client side need to parse
/// 				version: password version
///					username, password.
///					salt: password salt
///					signedModuls, serverEphemeral from authinfo call
//export GenerateProofs
func GenerateProofs(version int32, username, password, salt, signedModulus, serverEphemeral string, bits int32) []byte {
	v := int(version)
	auth, err := srp.NewAuth(v, username, password, salt, signedModulus, serverEphemeral)
	buf := bytes.Buffer{}
	if err != nil {
		//version
		buf.WriteByte(0x01)
		//type
		buf.WriteByte(0x00)
		var msg string = err.Error()
		bmsg := []byte(msg)

		binary.Write(&buf, binary.LittleEndian, uint16(len(bmsg)))
		buf.Write(bmsg)
		return buf.Bytes()
	}
	bitLength := int(bits)
	proofs, err := auth.GenerateProofs(bitLength)
	if err != nil {
		//version
		buf.WriteByte(0x01)
		//type
		buf.WriteByte(0x00)
		var msg string = err.Error()
		bmsg := []byte(msg)
		binary.Write(&buf, binary.LittleEndian, uint16(len(bmsg)))
		buf.Write(bmsg)
		return buf.Bytes()
	}

	//version
	buf.WriteByte(0x01)
	//type
	buf.WriteByte(0x01)
	clientProofLen := uint16(len(proofs.ClientProof))
	clientEphemeralLen := uint16(len(proofs.ClientEphemeral))
	expectedServerProofLen := uint16(len(proofs.ExpectedServerProof))

	binary.Write(&buf, binary.LittleEndian, clientProofLen)
	buf.Write(proofs.ClientProof)
	binary.Write(&buf, binary.LittleEndian, clientEphemeralLen)
	buf.Write(proofs.ClientEphemeral)
	binary.Write(&buf, binary.LittleEndian, expectedServerProofLen)
	buf.Write(proofs.ExpectedServerProof)

	return buf.Bytes()
}

/// GenerateVerifier return back the raw bytes verifier.
//export GenerateVerifier
func GenerateVerifier(password, signedModulus string, rawSalt []byte, bits int32) []byte {
	auth, err := srp.NewAuthForVerifier(password, signedModulus, rawSalt)
	b := bytes.Buffer{}
	if err != nil {
		//version
		b.WriteByte(0x01)
		//type
		b.WriteByte(0x00)
		var msg string = err.Error()
		bmsg := []byte(msg)
		binary.Write(&b, binary.LittleEndian, uint16(len(bmsg)))
		b.Write(bmsg)
		return b.Bytes()
	}
	bitLength := int(bits)
	verifier, err := auth.GenerateVerifier(bitLength)
	if err != nil {
		//version
		b.WriteByte(0x01)
		//type
		b.WriteByte(0x00)
		var msg string = err.Error()
		bmsg := []byte(msg)
		binary.Write(&b, binary.LittleEndian, uint16(len(bmsg)))
		b.Write(bmsg)
		return b.Bytes()
	}

	//version
	b.WriteByte(0x01)
	//type
	b.WriteByte(0x01)
	//verifier len
	verifierLen := uint16(len(verifier))
	binary.Write(&b, binary.LittleEndian, verifierLen)
	b.Write(verifier)
	return b.Bytes()
}

func main() {}
