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

package main

import "C"
import (
	"bytes"
	"encoding/binary"
	srp "github.com/ProtonMail/go-srp" //this could hange to repo link
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
