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
	"encoding/hex"
	"fmt"
	"math/rand"
	"testing"

	pmrand "github.com/ProtonMail/go-crypto/rand"
)

const (
	testServerEphemeral = "l13IQSVFBEV0ZZREuRQ4ZgP6OpGiIfIjbSDYQG3Yp39FkT2B/k3n1ZhwqrAdy+qvPPFq/le0b7UDtayoX4aOTJihoRvifas8Hr3icd9nAHqd0TUBbkZkT6Iy6UpzmirCXQtEhvGQIdOLuwvy+vZWh24G2ahBM75dAqwkP961EJMh67/I5PA5hJdQZjdPT5luCyVa7BS1d9ZdmuR0/VCjUOdJbYjgtIH7BQoZs+KacjhUN8gybu+fsycvTK3eC+9mCN2Y6GdsuCMuR3pFB0RF9eKae7cA6RbJfF1bjm0nNfWLXzgKguKBOeF3GEAsnCgK68q82/pq9etiUDizUlUBcA=="
	testServerProof     = "SLCSIClioSAtozauZZzcJuVPyY+MjnxfJSgEe9y6RafgjlPqnhQTZclRKPGsEhxVyWan7PIzhL+frPyZNaE1QaV5zbqz1yf9RXpGyTjZwU3FuVCJpkhp6iiCK3Wd2SemxawFXC06dgAdJ7I3HKvfkXeMANOUUh5ofjnJtXg42OGp4x1lKoFcH+IbB/CvRNQCmRTyhOiBJmZyUFwxHXLT/h+PlD0XSehcyybIIBIsscQ7ZPVPxQw4BqlqoYzTjjXPJxLxeQUQm2g9bPzT+izuR0VOPDtjt+dXrWny90k2nzS0Bs2YvNIqbJn1aQwFZr42p/O1I9n5S3mYtMgGk/7b1g=="

	testClientProof      = "Qb+1+jEqHRqpJ3nEJX2FEj0kXgCIWHngO0eT4R2Idkwke/ceCIUmQa0RfTYU53ybO1AVergtb7N0W/3bathdHT9FAHhy0vDGQDg/yPnuUneqV76NuU+pQHnO83gcjmZjDq/zvRRSD7dtIORRK97xhdR9W9bG5XRGr2c9Zev40YVcXgUiNUG/0zHSKQfEhUpMKxdauKtGC+dZnZzU6xaU0qvulYEsraawurRf0b1VXwohM6KE52Fj5xlS2FWZ3Mg0WIOC5KW5ziI6QirEUDK2pH/Rxvu4HcW9aMuppUmHk9Bm6kdg99o3vl0G7OgmEI7y6iyEYmXqH44XGORJ2sDMxQ=="
	testModulus          = "W2z5HBi8RvsfYzZTS7qBaUxxPhsfHJFZpu3Kd6s1JafNrCCH9rfvPLrfuqocxWPgWDH2R8neK7PkNvjxto9TStuY5z7jAzWRvFWN9cQhAKkdWgy0JY6ywVn22+HFpF4cYesHrqFIKUPDMSSIlWjBVmEJZ/MusD44ZT29xcPrOqeZvwtCffKtGAIjLYPZIEbZKnDM1Dm3q2K/xS5h+xdhjnndhsrkwm9U9oyA2wxzSXFL+pdfj2fOdRwuR5nW0J2NFrq3kJjkRmpO/Genq1UW+TEknIWAb6VzJJJA244K/H8cnSx2+nSNZO3bbo6Ys228ruV9A8m6DhxmS+bihN3ttQ=="
	testModulusClearSign = `-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA256

W2z5HBi8RvsfYzZTS7qBaUxxPhsfHJFZpu3Kd6s1JafNrCCH9rfvPLrfuqocxWPgWDH2R8neK7PkNvjxto9TStuY5z7jAzWRvFWN9cQhAKkdWgy0JY6ywVn22+HFpF4cYesHrqFIKUPDMSSIlWjBVmEJZ/MusD44ZT29xcPrOqeZvwtCffKtGAIjLYPZIEbZKnDM1Dm3q2K/xS5h+xdhjnndhsrkwm9U9oyA2wxzSXFL+pdfj2fOdRwuR5nW0J2NFrq3kJjkRmpO/Genq1UW+TEknIWAb6VzJJJA244K/H8cnSx2+nSNZO3bbo6Ys228ruV9A8m6DhxmS+bihN3ttQ==
-----BEGIN PGP SIGNATURE-----
Version: ProtonMail
Comment: https://protonmail.com

wl4EARYIABAFAlwB1j0JEDUFhcTpUY8mAAD8CgEAnsFnF4cF0uSHKkXa1GIa
GO86yMV4zDZEZcDSJo0fgr8A/AlupGN9EdHlsrZLmTA1vhIx+rOgxdEff28N
kvNM7qIK
=q6vu
-----END PGP SIGNATURE-----`
)

func init() {
	// Only for tests, replace the default random reader by something that always
	// return the same thing
	RandReader = rand.New(rand.NewSource(42))
}

func TestReadClearSigned(t *testing.T) {
	cleartext, err := readClearSignedMessage(testModulusClearSign)
	if err != nil {
		t.Fatal("Expected no error but have ", err)
	}
	if cleartext != testModulus {
		t.Fatalf("Expected message\n\t'%s'\nbut have\n\t'%s'", testModulus, cleartext)
	}

	lastChar := len(testModulusClearSign)
	wrongSignature := testModulusClearSign[:lastChar-100]
	wrongSignature += "c"
	wrongSignature += testModulusClearSign[lastChar-99:]
	_, err = readClearSignedMessage(wrongSignature)
	if err != ErrInvalidSignature {
		t.Fatal("Expected the ErrInvalidSignature but have ", err)
	}

	wrongSignature = testModulusClearSign + "data after modulus"
	_, err = readClearSignedMessage(wrongSignature)
	if err != ErrDataAfterModulus {
		t.Fatal("Expected the ErrDataAfterModulus but have ", err)
	}
}

func TestSRPauth(t *testing.T) {
	srp, err := NewAuth(4, "jakubqa", "abc123", "yKlc5/CvObfoiw==", testModulusClearSign, testServerEphemeral)
	if err != nil {
		t.Fatal("Expected no error but have ", err)
	}

	proofs, err := srp.GenerateProofs(2048)
	if err != nil {
		t.Fatal("Expected no error but have ", err)
	}

	expectedProof, err := base64.StdEncoding.DecodeString(testServerProof)
	if err != nil {
		t.Fatal("Expected no error but have ", err)
	}
	if bytes.Compare(proofs.ExpectedServerProof, expectedProof) != 0 {
		t.Fatalf("Expected server proof\n\t'%s'\nbut have\n\t'%s'",
			testServerProof,
			base64.StdEncoding.EncodeToString(proofs.ExpectedServerProof),
		)
	}

	expectedProof, err = base64.StdEncoding.DecodeString(testClientProof)
	if err != nil {
		t.Fatal("Expected no error but have ", err)
	}
	if bytes.Compare(proofs.ClientProof, expectedProof) != 0 {
		t.Fatalf("Expected client proof\n\t'%s'\nbut have\n\t'%s'",
			testClientProof,
			base64.StdEncoding.EncodeToString(proofs.ClientProof),
		)
	}
}

func TestNewAuth(t *testing.T) {
	type args struct {
		version         int
		username        string
		password        string
		salt            string
		signedModulus   string
		serverEphemeral string
	}
	tests := []struct {
		name     string
		args     args
		wantAuth *Auth
		wantErr  bool
	}{
		{
			name: "test1",
			args: args{
				version:         4,
				username:        "axiomarrochar",
				password:        "123",
				salt:            "xTRjm6MUl5mpYA==",
				signedModulus:   "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\no4ycZ14/7LfHkuSKWNlpQEh6bwLMVKvo0MFqVq9wHXwkZ/zMcqYaVhqNvLyDB0WY5Uv/Bo23JQsox52lM+4jPydw9/A9saAj8erLCc3ZaZHxOl/a8tlYTq7FeDrbhSSgivwTKJ5Y9otla/U8FATZBxqi7nqDihS5/7x/yK3VRnEsBG1i5DcY1UQK3KD9i9v7N2QTuGFYnRCv0MFsHzrQZWvUa1NsUhozU5PSV5s7hZkb/p6J3B9ybD6+LzuLS9fyLMcVdxzn2WUXG7JLeBbqsoECUfq9KP2waTzVLELOenWUV1wbioceJsaiP97ViwNJdnKx1ICoYu2c+z8ctVcqlw==\n-----BEGIN PGP SIGNATURE-----\nVersion: ProtonMail\nComment: https://protonmail.com\n\nwl4EARYIABAFAlwB1j0JEDUFhcTpUY8mAAB02wD5AOhMNS/K6/nvaeRhTr5n\niDGMalQccYlb58XzUEhqf3sBAOcTsz0fP3PVdMQYBbqcBl9Y6LGIG9DF4B4H\nZeLCoyYN\n=cAxM\n-----END PGP SIGNATURE-----\n",
				serverEphemeral: "xpBZbd761rSatefDH7TI5aYMHN1IviIb/hpG2yIz4kZQ/INDXxe11pIGxKeOKszbr8tJHrqQA9LF9OFr5vEqHgxzSQbAz/7ERaRK76mbtc+K9dOFsqq1oJ2dSxe1gI49kSyxqco33pETTLmIG3fYUqTJtE7Bmxn1A0SY3Nj5x2c1TGzGxU5yC5vstWLP7NNVDpgMfARUV6YNMjKeD6fvNdQB4bKcwn9vVTU8F04rVqagGG/VQMmIG8cYGd+cjVQavjGHagXbjsQAGblFMQ5ta6bnJn0fbdeflhk0So/FlvCpyoEqVeRZx/auZ9oUfkAXJjZOblaAIHMx+I3CCdyPUw==",
			},
		},

		{
			name: "test2",
			args: args{
				version:         4,
				username:        "Cyb3rReaper",
				password:        "123",
				salt:            "CGhrAMJla9YHGQ==",
				signedModulus:   "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\no4ycZ14/7LfHkuSKWNlpQEh6bwLMVKvo0MFqVq9wHXwkZ/zMcqYaVhqNvLyDB0WY5Uv/Bo23JQsox52lM+4jPydw9/A9saAj8erLCc3ZaZHxOl/a8tlYTq7FeDrbhSSgivwTKJ5Y9otla/U8FATZBxqi7nqDihS5/7x/yK3VRnEsBG1i5DcY1UQK3KD9i9v7N2QTuGFYnRCv0MFsHzrQZWvUa1NsUhozU5PSV5s7hZkb/p6J3B9ybD6+LzuLS9fyLMcVdxzn2WUXG7JLeBbqsoECUfq9KP2waTzVLELOenWUV1wbioceJsaiP97ViwNJdnKx1ICoYu2c+z8ctVcqlw==\n-----BEGIN PGP SIGNATURE-----\nVersion: ProtonMail\nComment: https://protonmail.com\n\nwl4EARYIABAFAlwB1j0JEDUFhcTpUY8mAAB02wD5AOhMNS/K6/nvaeRhTr5n\niDGMalQccYlb58XzUEhqf3sBAOcTsz0fP3PVdMQYBbqcBl9Y6LGIG9DF4B4H\nZeLCoyYN\n=cAxM\n-----END PGP SIGNATURE-----\n",
				serverEphemeral: "vl0zIXo4bLPtYVoy3kIvhWQx3ObPMYTY0c5/TFHlmwgBW6Hz/p2XDJdDykF3rBfwrSUD4tfs1YRCfgGfvxegCIQhL419OPYgA+ApXUuS2ni86AXUfjPnvJju/inYQxER8nzEhM8DZYAiNM44qeepmXGrHmwjXAMzyaggqxmkTq4v+seKntFE5oH7iIFacgP52wnV/p6OLOMNS4t/vZ3haKaoEVoFyCVVoTJ/OVPp1ZoUovOoxwDvUAOjSEgswenR96xT+4CsPz9Dm+yF/bDugcWGQ4KB8KEzBrO0PqmCQWMYOKaILegtgTjg08eQTvGylSEZmbTeVzoPe/THqh2bJw==",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotAuth, err := NewAuth(tt.args.version, tt.args.username, tt.args.password, tt.args.salt, tt.args.signedModulus, tt.args.serverEphemeral)
			if gotAuth != nil {
				fmt.Println(gotAuth.HashedPassword)
				fmt.Println(gotAuth.Modulus)
				//t.Errorf("gotAuth() error = %v", gotAuth)
			}

			if err != nil {
				t.Errorf("NewAuth() error = %v", err)
				return
			}
			// if !reflect.DeepEqual(gotAuth, tt.wantAuth) {
			// 	t.Errorf("NewAuth() = %v, want %v", gotAuth, tt.wantAuth)
			// }
		})
	}
}

// TestE2EFlow performs a test with the client and server using real random data.
func TestE2EFlow(t *testing.T) {
	RandReader = pmrand.Reader

	var bits = 2048
	var password = "Password\nabc!!~~ä\r\n"

	rawSalt, err := RandomBytes(10)
	if err != nil {
		t.Fatal("Expected no error while generating raw salt, have ", err)
	}

	verifierAuth, err := NewAuthForVerifier(password, testModulusClearSign, rawSalt)
	if err != nil {
		t.Fatal("Expected no error while creating auth for verifier, have ", err)
	}

	verifier, err := verifierAuth.GenerateVerifier(bits)
	if err != nil {
		t.Fatal("Expected no error while generating verifier, have ", err)
	}

	server, err := NewServerFromSigned(testModulusClearSign, verifier, bits)
	if err != nil {
		t.Fatal("Expected no error while creating server, have ", err)
	}

	challenge, err := server.GenerateChallenge()
	if err != nil {
		t.Fatal("Expected no error while generating challenge, have ", err)
	}

	auth, err := NewAuth(
		4,
		"Test",
		password,
		base64.StdEncoding.EncodeToString(rawSalt),
		testModulusClearSign,
		base64.StdEncoding.EncodeToString(challenge),
	)
	if err != nil {
		t.Fatal("Expected no error while creating auth, have ", err)
	}

	proofs, err := auth.GenerateProofs(bits)
	if err != nil {
		t.Fatal("Expected no error while generating client proofs, have ", err)
	}

	serverProof, err := server.VerifyProofs(proofs.ClientEphemeral, proofs.ClientProof)
	if err != nil {
		t.Fatal("Expected no error while generating server proofs, have ", err)
	}

	if !server.IsCompleted() {
		t.Fatal("Expected SRP exchange to be completed, have ", err)
	}

	if bytes.Compare(proofs.ExpectedServerProof, serverProof) != 0 {
		t.Fatalf("Expected server proof\n\t'%s'\nbut have\n\t'%s'",
			hex.EncodeToString(proofs.ExpectedServerProof),
			hex.EncodeToString(serverProof),
		)
	}

	sharedSession, err := server.GetSharedSession()
	if err != nil {
		t.Fatal("Expected no error while getting shared session secret, have ", err)
	}

	if bytes.Compare(proofs.sharedSession, sharedSession) != 0 {
		t.Fatalf("Expected server proof\n\t'%s'\nbut have\n\t'%s'",
			hex.EncodeToString(proofs.sharedSession),
			hex.EncodeToString(sharedSession),
		)
	}
}