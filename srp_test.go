package srp

import (
	"math/rand"
	"testing"
)

const testModulus = "W2z5HBi8RvsfYzZTS7qBaUxxPhsfHJFZpu3Kd6s1JafNrCCH9rfvPLrfuqocxWPgWDH2R8neK7PkNvjxto9TStuY5z7jAzWRvFWN9cQhAKkdWgy0JY6ywVn22+HFpF4cYesHrqFIKUPDMSSIlWjBVmEJZ/MusD44ZT29xcPrOqeZvwtCffKtGAIjLYPZIEbZKnDM1Dm3q2K/xS5h+xdhjnndhsrkwm9U9oyA2wxzSXFL+pdfj2fOdRwuR5nW0J2NFrq3kJjkRmpO/Genq1UW+TEknIWAb6VzJJJA244K/H8cnSx2+nSNZO3bbo6Ys228ruV9A8m6DhxmS+bihN3ttQ=="
const testModulusClearSign = `-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA256

W2z5HBi8RvsfYzZTS7qBaUxxPhsfHJFZpu3Kd6s1JafNrCCH9rfvPLrfuqocxWPgWDH2R8neK7PkNvjxto9TStuY5z7jAzWRvFWN9cQhAKkdWgy0JY6ywVn22+HFpF4cYesHrqFIKUPDMSSIlWjBVmEJZ/MusD44ZT29xcPrOqeZvwtCffKtGAIjLYPZIEbZKnDM1Dm3q2K/xS5h+xdhjnndhsrkwm9U9oyA2wxzSXFL+pdfj2fOdRwuR5nW0J2NFrq3kJjkRmpO/Genq1UW+TEknIWAb6VzJJJA244K/H8cnSx2+nSNZO3bbo6Ys228ruV9A8m6DhxmS+bihN3ttQ==
-----BEGIN PGP SIGNATURE-----
Version: ProtonMail
Comment: https://protonmail.com

wl4EARYIABAFAlwB1j0JEDUFhcTpUY8mAAD8CgEAnsFnF4cF0uSHKkXa1GIa
GO86yMV4zDZEZcDSJo0fgr8A/AlupGN9EdHlsrZLmTA1vhIx+rOgxdEff28N
kvNM7qIK
=q6vu
-----END PGP SIGNATURE-----
`

func init() {
	// Only for tests, replace the default random reader by something that always
	// return the same thing
	randReader = rand.New(rand.NewSource(42))
}

func TestReadClearSigned(t *testing.T) {

	cleartext, err := ReadClearSignedMessage(testModulusClearSign)
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
	_, err = ReadClearSignedMessage(wrongSignature)
	if err != ErrInvalidSignature {
		t.Fatal("Expected the ErrInvalidSignature but have ", err)
	}

	wrongSignature = testModulusClearSign + "data after modulus"
	_, err = ReadClearSignedMessage(wrongSignature)
	if err != ErrDataAfterModulus {
		t.Fatal("Expected the ErrDataAfterModulus but have ", err)
	}

}
