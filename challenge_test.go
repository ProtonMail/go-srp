package srp

import (
	"strings"
	"testing"
	"time"
)

func TestECDLPChallenge(t *testing.T) {
	b64Challenge := "qfGBXLcNQMRqs/Krzx+EL87++Unwy5PGlnWxK2/BRIckF+Zlqmo7eIczHzAfm66MIZk5hkRVDVXMmEfy7dB++pkn3Ht+4bm3UtbBws/R43xZn23E2rSvPACxnjGFxMar"
	b64Target := "ewAAAAAAAACsasMixdYBr/9Fb4SMM8urvjPUEUCVOjGqzwQyRdUafg=="

	result, err := ECDLPChallenge(b64Challenge, -1)
	if err != nil {
		t.Fatal("Expected no error in processing challenge")
	}

	if result != b64Target {
		t.Fatalf("Expected result to be %s, returned %s", b64Target, result)
	}
}

func TestECDLPChallengeTimeout(t *testing.T) {
	b64Challenge := strings.Repeat("A", 128)
	_, err := ECDLPChallenge(b64Challenge, time.Now().UnixMilli()+5)
	if err != DeadlineExceeded {
		t.Fatal("Expected timeout in ECDLP challenge")
	}
}

func TestArgon2PreimageChallenge(t *testing.T) {
	b64Challenge := "qbYJSn07JQGfol0u8MJTZ16fDRyFo2AR6phcgqlZCr44RBpz/odJc17EROMfMOpz2dE8oHW2JHeqoRax2ha4bpGusDBkEySSWJU+cmuWePzUC58fTY+VJMLBMDLhdqV9QKvozeqKcoPzqDoHZZYmyWQf4DIAKfgaha/WwzMikQMBAAAAIAAAAOEQAAABAAAA"
	b64Target := "ewAAAAAAAABXe+n/4g0Hfz40eEw7h5d3XeiKdWilfCJvz0izj7p0YA=="

	result, err := Argon2PreimageChallenge(b64Challenge, -1)
	if err != nil {
		t.Fatal("Expected no error in processing challenge")
	}

	if result != b64Target {
		t.Fatalf("Expected result to be %s, returned %s", b64Target, result)
	}
}

func TestArgon2PreimageChallengeTimeout(t *testing.T) {
	b64Challenge := strings.Repeat("A", 170) + "MBAAAAIAAAAOEQAAABAAAA"
	_, err := Argon2PreimageChallenge(b64Challenge, time.Now().UnixMilli()+5)
	if err != DeadlineExceeded {
		t.Fatal("Expected timeout in Argon2 preimage challenge")
	}
}
