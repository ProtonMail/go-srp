package srp

import "testing"

func TestECDLPChallenge(t *testing.T) {
	b64Challenge := "qfGBXLcNQMRqs/Krzx+EL87++Unwy5PGlnWxK2/BRIckF+Zlqmo7eIczHzAfm66MIZk5hkRVDVXMmEfy7dB++pkn3Ht+4bm3UtbBws/R43xZn23E2rSvPACxnjGFxMar"
	b64Target := "ewAAAAAAAACsasMixdYBr/9Fb4SMM8urvjPUEUCVOjGqzwQyRdUafg=="

	result, err := ECDLPChallenge(b64Challenge)
	if err != nil {
		t.Fatal("Expected no error in processing challenge")
	}

	if result != b64Target {
		t.Fatalf("Expected result to be %s, returned %s", b64Target, result)
	}
}

func TestArgon2PreimageChallenge(t *testing.T) {
	b64Challenge := "qbYJSn07JQGfol0u8MJTZ16fDRyFo2AR6phcgqlZCr44RBpz/odJc17EROMfMOpz2dE8oHW2JHeqoRax2ha4bpGusDBkEySSWJU+cmuWePzUC58fTY+VJMLBMDLhdqV9QKvozeqKcoPzqDoHZZYmyWQf4DIAKfgaha/WwzMikQMBAAAAIAAAAOEQAAABAAAA"
	b64Target := "ewAAAAAAAABXe+n/4g0Hfz40eEw7h5d3XeiKdWilfCJvz0izj7p0YA=="

	result, err := Argon2PreimageChallenge(b64Challenge)
	if err != nil {
		t.Fatal("Expected no error in processing challenge")
	}

	if result != b64Target {
		t.Fatalf("Expected result to be %s, returned %s", b64Target, result)
	}
}
