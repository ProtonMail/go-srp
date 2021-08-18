package srp

import "testing"

func TestECDLPChallenge(t *testing.T) {
	challenge := "Qwr8NfpwpxeC3ulvVNIQlhJiKou7WUV1YLrwE8K94wf+RGrY9NJyR/HFBSNM6GZuzrZ3vdTdJkA="
	result, err := ECDLPChallenge(challenge)
	if err != nil {
		t.Fatal("Expected no error in processing challenge")
	}

	if result != 123 {
		t.Fatalf("Expected result to be 123, returned %d", result)
	}
}