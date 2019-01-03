package pmapi

import (
	"math/rand"
)

func init() {
	// Only for tests, replace the default random reader by something that always
	// return the same thing
	randReader = rand.New(rand.NewSource(42))
}
