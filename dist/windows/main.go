package main

import (
	"C"
	"github.com/ProtonMail/go-srp"
)

// export VerifyMessage
func VerifyMessage(signedMessage *C.char) (errC int) {
	errC = 0
	if _, err := srp.ReadClearSignedMessage(C.GoString(signedMessage)); err != nil {
		errC = 1
	}
	return
}

func main() {
}
