module go-srp

go 1.12

require (
	github.com/jameskeane/bcrypt v0.0.0-20120420032655-c3cd44c1e20f
	golang.org/x/crypto v0.0.0-20190604143603-d3d8a14a4d4f
	golang.org/x/mobile v0.0.0-20190910184405-b558ed863381 // indirect
)

replace golang.org/x/crypto => github.com/ProtonMail/crypto v1.0.1-0.20190903160734-ac9b7da05e53
