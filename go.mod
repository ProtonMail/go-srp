module github.com/ProtonMail/go-srp

go 1.12

require (
	github.com/ProtonMail/go-crypto v0.0.0-20201208181130-20fe99622a86
	github.com/jameskeane/bcrypt v0.0.0-20120420032655-c3cd44c1e20f
	golang.org/x/mobile v0.0.0-20190910184405-b558ed863381 // indirect
)

replace golang.org/x/mobile => github.com/ProtonMail/go-mobile v0.0.0-20201014085805-7a2d68bf792f
