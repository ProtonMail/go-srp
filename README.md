# go-srp

## Introduction

Golang implementation of the [SRP protocol](https://datatracker.ietf.org/doc/html/rfc5054), used for authentication of ProtonMail users.

## License

Copyright (c) 2019 Proton Technologies AG

Please see [LICENSE](LICENSE.txt) file for the license.

## Doc 

- [Technical blog post](https://protonmail.com/blog/encrypted_email_authentication/)
- [RFC 5054](https://datatracker.ietf.org/doc/html/rfc5054)

## .NET Wrapper

The `windows` folder contains the wrapper for .net.

## Build for mobile apps

Setup Go Mobile and build/bind the source code:

Go Mobile repo: https://github.com/golang/mobile

Go Mobile wiki: https://github.com/golang/go/wiki/Mobile

1. Install Go: `brew install go`
2. Install Gomobile: `go get -u golang.org/x/mobile/cmd/gomobile`
3. Install Gobind: `go install golang.org/x/mobile/cmd/gobind`
4. Install Android SDK and NDK using Android Studio
5. Set env: `export ANDROID_HOME="/AndroidSDK"` (path to your SDK)
6. Init gomobile: `gomobile init -ndk /AndroidSDK/ndk-bundle/` (path to your NDK)
7. Copy Go module dependencies to the vendor directory: `go mod vendor`
8. Build examples:
   `gomobile build -target=android  #or ios`

   Bind examples:
   `gomobile bind -target ios -o frameworks/name.framework`
   `gomobile bind -target android`

   The bind will create framework for iOS and jar&aar files for Android (x86_64 and ARM).

#### Other notes

If you wish to use `build.sh`, you may need to modify the paths in it.

```go
go mod vendor
```

```bash
./build.sh
```

## Dependencies

[github.com/ProtonMail/bcrypt (fork of github.com/jameskeane/bcrypt)](https://github.com/ProtonMail/bcrypt)

[golang.org/x/mobile](https://golang.org/x/mobile)

[github.com/ProtonMail/go-crypto](https://github.com/ProtonMail/go-crypto)

[github.com/cronokirby/saferith](https://github.com/cronokirby/saferith)

## Usage

### SRP Client

#### Sign up
```go 

bitLength := 2048

password := "<password typed by user>"

salt := srp.RandomBytes(16)

signedModulus := // provided and signed by the server, base64 encoded

verifierGenerator, err  := NewAuthForVerifier(password, signedModulus, salt)

// check errors, abort sign up if it failed 

verifier, err := verifierGenerator.GenerateVerifier(bitLength)

// check errors, abort sign up if it failed 

// send salt and verifier to server for sign up
```

#### Log in

```go 

bitLength := 2048

username := "username"

password := "<password typed by user>"

version, salt, signedModulus, serverEphemeral := // get login info from server, values are base64 encoded

proofsGenerator, err  := NewAuth(version, username, password, salt, signedModulus, serverEphemeral)

// check errors, abort login if it failed 

proofs, err := proofsGenerator.GenerateProofs(bitLength)

// check errors, abort login if it failed 

serverProof := // send proofs.ClientProof and proofs.ClientEphemeral to server, expect the serverProof in the response

if !bytes.Equal(serverProof, proofs.ExpectedServerProof) {
		// abort login
}
```

### SRP Server

the server side implementation is provided for testing purposes

#### Sign up
```go 

bitLength := 2048

signedModulus := // Hardcoded on the server, needs to be signed by proton

// send signed modulus to the client

salt, verifier := // get sign up values from the client

version := 4

// store (salt, verifier, version, modulus) as the login information for the newly created account

```

#### Log in

```go 

bitLength := 2048

username := // get a login request for a given username

salt, verifier, version, modulus := // retrieve the login information from the sign up

loginServer, err := NewServerFromSigned(modulus, verifier, bitLength)

// check errors, abort login if it failed

serverEphemeral, err  := loginServer.GenerateChallenge()

// check errors, abort login if it failed

// reply to the request with salt, version, modulus, serverEphemeral

clientEphemeral, clientProof := // get a login proof from the client

serverProof, err := loginServer.VerifyProofs(clientEphemeral, clientProof)

// check errors, abort login if it failed

// send back serverProof to the client

// user is logged in
```