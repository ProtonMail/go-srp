# go-srp

## Introduction

srp libaray used in all protonmail clients

## License

Copyright (c) 2019 Proton Technologies AG

Please see [LICENSE](LICENSE.txt) file for the license.

## Doc 
[Secure Remote Password (SRP) Protocol](https://protonmail.com/blog/encrypted_email_authentication/)

## Folders

the root folder contains the main logic.

windows forder contains the warpper for .net.

## Setup

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

If you wish to use build.sh, you may need to modify the paths in it.

#### use go mod

```go
go mod vender
```

```bash
./build.sh
```

#### use glide

```bash
glide i
./build.sh
```

### Dependicy

[bcrypt](https://github.com/jameskeane/bcrypt)

[golang.org/x/mobile](https://golang.org/x/mobile)

[ProtonMail Crypto](https://github.com/ProtonMail/crypto)
