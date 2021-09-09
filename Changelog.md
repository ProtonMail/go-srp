# Changelog for SRP

## Unreleased

### Added
* New function `ECDLPChallenge` to solve Elliptic Curve Discrete Logaritm Problem challenges.

### Changed
* Use `github.com/cronokirby/saferith.Nat` instead of `math/big.Int` for sensitive operations, to avoid side channel attacks.
* Updated `saferith` to `v0.31.0`
### Removed 
* Deleted `srp_openpgp.go` and `srp_openpgp_test.go` as it was redundant and unused. 

## 2021-05-04
### Added
* Add `NewServerWithSecret` function to create a custom server instance.

## 2021-05-03
### Changed 
* Updated ProtonMail/go-crypto to the latest version and reverted to use standard library packages in some cases.

## 2021-04-21
### Changed
* Changed all interfaces taking a password to use []byte instead of string

## 2019-01-14

### Added
* tests

## 2019-01-03

### Added
* pmapi#27 modulus pubkey and verification
* password hash functions for different versions
