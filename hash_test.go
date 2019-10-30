//  The MIT License
//
//  Copyright (c) 2019 Proton Technologies AG
//
//  Permission is hereby granted, free of charge, to any person obtaining a copy
//  of this software and associated documentation files (the "Software"), to deal
//  in the Software without restriction, including without limitation the rights
//  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//  copies of the Software, and to permit persons to whom the Software is
//  furnished to do so, subject to the following conditions:
//
//  The above copyright notice and this permission notice shall be included in
//  all copies or substantial portions of the Software.
//
//  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
//  THE SOFTWARE.

package srp

import (
	"reflect"
	"testing"
)

func Test_bcryptHash(t *testing.T) {

	tests := []struct {
		encodedSalt string
		wantHashed  string
		wantErr     bool
	}{
		{encodedSalt: "PTTsDBs/mlLnSk6VmtFghe", wantHashed: "$2y$10$PTTsDBs/mlLnSk6VmtFgheNSiK/lSwtJsrBLLDK3kZYI7193nInqy", wantErr: false},
		{encodedSalt: "4DZHd6WZX4fEaWKtCfYdde", wantHashed: "$2y$10$4DZHd6WZX4fEaWKtCfYddeZfcryISo9eEMgbA90O.Wnnz1s1VKmKC", wantErr: false},
		{encodedSalt: "RpyeXO7K2eD3r/ZZ/B63V.", wantHashed: "$2y$10$RpyeXO7K2eD3r/ZZ/B63V.Tya53OExbyO8LR7TB93KYP4PvC.EPMW", wantErr: false},
		{encodedSalt: "xVEeHQI8CyNkblUJDhyx3u", wantHashed: "$2y$10$xVEeHQI8CyNkblUJDhyx3uZjo8GDXoNNVoRpLwLvssO1GvV3eYFJS", wantErr: false},
		{encodedSalt: "d4Q1rrFYjGq2jyVUi7YwTu", wantHashed: "$2y$10$d4Q1rrFYjGq2jyVUi7YwTuikgSeAgJfaAYJSJZIbIOvW1GBFwx2J6", wantErr: false},
		{encodedSalt: "/.3KXCwRnsrxURMGxN7.R.", wantHashed: "$2y$10$/.3KXCwRnsrxURMGxN7.R.GLpVq0zyBbI9wgS0wB2U/g2btx1RYoy", wantErr: false},
		{encodedSalt: "tuE3bNGezetI9Ra2aGePqu", wantHashed: "$2y$10$tuE3bNGezetI9Ra2aGePqutWPxG2r36BOzMGoXYzM0p2vmGT9fK1i", wantErr: false},
		{encodedSalt: "GFfbuV2J/9BsY0Mb8sJOCe", wantHashed: "$2y$10$GFfbuV2J/9BsY0Mb8sJOCejr2HSgVY2R93m7qQYqSID5ONeYg7ngG", wantErr: false},
		{encodedSalt: "FYvnvw/ghdYJbOADddZ3Ae", wantHashed: "$2y$10$FYvnvw/ghdYJbOADddZ3Ae.XoxSKZqOf5t0S/epYUaNn7YmdxmxD6", wantErr: false},
		{encodedSalt: "jjMNLFvjPepiyCfuKxYUcO", wantHashed: "$2y$10$jjMNLFvjPepiyCfuKxYUcOykUITQRwkNY1oY5ZgxCDIgj6lXypXx2", wantErr: false},
	}
	for _, tt := range tests {
		t.Run("testBcryp", func(t *testing.T) {
			gotHashed, err := bcryptHash("test!!!", tt.encodedSalt)
			if (err != nil) != tt.wantErr {
				t.Errorf("bcryptHash() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotHashed != tt.wantHashed {
				t.Errorf("bcryptHash() = %v, want %v", gotHashed, tt.wantHashed)
			}
		})
	}
}

func TestMailboxPassword(t *testing.T) {
	type args struct {
		password string
		salt     []byte
	}
	tests := []struct {
		name       string
		args       args
		wantHashed string
		wantErr    bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotHashed, err := MailboxPassword(tt.args.password, tt.args.salt)
			if (err != nil) != tt.wantErr {
				t.Errorf("MailboxPassword() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotHashed != tt.wantHashed {
				t.Errorf("MailboxPassword() = %v, want %v", gotHashed, tt.wantHashed)
			}
		})
	}
}

func TestHashPassword(t *testing.T) {
	type args struct {
		authVersion int
		password    string
		userName    string
		salt        []byte
		modulus     []byte
	}
	tests := []struct {
		name    string
		args    args
		want    []byte
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := HashPassword(tt.args.authVersion, tt.args.password, tt.args.userName, tt.args.salt, tt.args.modulus)
			if (err != nil) != tt.wantErr {
				t.Errorf("HashPassword() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("HashPassword() = %v, want %v", got, tt.want)
			}
		})
	}
}
