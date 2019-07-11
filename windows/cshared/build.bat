@echo off

rd bin /s /q
mkdir bin\32
mkdir bin\64

set fn=GoSrp
set gn=main.go
set dn=GoSrp.def

set tmp=%path%
::enable cgo for cross plantforms
set CGO_ENABLED=1

::set gcc to 32 bits and need to make sure the env set the gcc path
set GOARCH=386
::complie 32 bits c-shared dll
go build -buildmode=c-shared -v -ldflags="-s -w" -o bin\32\%fn%.dll %gn%

set GOARCH=amd64
go build -buildmode=c-shared -v -ldflags="-s -w" -o bin\64\%fn%.dll %gn%

::xcopy /Y bin\32\%fn%.dll C:\Workspace-VS\Srp\%fn%.dll

::xcopy /Y bin\32\%fn%.dll C:\Workspace-VS\Srp\lib\32\%fn%.dll

::xcopy /Y bin\64\%fn%.dll C:\Workspace-VS\Srp\lib\64\%fn%.dll