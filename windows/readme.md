# go-srp windows

* go to cshared folder and run the bat script to compile 32 bits and 64 bits c-shared libs. output file is in bin folder
* The cshared bin folder contains the prebuild files

* win_wrapper contains the c# wrapper code and the example code. try to open the testgo.sln 
* Localnugets contains prebuild nupkg file
* Srp folder is the c-shared C# wrapper project. you need copy the c-shared DLLs to this folder
* the build.bat will generate the nupkg file after you archive and you need to modify Srp.nuspec to update the version number

* SrpExample is the example console project. it contains the simple code. the reference could be the project or the nuget. you can change it in the sln.

* SrpTests is the unit test project

* TestGO not in used
