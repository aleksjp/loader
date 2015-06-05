About
=====

DLL Injection using Remote Thread

Overview
=====

Create a process in a suspended state and inject the DLL to target process address space using CreateRemoteThread() Win API routine. The DLL itself is extracted from resource.

Build
=====

Open the 'Loader.sln' file in Visual Studio C++ and build the solution in Release mode to make loader.exe.

Usage
=====

Copy loader.exe to the target directory.
Can be tested with IW5 MP 1.4 build 382

