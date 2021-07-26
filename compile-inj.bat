@ECHO OFF

cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /Tcpeekaboo-enc.cpp /link /OUT:peekaboo.exe /SUBSYSTEM:WINDOWS /MACHINE:x64