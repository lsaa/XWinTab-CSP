#!/bin/bash

# winegcc produces a normal native ELF shared object that has additional
# information embedded in it that allows its exports to be loaded by Windows
# code. It will feed the '.spec' file to the confusingly named 'winebuild' tool
# which generates some assembly source code with the needed information.
winegcc -o XWinTabHelper.dll.so -O3 -shared  src/XWinTabHelper.c src/XWinTabHelper.dll.spec -lxcb -lxcb-xinput

# The actual wintab DLL is written as a Windows DLL to avoid relying on
# any wine interals. Therefore you also need the mingw cross compiler.
x86_64-w64-mingw32-gcc -O3 -shared -o wintab32.dll src/WinTab.c
