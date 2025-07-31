XWinTab: tablet input for Rebelle running on Wine.
==================================================

Wine's built-in implementation of wintab does not work with Rebelle, CSP and Drawpile. XWinTab works around this by having the applications load it instead and creates its own connection to X11.

This software is experimental and has not been tested extensively. Also, X11 exclusive.

Requirements
------------
A Wacom compatible tablet that works in native Linux applications. The tablet needs to have a device with the word "stylus" in its name.

This uses the ``libxcb.so.1`` and ``libxcb-xinput.so.0`` libraries. On Debian/Ubuntu distributions, these can be obtained by installing the ``libxcb-xinput0`` package.

To build it yourself, you will also need to install the following packages: ``libxcb-xinput-dev``, ``wine64-tools``, and ``gcc-mingw-w64``.

Installation
------------
1. With Rebelle already installed, copy **BOTH** ``wintab32.dll`` and ``XWinTabHelper.dll.so`` into the installation directory (the one with the exe).
2. Add a DLL Override for ``wintab32.dll`` (needed for it to be loaded instead of the built-in one).
3. Configure Rebelle to use the ``Wacom Compatible (wintab)`` option.

Additional
----------
This software is provided without warranty of any kind (see ``LICENSE``) and is used at your own risk.
