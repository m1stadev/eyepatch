<h1 align="center">
eyepatch
</h1>
<p align="center">
  <a href="https://github.com/m1stadev/eyepatch/blob/master/LICENSE">
    <image src="https://img.shields.io/github/license/m1stadev/eyepatch">
  </a>
  <a href="https://github.com/m1stadev/eyepatch/stargazers">
    <image src="https://img.shields.io/github/stars/m1stadev/eyepatch">
  </a>
  <a href="https://github.com/m1stadev/eyepatch">
    <image src="https://tokei.rs/b1/github/m1stadev/eyepatch?category=code&lang=python&style=flat">
  </a>
    <br>
</p>

<p align="center">
An *OS bootchain patching library, written in Python.</a>
</p>

## Features
- Supports 32-bit and 64-bit ARM
- Attempts to provide a Pythonic API
- Provides convenience functions, like identifying strings & cross-references

## Usage
- The `eyepatch` module provides `AArch64Patcher` and `ARMPatcher` classes for 64-bit and 32-bit patching, respectively.
- A good example for the API is the [64-bit iBoot patcher](https://github.com/m1stadev/eyepatch/tree/master/iboot).

## Requirements
- Python 3.8 or higher

## Installation
- Local installation:
    - `./install.sh`
    - Requires [Poetry](https://python-poetry.org)

## TODO
- Write documentation
- Add logging
- Add more modules for different patchers
- Add a CLI tool
- Push to PyPI

## Support

For any questions/issues you have, [open an issue](https://github.com/m1stadev/eyepatch/issues).
