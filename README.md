# Obol

[![Test workflow](https://github.com/jborean93/Obol/workflows/Test%20Obol/badge.svg)](https://github.com/jborean93/Obol/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/jborean93/Obol/branch/main/graph/badge.svg)](https://codecov.io/gh/jborean93/Obol)
[![PowerShell Gallery](https://img.shields.io/powershellgallery/dt/Obol.svg)](https://www.powershellgallery.com/packages/Obol)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/jborean93/Obol/blob/main/LICENSE)

PowerShell module that runs a Kerberos KDC endpoint based on [Kerberos.NET](https://github.com/dotnet/Kerberos.NET).

See [about_Obol](docs/en-US/Obol/about_Obol.md) for more details.

> [!WARNING]
> Obol is designed for testing and learning purposes.
> It should not be considered a secure solution for production environments and must not be used as the KDC for a real realm.

## Documentation

Documentation for this module and details on the cmdlets included can be found [here](docs/en-US/Obol/Obol.md).

## Requirements

These cmdlets have the following requirements

* PowerShell v7.6 or newer

## Installing

The easiest way to install this module is through
[PowerShellGet](https://docs.microsoft.com/en-us/powershell/gallery/overview).

You can install this module by running;

```powershell
# Install for only the current user
Install-PSResource -Name Obol -Scope CurrentUser

# Install for all users
Install-PSResource -Name Obol -Scope AllUsers
```

## Contributing

Contributing is quite easy, fork this repo and submit a pull request with the changes.
To build this module run `.\build.ps1 -Task Build` in PowerShell.
To test a build run `.\build.ps1 -Task Test` in PowerShell.
This script will ensure all dependencies are installed before running the test suite.
