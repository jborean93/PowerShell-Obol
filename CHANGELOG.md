# Changelog for Obol

## v0.1.0 - TBD

+ Initial version of the `Obol` module
+ Added `Start-ObolKdc`, `Get-ObolKdc` and `Stop-ObolKdc` to run a Kerberos KDC in the current PowerShell process
+ Added `New-ObolPrincipal`, `Get-ObolPrincipal`, `Set-ObolPrincipal` and `Remove-ObolPrincipal` to manage the principals of a KDC
+ Added `New-ObolPrincipalSetting` to define the settings of a principal for `Start-ObolKdc -Principal` and `New-ObolPrincipal -Setting`
