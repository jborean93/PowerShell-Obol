# AGENTS.md

Guidance for AI agents and other automation working in this repository.
Humans should read it too; it is the shortest accurate description of how the
project is built and tested.

## What this project is

Obol is a cross platform PowerShell binary module for PowerShell 7.6+ that
runs a Kerberos Key Distribution Center (KDC) endpoint built on
[Kerberos.NET](https://github.com/dotnet/Kerberos.NET).

## Repository layout

| Path | Purpose |
| --- | --- |
| `build.ps1` | Entry point for every build and test action. Wraps InvokeBuild. |
| `manifest.psd1` | Pinned versions of the PowerShell build/test modules (InvokeBuild, Pester, Microsoft.PowerShell.PlatyPS, PSResourceGet, OpenAuthenticode). |
| `global.json` | Pins the .NET SDK (10.0.x) and selects `Microsoft.Testing.Platform` as the `dotnet test` runner. |
| `Obol.slnx` | Solution file listing the `src/` projects. |
| `src/Obol/` | The PowerShell module assembly. Cmdlets live in `src/Obol/Commands/`. |
| `src/Obol.Loader/` | Tiny `AssemblyLoadContext` used by `module/Obol.psm1` to isolate the module's dependencies, like Kerberos.NET, from the host process. |
| `src/Directory.Build.props` | Shared compiler settings (nullable enabled, unsafe allowed). |
| `src/Directory.Packages.props` | Central package management. All NuGet versions live here; `.csproj` files reference packages without a `Version`. |
| `module/` | The `.psd1` manifest and `.psm1` loader script copied verbatim into the built module. `ModuleVersion` here is the single source of truth for the version. |
| `docs/en-US/Obol/` | Microsoft.PowerShell.PlatyPS markdown help (PlatyPS always nests pages under a folder named after the module). Cmdlet pages are compiled to MAML and `about_*.md` pages are copied as `about_*.help.txt` at build time. Edit the prose here; run `tools/UpdateDocs.ps1` to sync the syntax and parameter metadata. |
| `tests/*.Tests.ps1` | Pester tests that run against the built module. |
| `tests/common.ps1` | Dot-sourced by every Pester file. Imports the built module. |
| `tests/units/<Project>/` | .NET unit test projects (TUnit). Each directory is discovered and run automatically by the `Test` task. None exist yet. |
| `tools/` | Scripts used by `build.ps1`. `InvokeBuild.ps1` defines the tasks; `common.ps1` holds the `Manifest` class and helpers. `UpdateDocs.ps1` regenerates the markdown help from the built module. |
| `output/` | Git-ignored. Built module, nupkg, downloaded PowerShell versions, cached build modules, and test results all land here. Never commit or hand-edit it. |
| `scratch/` | Git-ignored. Working space for files that should not be committed: notes, logs, captures, throwaway scripts. Kept across sessions and builds. See [Scratch files](#scratch-files). |
| `CHANGELOG.md` | Update under the top (unreleased) heading for any user-visible change. |

## Prerequisites

- .NET SDK 10.0.x (see `global.json`; `rollForward` is `latestFeature`).
- PowerShell 7.6 or newer to run the module. The build scripts themselves only need 7.2.
- Network access on first run. The build script downloads the pinned
  PowerShell modules into `output/Modules` via ModuleFast, and `dotnet`
  restores NuGet packages into the usual NuGet cache. Both are cached
  afterwards.
- Global dotnet tools `dotnet-coverage` and `dotnet-reportgenerator-globaltool`
  are installed automatically by the `Test` task if missing.

## The one command to know

```powershell
pwsh -File ./build.ps1 -Configuration Debug|Release -Task Build|Test
```

`-Configuration` defaults to `Debug` and `-Task` defaults to `Build`. Before
calling a change done, run `-Task Build` followed by `-Task Test` and report
the result.

## Building

The `Build` task runs, in order: `Clean`, `BuildManaged` (`dotnet publish` of
`src/Obol` for each target framework with `-p:Version` taken from
`module/Obol.psd1`), `BuildModule` (copy `module/`), `BuildDocs` (PlatyPS
MAML), `Sign` (no-op unless the Azure Trusted Signing env vars are set), and
`Package` (produces `output/Obol.<version>.nupkg`).

The built module is at `output/Obol/<version>/` and can be imported with
`Import-Module ./output/Obol`.

Gotchas:

- Binary modules cannot be unloaded. After rebuilding, always start a fresh
  `pwsh` process before importing the module again.
- Adding a NuGet dependency means adding a `PackageVersion` to
  `src/Directory.Packages.props` and an unversioned `PackageReference` in the
  `.csproj`. Do not put versions in `.csproj` files.
- Target frameworks are read from the `<TargetFrameworks>` element of
  `src/Obol/Obol.csproj` by the build script. Keep that element on the
  first `PropertyGroup`.

## Testing

`Test` does not build. Run `Build` first.

The `Test` task runs `TestSetup` (coverage settings), `UnitTests` (every
directory under `tests/units/`, skipped when there are none), `PesterTests`
(all `tests/*.Tests.ps1` in a separate `pwsh` under `dotnet-coverage`) and
`CoverageReport`. Results land in `output/TestResults/`.

```powershell
# Test against a specific PowerShell version (downloads it if needed)
pwsh -File ./build.ps1 -Task Test -PowerShellVersion 7.6.0

# Run a single Pester file quickly against the built module
pwsh -NoProfile -Command {
    Import-Module ./output/Modules/Pester
    Invoke-Pester -Path ./tests/Start-ObolKdc.Tests.ps1 -Output Detailed
}
```

### Test conventions

- Every Pester file must start with `BeforeDiscovery { . ([IO.Path]::Combine($PSScriptRoot, 'common.ps1')) }`.
- Assertions use the Pester 6 `Should-*` commands (`Should-Be`, `Should-Throw -ExceptionMessage`, ...). The
  classic `Should -Be` form is disabled in the test run and fails.
- `build.ps1 -Task Test` instruments the built module for coverage. Do not
  run it while another `pwsh` process has `output/Obol` imported.

## Continuous integration

`.github/workflows/ci.yml` builds once on Ubuntu, uploads the nupkg, then runs
`build.ps1 -Task Test -ModuleNupkg` on PowerShell 7.6 on Windows, Linux, and
macOS. Coverage goes to Codecov. Pushes to `main` and tagged releases (`v*`)
build in `Release` configuration; pull requests build `Debug`. Releases are
signed with Azure Trusted Signing and published to the PowerShell Gallery.

## Code conventions

- C# language version is the default for the target framework (no explicit
  `LangVersion`), `Nullable` enabled, file-scoped namespaces, 4-space indent.
  Private static fields use the `s_` prefix, private instance fields
  `_camelCase`.
- Line endings are LF everywhere (`.gitattributes` sets `text=auto`). Trim
  trailing whitespace and end files with a newline.
- `.editorconfig` raises a chosen set of IDE rules to warnings, which are
  errors in `Release` and CI builds (`TreatWarningsAsErrors`). Run
  `dotnet format <project> --severity warn` on each `src/` project to fix most
  of them.
- Adding a cmdlet means also adding it to `CmdletsToExport` in
  `module/Obol.psd1` and writing `docs/en-US/Obol/<Verb-Noun>.md`.
  After building, `pwsh -File ./tools/UpdateDocs.ps1` syncs the markdown with
  the built cmdlets: it refreshes syntax and parameter metadata, adds new
  parameters and input/output types, removes deleted ones, creates pages with
  placeholders for new cmdlets and refreshes the module page, while keeping
  the existing prose.
  Fill in any `{{ ... }}` placeholders it adds. Pages for removed cmdlets
  must be deleted by hand.
- Add a line to `CHANGELOG.md` under the unreleased heading for anything a
  user would notice.

## Scratch files

Anything you generate that should not be committed goes in `scratch/` at the
repository root, not `output/` (wiped by `Clean`) or a system temp directory.
This includes investigation notes, session handoff notes, KDC/packet captures,
logs, generated `krb5.conf`/keytab files used for manual testing, and
throwaway scripts. It is git-ignored and survives builds, so it can carry
state from one session to the next.

- Create subdirectories freely, such as `scratch/logs/` or `scratch/<topic>/`,
  and use descriptive file names so a later session can find things.
- Check `scratch/` for earlier notes before starting work that may have been
  investigated before.
- Never reference `scratch/` from source, tests or build scripts. Anything that
  turns out to be needed belongs in the tracked tree.

## Debugging

- `pwsh -NoExit -File ./tools/LaunchScript.ps1` imports the built module in
  an interactive session. `.vscode/launch.json` attaches the .NET debugger to
  that script.
