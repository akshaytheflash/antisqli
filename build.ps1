<#
.SYNOPSIS
    Build, test and package sqli on Windows.

.DESCRIPTION
    Native PowerShell equivalent of the Makefile. Requires the Go toolchain.

.EXAMPLE
    .\build.ps1 build
    .\build.ps1 test
    .\build.ps1 cross -Version 1.2.0

.PARAMETER Target
    build (default), test, test-short, race, vet, fmt, check, cross, clean, demo, help.

.PARAMETER Version
    Semantic version embedded in the binary. Defaults to 1.0.0.
#>
[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [ValidateSet('build', 'test', 'test-short', 'race', 'vet', 'fmt', 'check', 'cross', 'clean', 'demo', 'help')]
    [string]$Target = 'build',

    [string]$Version = '1.0.0'
)

$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot

$binDir = Join-Path $PSScriptRoot 'bin'
$distDir = Join-Path $PSScriptRoot 'dist'
$cmd = './cmd/sqli'
$vulnCmd = './cmd/vulnserver'

$commit = 'dev'
try {
    $c = git rev-parse --short HEAD 2>$null
    if ($LASTEXITCODE -eq 0 -and $c) { $commit = $c.Trim() }
} catch { }

$date = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
$ldflags = "-s -w " +
    "-X github.com/akshaytheflash/antisqli/internal/version.Version=$Version " +
    "-X github.com/akshaytheflash/antisqli/internal/version.Commit=$commit " +
    "-X github.com/akshaytheflash/antisqli/internal/version.Date=$date"

function New-Dir([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -ItemType Directory -Path $Path | Out-Null
    }
}

function Invoke-Go {
    param([string[]]$GoArgs)
    & go @GoArgs
    if ($LASTEXITCODE -ne 0) {
        throw "go $($GoArgs -join ' ') failed with exit code $LASTEXITCODE"
    }
}

switch ($Target) {
    'build' {
        New-Dir $binDir
        Invoke-Go @('build', '-trimpath', '-ldflags', $ldflags, '-o', (Join-Path $binDir 'sqli.exe'), $cmd)
        Write-Host "built bin\sqli.exe" -ForegroundColor Green
    }
    'test' {
        Invoke-Go @('test', '-count=1', './...')
    }
    'test-short' {
        Invoke-Go @('test', '-count=1', '-short', './...')
    }
    'race' {
        Invoke-Go @('test', '-count=1', '-race', './...')
    }
    'vet' {
        Invoke-Go @('vet', './...')
    }
    'fmt' {
        Invoke-Go @('fmt', './...')
    }
    'check' {
        $unformatted = & gofmt -l .
        if ($unformatted) {
            Write-Host "unformatted files:" -ForegroundColor Red
            $unformatted | ForEach-Object { Write-Host "  $_" }
            throw 'gofmt check failed'
        }
        Invoke-Go @('vet', './...')
        Invoke-Go @('test', '-count=1', './...')
        Write-Host 'check passed' -ForegroundColor Green
    }
    'cross' {
        New-Dir $distDir
        $targets = @(
            @{ OS = 'linux'; Arch = 'amd64'; Ext = '' },
            @{ OS = 'linux'; Arch = 'arm64'; Ext = '' },
            @{ OS = 'darwin'; Arch = 'amd64'; Ext = '' },
            @{ OS = 'darwin'; Arch = 'arm64'; Ext = '' },
            @{ OS = 'windows'; Arch = 'amd64'; Ext = '.exe' },
            @{ OS = 'windows'; Arch = 'arm64'; Ext = '.exe' }
        )
        foreach ($t in $targets) {
            $out = Join-Path $distDir ("sqli_{0}_{1}{2}" -f $t.OS, $t.Arch, $t.Ext)
            Write-Host "building $out"
            $env:GOOS = $t.OS
            $env:GOARCH = $t.Arch
            $env:CGO_ENABLED = '0'
            try {
                Invoke-Go @('build', '-trimpath', '-ldflags', $ldflags, '-o', $out, $cmd)
            } finally {
                Remove-Item Env:\GOOS, Env:\GOARCH, Env:\CGO_ENABLED -ErrorAction SilentlyContinue
            }
        }
        Write-Host "release binaries in dist\" -ForegroundColor Green
    }
    'clean' {
        foreach ($p in @($binDir, $distDir)) {
            if (Test-Path -LiteralPath $p) { Remove-Item -Recurse -Force -LiteralPath $p }
        }
        Invoke-Go @('clean', '-cache', '-testcache')
        Write-Host 'cleaned'
    }
    'demo' {
        New-Dir $binDir
        Invoke-Go @('build', '-trimpath', '-o', (Join-Path $binDir 'vulnserver.exe'), $vulnCmd)
        Write-Host 'starting demo app on http://127.0.0.1:8099'
        Write-Host 'scan it with: .\bin\sqli.exe scan -u "http://127.0.0.1:8099/item?id=1" --authorized'
        & (Join-Path $binDir 'vulnserver.exe')
    }
    'help' {
        Write-Host 'usage: .\build.ps1 <target> [-Version 1.0.0]'
        Write-Host ''
        Write-Host 'targets:'
        Write-Host '  build        compile bin\sqli.exe'
        Write-Host '  test         run all tests'
        Write-Host '  test-short   skip timing tests'
        Write-Host '  race         run tests with the race detector'
        Write-Host '  vet          go vet ./...'
        Write-Host '  fmt          gofmt the tree'
        Write-Host '  check        gofmt check + vet + test'
        Write-Host '  cross        build linux/darwin/windows binaries into dist\'
        Write-Host '  clean        remove build artifacts'
        Write-Host '  demo         run the vulnerable demo app'
    }
}
