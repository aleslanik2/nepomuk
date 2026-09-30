<#
.SYNOPSIS
    nepomuk installer for Windows (PowerShell 5.1+).

.DESCRIPTION
    Downloads nepomuk-<tag>-<target>.tar.gz from the GitHub release and installs nepomuk.exe
    only after its SHA-256 matches SHA256SUMS and SHA256SUMS carries a valid release signature
    (ssh-keygen -Y verify, namespace "nepomuk-release"), or after it matches -Sha256.

    For a private repository set GH_TOKEN / GITHUB_TOKEN and have the GitHub CLI (gh) installed.

.EXAMPLE
    irm https://raw.githubusercontent.com/aleslanik2/nepomuk/main/install.ps1 | iex

.EXAMPLE
    ./install.ps1 -Version v0.1.0 -Sha256 <published SHA-256>

.EXAMPLE
    ./install.ps1 -System     # for all users: Program Files\nepomuk and the system PATH (as administrator)

.EXAMPLE
    ./install.ps1 -Gui        # the CLI and the desktop app (its installer runs silently)
#>
[CmdletBinding()]
param(
    [string]$Version = $(if ($env:NEPOMUK_VERSION) { $env:NEPOMUK_VERSION } else { 'latest' }),
    [string]$Dir = $env:NEPOMUK_INSTALL_DIR,
    [string]$Sha256 = $env:NEPOMUK_SHA256,
    [string]$Signers,
    [string]$BaseUrl = $env:NEPOMUK_BASE_URL,
    [switch]$NoPath,
    [switch]$Gui,
    [switch]$System
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$Repo = 'aleslanik2/nepomuk'
$Namespace = 'nepomuk-release'

# Public keys allowed to sign releases (allowed_signers format); keep in sync with install.sh.
$ReleaseSigners = @'
release@nepomuk ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIClyxfJb2+KHFDtD0JbFya1aAdTl7zrawzY7NA7cH2Uo
'@

function Say([string]$m) { Write-Host "nepomuk-install: $m" }
function Die([string]$m) { throw "nepomuk-install: error: $m" }

[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

# ---------------------------------------------------------------- Platform

$arch = if ($env:PROCESSOR_ARCHITEW6432) { $env:PROCESSOR_ARCHITEW6432 } else { $env:PROCESSOR_ARCHITECTURE }
switch ($arch) {
    'AMD64' { $Target = 'x86_64-pc-windows-msvc' }
    'ARM64' { $Target = 'aarch64-pc-windows-msvc' }
    default { Die "unsupported architecture: $arch" }
}
if ($System) {
    $admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $admin) { Die 'installing for all users needs an administrator PowerShell' }
    if (-not $Dir) { $Dir = Join-Path $env:ProgramFiles 'nepomuk' }
}
if (-not $Dir) { $Dir = Join-Path $env:LOCALAPPDATA 'nepomuk\bin' }

$token = if ($env:GH_TOKEN) { $env:GH_TOKEN } elseif ($env:GITHUB_TOKEN) { $env:GITHUB_TOKEN } else { $null }
if ($BaseUrl -match '^file://') { $BaseUrl = ([Uri]$BaseUrl).LocalPath }
$useGh = (-not $BaseUrl) -and $token -and (Get-Command gh -ErrorAction SilentlyContinue)

$work = Join-Path ([IO.Path]::GetTempPath()) ("nepomuk-install-" + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $work | Out-Null

function Fetch([string]$name) {
    $dest = Join-Path $work $name
    if ($useGh) {
        $env:GH_TOKEN = $token
        & gh release download $Version -R $Repo -p $name -D $work --clobber
        if ($LASTEXITCODE -ne 0) { Die "download failed: $name" }
    } elseif ($BaseUrl -and (Test-Path -LiteralPath $BaseUrl -PathType Container)) {
        Copy-Item -LiteralPath (Join-Path $BaseUrl $name) -Destination $dest
    } else {
        $base = if ($BaseUrl) { $BaseUrl.TrimEnd('/') } else { "https://github.com/$Repo/releases/download/$Version" }
        try { Invoke-WebRequest -UseBasicParsing -Uri "$base/$name" -OutFile $dest } catch { Die "download failed: $base/$name" }
    }
    return $dest
}

function Resolve-Latest {
    if ($useGh) {
        $env:GH_TOKEN = $token
        $t = & gh release view -R $Repo --json tagName -q .tagName
        if ($LASTEXITCODE -ne 0 -or -not $t) { Die "no release found in $Repo" }
        return $t.Trim()
    }
    $r = Invoke-WebRequest -UseBasicParsing -Uri "https://github.com/$Repo/releases/latest"
    $uri = if ($r.BaseResponse.ResponseUri) { $r.BaseResponse.ResponseUri } else { $r.BaseResponse.RequestMessage.RequestUri }
    $t = $uri.AbsoluteUri.TrimEnd('/').Split('/')[-1]
    if (-not $t -or $t -eq 'latest' -or $t -eq 'releases') { Die "no release found in $Repo" }
    return $t
}

# Downloads a release asset and verifies it (pinned hash, or signed SHA256SUMS).
function Get-Verified([string]$asset) {
    Say "downloading $asset"
    $archive = Fetch $asset
    $actual = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()

    if ($Sha256) {
        if ($actual -ne $Sha256.ToLowerInvariant()) { Die "SHA-256 mismatch: expected $Sha256, got $actual" }
        Say 'SHA-256 matches the pinned value'
    } else {
        $sums = Fetch 'SHA256SUMS'
        $sig = Fetch 'SHA256SUMS.sig'
        $allowed = Join-Path $work 'allowed_signers'
        $keys = if ($Signers) { Get-Content -LiteralPath $Signers } else { $ReleaseSigners -split "`r?`n" }
        $keys = @($keys | Where-Object { $_.Trim() })
        if ($keys.Count -eq 0) { Die 'no release signing key configured; pin the archive hash with -Sha256' }
        [IO.File]::WriteAllText($allowed, (($keys -join "`n") + "`n"))
        $sshKeygen = Get-Command ssh-keygen -ErrorAction SilentlyContinue
        if (-not $sshKeygen) { Die 'ssh-keygen (OpenSSH client) is required to verify the signature; or pin -Sha256' }
        $principal = ($keys[0] -split '\s+')[0]
        # cmd.exe redirection passes the file byte for byte (PowerShell 5 pipes re-encode text).
        & cmd.exe /d /c "`"$($sshKeygen.Source)`" -Y verify -f `"$allowed`" -I $principal -n $Namespace -s `"$sig`" < `"$sums`" >NUL 2>&1"
        if ($LASTEXITCODE -ne 0) { Die 'invalid signature on SHA256SUMS' }
        $expected = $null
        foreach ($line in Get-Content -LiteralPath $sums) {
            $parts = $line -split '\s+', 2
            if ($parts.Count -eq 2 -and $parts[1].TrimStart('*') -eq $asset) { $expected = $parts[0].ToLowerInvariant() }
        }
        if (-not $expected) { Die "$asset is not listed in SHA256SUMS" }
        if ($actual -ne $expected) { Die "SHA-256 mismatch for $asset" }
        Say 'signature and SHA-256 verified'
    }
    return $archive
}

try {
    if ($Version -eq 'latest') { $Version = Resolve-Latest }

    $asset = "nepomuk-$Version-$Target.tar.gz"
    $archive = Get-Verified $asset

    $extract = Join-Path $work 'x'
    New-Item -ItemType Directory -Path $extract | Out-Null
    & tar.exe -xzf $archive -C $extract
    if ($LASTEXITCODE -ne 0) { Die 'cannot extract the archive (tar.exe is part of Windows 10 1803+)' }
    $exe = Get-ChildItem -LiteralPath $extract -Recurse -Filter 'nepomuk.exe' | Select-Object -First 1
    if (-not $exe) { Die "nepomuk.exe not found in $asset" }

    New-Item -ItemType Directory -Force -Path $Dir | Out-Null
    $installed = Join-Path $Dir 'nepomuk.exe'
    $tmp = Join-Path $Dir ".nepomuk.exe.tmp"
    Copy-Item -LiteralPath $exe.FullName -Destination $tmp -Force
    Move-Item -LiteralPath $tmp -Destination $installed -Force

    $v = & $installed version
    if ($LASTEXITCODE -ne 0) { Die "the installed binary does not run: $installed" }
    Say "installed $($v | Select-Object -First 1) to $installed"

    if ($env:GITHUB_PATH) {
        Add-Content -LiteralPath $env:GITHUB_PATH -Value $Dir
    } elseif (-not $NoPath) {
        $scope = if ($System) { 'Machine' } else { 'User' }
        $current = [Environment]::GetEnvironmentVariable('Path', $scope)
        $parts = @($current -split ';' | Where-Object { $_ })
        if ($parts -notcontains $Dir) {
            [Environment]::SetEnvironmentVariable('Path', (($parts + $Dir) -join ';'), $scope)
            $env:Path = "$env:Path;$Dir"
            Say "added $Dir to the $($scope.ToLower()) PATH (open a new terminal)"
        }
    }

    # The desktop app comes in addition to the CLI.
    if ($Gui) {
        # ARM64 Windows runs the x86_64 app through emulation.
        $installer = Get-Verified "nepomuk-gui-$Version-x86_64-pc-windows-msvc.exe"
        Say 'running the installer'
        # /AllUsers is the NSIS installer's per-machine mode.
        $installArgs = if ($System) { @('/S', '/AllUsers') } else { @('/S') }
        $p = Start-Process -FilePath $installer -ArgumentList $installArgs -Wait -PassThru
        if ($p.ExitCode -ne 0) { Die "the installer failed with code $($p.ExitCode)" }
        Say 'installed the nepomuk desktop app; start it from the Start menu'
    }
} finally {
    Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
}
