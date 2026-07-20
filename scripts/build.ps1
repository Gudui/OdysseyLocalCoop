param(
    [string]$DevkitProRoot,
    [string]$ExlaunchSource,
    [int]$Jobs = 8,
    [switch]$UseDocker,
    [string]$DockerImage = "devkitpro/devkita64@sha256:1fc388c3a0d34bd2045a6dadcb1020e069d5f876a187fd705de14b4440c00282"
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$RepoRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..")).Path
$PinnedExlaunchCommit = "f698816d6e198afb0029ad5c07d55e7017a620fe"
$ProgramId = "0100000000010000"
$Version = (Get-Content -Raw -LiteralPath (Join-Path $RepoRoot "VERSION")).Trim()
$ArtifactRoot = Join-Path $RepoRoot "artifacts"
$WorkRoot = Join-Path $ArtifactRoot "build-work\exlaunch"
$BuildOutputRoot = Join-Path $ArtifactRoot "build"
$BuildLog = Join-Path $BuildOutputRoot "build.log"
$Utf8NoBom = New-Object System.Text.UTF8Encoding($false)
$RunningOnWindows = ($env:OS -eq "Windows_NT")
$ReleaseAsFlags = "-g0 -march=armv8-a+crc+crypto -mtune=cortex-a57 -mtp=soft -fPIC -fvisibility=hidden"

function Assert-ChildPath {
    param([string]$Root, [string]$Path, [string]$Label)
    $fullRoot = [IO.Path]::GetFullPath($Root).TrimEnd('\', '/')
    $fullPath = [IO.Path]::GetFullPath($Path)
    $prefix = $fullRoot + [IO.Path]::DirectorySeparatorChar
    if (-not $fullPath.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw "$Label is outside its expected root: $fullPath"
    }
    return $fullPath
}

function Write-Json {
    param([string]$Path, $Value)
    [IO.File]::WriteAllText($Path, (($Value | ConvertTo-Json -Depth 10) + "`n"), $Utf8NoBom)
}

function Invoke-Checked {
    param([string]$FilePath, [string[]]$Arguments, [string]$Failure)
    $previousPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = "Continue"
        $nativeOutput = @(& $FilePath @Arguments 2>&1)
        $exitCode = $LASTEXITCODE
        $nativeOutput | ForEach-Object { $_.ToString() } | Tee-Object -FilePath $BuildLog -Append
    } finally {
        $ErrorActionPreference = $previousPreference
    }
    if ($exitCode -ne 0) {
        throw "$Failure (exit code $exitCode). See $BuildLog"
    }
}

function Get-SourceFingerprint {
    $records = @()
    foreach ($file in @(Get-ChildItem -LiteralPath $RepoRoot -Recurse -File | Sort-Object FullName)) {
        $relative = $file.FullName.Substring($RepoRoot.Length).TrimStart('\', '/').Replace('\', '/')
        if ($relative.StartsWith("artifacts/", [StringComparison]::OrdinalIgnoreCase) -or
            $relative.StartsWith("vendor/exlaunch/", [StringComparison]::OrdinalIgnoreCase) -or
            $relative.StartsWith(".git/", [StringComparison]::OrdinalIgnoreCase)) {
            continue
        }
        $records += "$relative $((Get-FileHash -Algorithm SHA256 -LiteralPath $file.FullName).Hash)"
    }
    $bytes = [Text.Encoding]::UTF8.GetBytes(($records -join "`n"))
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace("-", "") }
    finally { $sha.Dispose() }
}

if ($Jobs -lt 1 -or $Jobs -gt 64) { throw "Jobs must be between 1 and 64." }
if ([string]::IsNullOrWhiteSpace($ExlaunchSource)) {
    $ExlaunchSource = Join-Path $RepoRoot "vendor\exlaunch"
}
$ExlaunchSource = (Resolve-Path -LiteralPath $ExlaunchSource).Path

$sourceCommit = (& git -C $ExlaunchSource rev-parse HEAD).Trim()
if ($LASTEXITCODE -ne 0 -or $sourceCommit -ne $PinnedExlaunchCommit) {
    throw "vendor/exlaunch must be checked out at $PinnedExlaunchCommit; found '$sourceCommit'."
}

New-Item -ItemType Directory -Force -Path $ArtifactRoot | Out-Null
if (Test-Path -LiteralPath $WorkRoot) {
    $validatedWorkRoot = Assert-ChildPath -Root $ArtifactRoot -Path $WorkRoot -Label "Build worktree"
    Remove-Item -LiteralPath $validatedWorkRoot -Recurse -Force
}
if (Test-Path -LiteralPath $BuildOutputRoot) {
    $validatedOutputRoot = Assert-ChildPath -Root $ArtifactRoot -Path $BuildOutputRoot -Label "Build output"
    Remove-Item -LiteralPath $validatedOutputRoot -Recurse -Force
}
New-Item -ItemType Directory -Force -Path $BuildOutputRoot | Out-Null

Invoke-Checked -FilePath "git" -Arguments @("-c", "init.defaultBranch=main", "clone", "--quiet", "--no-hardlinks", $ExlaunchSource, $WorkRoot) -Failure "Could not create isolated ExLaunch build checkout"
Invoke-Checked -FilePath "git" -Arguments @("-C", $WorkRoot, "checkout", "--quiet", $PinnedExlaunchCommit) -Failure "Could not check out pinned ExLaunch revision"

$OverlayRoot = Join-Path $RepoRoot "patch_src\exlaunch"
foreach ($required in @("config.mk", "config.json", "source\program\main.cpp", "source\program\diagnostics_profile.cpp")) {
    if (-not (Test-Path -LiteralPath (Join-Path $OverlayRoot $required) -PathType Leaf)) {
        throw "Public release overlay is incomplete: $required"
    }
}
foreach ($file in @(Get-ChildItem -LiteralPath $OverlayRoot -Recurse -File)) {
    $relative = $file.FullName.Substring($OverlayRoot.Length).TrimStart('\', '/')
    $destination = Join-Path $WorkRoot $relative
    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $destination) | Out-Null
    Copy-Item -LiteralPath $file.FullName -Destination $destination -Force
}

$toolchainDescription = ""
if ($UseDocker) {
    if (-not (Get-Command docker -ErrorAction SilentlyContinue)) { throw "Docker is required when -UseDocker is selected." }
    $mount = "type=bind,source=$RepoRoot,target=/workspace"
    Invoke-Checked -FilePath "docker" -Arguments @(
        "run", "--rm", "--mount", $mount, "--workdir", "/workspace/artifacts/build-work/exlaunch",
        $DockerImage, "bash", "-lc", "make clean && make -j$Jobs ASFLAGS='$ReleaseAsFlags'"
    ) -Failure "Containerized ExLaunch build failed"
    $toolchainDescription = $DockerImage
} else {
    if ([string]::IsNullOrWhiteSpace($DevkitProRoot)) {
        if ($RunningOnWindows -and (Test-Path -LiteralPath "C:\devkitPro")) {
            $DevkitProRoot = "C:\devkitPro"
        } elseif (-not [string]::IsNullOrWhiteSpace($env:DEVKITPRO)) {
            $DevkitProRoot = $env:DEVKITPRO
        } else {
            throw "Specify -DevkitProRoot or set DEVKITPRO."
        }
    }

    $nativeDevkitRoot = $DevkitProRoot
    if ($RunningOnWindows -and [IO.Path]::IsPathRooted($DevkitProRoot)) {
        if (-not (Test-Path -LiteralPath (Join-Path $DevkitProRoot "libnx\switch_rules"))) {
            throw "devkitPro root does not contain libnx/switch_rules: $DevkitProRoot"
        }
        $drive = $DevkitProRoot.Substring(0, 1).ToLowerInvariant()
        $rest = $DevkitProRoot.Substring(2).Replace('\', '/').TrimStart('/')
        $nativeDevkitRoot = "/$drive/$rest"
        $compiler = Join-Path $DevkitProRoot "devkitA64\bin\aarch64-none-elf-g++.exe"
    } else {
        $compiler = Join-Path $DevkitProRoot "devkitA64/bin/aarch64-none-elf-g++"
    }
    if (-not (Test-Path -LiteralPath $compiler -PathType Leaf)) {
        throw "devkitA64 compiler not found below: $DevkitProRoot"
    }
    $previousDevkitPro = $env:DEVKITPRO
    try {
        $env:DEVKITPRO = $nativeDevkitRoot
        Invoke-Checked -FilePath "make" -Arguments @("-C", $WorkRoot, "clean") -Failure "ExLaunch clean failed"
        Invoke-Checked -FilePath "make" -Arguments @("-C", $WorkRoot, "-j$Jobs", "ASFLAGS=$ReleaseAsFlags") -Failure "ExLaunch build failed"
    } finally {
        $env:DEVKITPRO = $previousDevkitPro
    }
    $toolchainDescription = ((& $compiler --version | Select-Object -First 1) -join "").Trim()
}

$builtSubsdk = Join-Path $WorkRoot "deploy\subsdk9"
$builtElf = Join-Path $WorkRoot "exlaunch.elf"
foreach ($requiredOutput in @($builtSubsdk, $builtElf)) {
    if (-not (Test-Path -LiteralPath $requiredOutput -PathType Leaf)) { throw "Expected build output is missing: $requiredOutput" }
}
Copy-Item -LiteralPath $builtSubsdk -Destination (Join-Path $BuildOutputRoot "subsdk9") -Force
Copy-Item -LiteralPath $builtElf -Destination (Join-Path $BuildOutputRoot "exlaunch.elf") -Force

$subsdk = Get-Item -LiteralPath (Join-Path $BuildOutputRoot "subsdk9")
$elf = Get-Item -LiteralPath (Join-Path $BuildOutputRoot "exlaunch.elf")
$report = [ordered]@{
    schema_version = 1
    status = "PASS"
    version = $Version
    program_id = $ProgramId
    source_fingerprint_sha256 = Get-SourceFingerprint
    exlaunch_commit = $PinnedExlaunchCommit
    build_mode = $(if ($UseDocker) { "docker" } else { "local" })
    toolchain = $toolchainDescription
    clean_build = $true
    outputs = @(
        [ordered]@{ path = "artifacts/build/subsdk9"; bytes = $subsdk.Length; sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $subsdk.FullName).Hash },
        [ordered]@{ path = "artifacts/build/exlaunch.elf"; bytes = $elf.Length; sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $elf.FullName).Hash }
    )
}
Write-Json -Path (Join-Path $BuildOutputRoot "build-report.json") -Value $report
Write-Host "Public release build: PASS"
Write-Host "ExLaunch: $PinnedExlaunchCommit"
Write-Host "subsdk9: $($subsdk.Length) bytes, $((Get-FileHash -Algorithm SHA256 -LiteralPath $subsdk.FullName).Hash)"
