param(
    [string]$Version,
    [string]$BuildRoot,
    [string]$OutputRoot
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
$RepoRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..")).Path
$ProgramId = "0100000000010000"
$ExpectedExlaunchCommit = "f698816d6e198afb0029ad5c07d55e7017a620fe"
$Utf8NoBom = New-Object System.Text.UTF8Encoding($false)
if ([string]::IsNullOrWhiteSpace($Version)) { $Version = (Get-Content -Raw -LiteralPath (Join-Path $RepoRoot "VERSION")).Trim() }
if ([string]::IsNullOrWhiteSpace($BuildRoot)) { $BuildRoot = Join-Path $RepoRoot "artifacts\build" }
if ([string]::IsNullOrWhiteSpace($OutputRoot)) { $OutputRoot = Join-Path $RepoRoot "artifacts\package" }
$BuildRoot = (Resolve-Path -LiteralPath $BuildRoot).Path

function Write-Utf8 { param([string]$Path, [string]$Content) [IO.File]::WriteAllText($Path, $Content, $Utf8NoBom) }
function Get-RelativeUnix { param([string]$Root, [string]$Path) return $Path.Substring($Root.Length).TrimStart('\', '/').Replace('\', '/') }
function Assert-ChildPath {
    param([string]$Root, [string]$Path)
    $fullRoot = [IO.Path]::GetFullPath($Root).TrimEnd('\', '/')
    $fullPath = [IO.Path]::GetFullPath($Path)
    if (-not $fullPath.StartsWith($fullRoot + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) { throw "Path escapes package output root: $fullPath" }
    return $fullPath
}

$buildReportPath = Join-Path $BuildRoot "build-report.json"
$subsdkPath = Join-Path $BuildRoot "subsdk9"
foreach ($path in @($buildReportPath, $subsdkPath)) { if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Build first; missing $path" } }
$buildReport = Get-Content -Raw -LiteralPath $buildReportPath | ConvertFrom-Json
if ($buildReport.status -ne "PASS" -or $buildReport.version -ne $Version -or $buildReport.exlaunch_commit -ne $ExpectedExlaunchCommit) { throw "Build report does not match the requested release." }

$settingsPath = Join-Path $RepoRoot "romfs\OCoop\settings.ini"
$settingsText = Get-Content -Raw -LiteralPath $settingsPath
if ($settingsText -notmatch '(?m)^competition\.coin\.enabled=0\s*$' -or $settingsText -notmatch '(?m)^competition\.moon\.enabled=0\s*$') { throw "Alpha package requires both competition modes to be disabled." }

New-Item -ItemType Directory -Force -Path $OutputRoot | Out-Null
$packageName = "OdysseyLocalCoop-$Version"
$stageRoot = Join-Path $OutputRoot $packageName
if (Test-Path -LiteralPath $stageRoot) { Remove-Item -LiteralPath (Assert-ChildPath -Root $OutputRoot -Path $stageRoot) -Recurse -Force }
$contentRoot = Join-Path $stageRoot "payload\contents\$ProgramId"
New-Item -ItemType Directory -Force -Path (Join-Path $contentRoot "exefs") | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $contentRoot "romfs\OCoop") | Out-Null
Copy-Item -LiteralPath $subsdkPath -Destination (Join-Path $contentRoot "exefs\subsdk9")
Copy-Item -LiteralPath $settingsPath -Destination (Join-Path $contentRoot "romfs\OCoop\settings.ini")
Copy-Item -LiteralPath (Join-Path $RepoRoot "scripts\install.ps1") -Destination (Join-Path $stageRoot "install.ps1")

$payloadRecords = @()
foreach ($file in @(Get-ChildItem -LiteralPath (Join-Path $stageRoot "payload") -Recurse -File | Sort-Object FullName)) {
    $payloadRecords += [ordered]@{ path = Get-RelativeUnix -Root $stageRoot -Path $file.FullName; bytes = $file.Length; sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $file.FullName).Hash }
}
$packageManifest = [ordered]@{
    schema_version = 1
    name = "Odyssey Local Co-op"
    version = $Version
    program_id = $ProgramId
    primary_target = "Ryujinx"
    atmosphere_support = "experimental"
    exlaunch_commit = $ExpectedExlaunchCommit
    competition_hud = "omitted"
    competition_enabled = $false
    files = $payloadRecords
}
$manifestPath = Join-Path $stageRoot "PACKAGE_MANIFEST.json"
Write-Utf8 -Path $manifestPath -Content (($packageManifest | ConvertTo-Json -Depth 8) + "`n")

$checksumFiles = @(Get-ChildItem -LiteralPath $stageRoot -Recurse -File | Where-Object { $_.Name -ne "CHECKSUMS.txt" } | Sort-Object FullName)
$checksumLines = @($checksumFiles | ForEach-Object { "$((Get-FileHash -Algorithm SHA256 -LiteralPath $_.FullName).Hash) *$(Get-RelativeUnix -Root $stageRoot -Path $_.FullName)" })
Write-Utf8 -Path (Join-Path $stageRoot "CHECKSUMS.txt") -Content (($checksumLines -join "`n") + "`n")

$zipPath = Join-Path $OutputRoot "$packageName.zip"
if (Test-Path -LiteralPath $zipPath) { Remove-Item -LiteralPath (Assert-ChildPath -Root $OutputRoot -Path $zipPath) -Force }
Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem
$zip = [IO.Compression.ZipFile]::Open($zipPath, [IO.Compression.ZipArchiveMode]::Create)
try {
    foreach ($file in @(Get-ChildItem -LiteralPath $stageRoot -Recurse -File | Sort-Object FullName)) {
        $entryName = "$packageName/$(Get-RelativeUnix -Root $stageRoot -Path $file.FullName)"
        $entry = $zip.CreateEntry($entryName, [IO.Compression.CompressionLevel]::Optimal)
        $entry.LastWriteTime = [DateTimeOffset]::new(2020, 1, 1, 0, 0, 0, [TimeSpan]::Zero)
        $input = [IO.File]::OpenRead($file.FullName)
        $output = $entry.Open()
        try { $input.CopyTo($output) } finally { $output.Dispose(); $input.Dispose() }
    }
} finally { $zip.Dispose() }

$zipHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $zipPath).Hash
Write-Utf8 -Path "$zipPath.sha256" -Content "$zipHash *$([IO.Path]::GetFileName($zipPath))`n"
$report = [ordered]@{
    schema_version = 1; status = "PASS"; version = $Version; program_id = $ProgramId
    zip = [ordered]@{ path = $zipPath; bytes = (Get-Item -LiteralPath $zipPath).Length; sha256 = $zipHash }
    payload_files = $payloadRecords; competition_hud = "omitted"; competition_enabled = $false
}
Write-Utf8 -Path (Join-Path $OutputRoot "package-report.json") -Content (($report | ConvertTo-Json -Depth 8) + "`n")
Write-Host "Public release package: PASS"
Write-Host "$zipPath"
Write-Host "SHA256 $zipHash"
