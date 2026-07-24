param(
    [string]$BuildRoot,
    [string]$PackageRoot,
    [string]$ReportPath
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
$RepoRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..")).Path
$ExpectedVersion = (Get-Content -Raw -LiteralPath (Join-Path $RepoRoot "VERSION")).Trim()
$ExpectedCommit = "f698816d6e198afb0029ad5c07d55e7017a620fe"
$ExpectedHudSha256 = "EE828417DE626FFB2C2A861EC247223654D3784CF9D754ED04691EE9F871C4E8"
$ProgramId = "0100000000010000"
$ExpectedDockerImage = "devkitpro/devkita64@sha256:1fc388c3a0d34bd2045a6dadcb1020e069d5f876a187fd705de14b4440c00282"
if ([string]::IsNullOrWhiteSpace($BuildRoot)) { $BuildRoot = Join-Path $RepoRoot "artifacts\build" }
if ([string]::IsNullOrWhiteSpace($PackageRoot)) { $PackageRoot = Join-Path $RepoRoot "artifacts\package" }
if ([string]::IsNullOrWhiteSpace($ReportPath)) { $ReportPath = Join-Path $RepoRoot "artifacts\verify\verification-report.json" }
$VerifyRoot = Split-Path -Parent $ReportPath
$Utf8NoBom = New-Object Text.UTF8Encoding($false)

$buildReport = Get-Content -Raw -LiteralPath (Join-Path $BuildRoot "build-report.json") | ConvertFrom-Json
if ($buildReport.status -ne "PASS" -or $buildReport.version -ne $ExpectedVersion -or $buildReport.program_id -ne $ProgramId -or $buildReport.exlaunch_commit -ne $ExpectedCommit -or -not $buildReport.clean_build) { throw "Build report failed release identity checks." }
$subsdk = Join-Path $BuildRoot "subsdk9"
$npdm = Join-Path $BuildRoot "main.npdm"
$elf = Join-Path $BuildRoot "exlaunch.elf"
foreach ($path in @($subsdk, $npdm, $elf)) { if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Missing build output: $path" } }
$reportedSubsdk = @($buildReport.outputs | Where-Object { $_.path -eq "artifacts/build/subsdk9" })
if ($reportedSubsdk.Count -ne 1 -or (Get-FileHash -Algorithm SHA256 -LiteralPath $subsdk).Hash -ne $reportedSubsdk[0].sha256) { throw "Built subsdk9 does not match its report." }
$reportedNpdm = @($buildReport.outputs | Where-Object { $_.path -eq "artifacts/build/main.npdm" })
if ($reportedNpdm.Count -ne 1 -or (Get-FileHash -Algorithm SHA256 -LiteralPath $npdm).Hash -ne $reportedNpdm[0].sha256) { throw "Built main.npdm does not match its report." }

$workflowText = Get-Content -Raw -LiteralPath (Join-Path $RepoRoot ".github\workflows\build.yml")
$buildScriptText = Get-Content -Raw -LiteralPath (Join-Path $RepoRoot "scripts\build.ps1")
if ($workflowText -notmatch 'actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5' -or
    $workflowText -notmatch 'actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02' -or
    $workflowText -notmatch '\./scripts/build\.ps1 -UseDocker' -or
    -not $buildScriptText.Contains($ExpectedDockerImage)) {
    throw "CI workflow or container dependency is not pinned as expected."
}

$forbiddenBinaryPatterns = @(
    'DIAG[-_][0-9]{4}',
    '\b(?:EVD|FND|ATT|HYP)-[A-Z0-9]',
    '\b(?:META-)?METHOD-[0-9]{3}\b',
    '(?i)[A-Z]:[\\/]+Users[\\/]+',
    '(?i)MarioOdessey|ocoop_release'
)
foreach ($binary in @($elf, $subsdk)) {
    $binaryText = [Text.Encoding]::ASCII.GetString([IO.File]::ReadAllBytes($binary))
    foreach ($pattern in $forbiddenBinaryPatterns) {
        if ([regex]::IsMatch($binaryText, $pattern)) { throw "Release binary $([IO.Path]::GetFileName($binary)) contains forbidden pattern: $pattern" }
    }
}

$packageReport = Get-Content -Raw -LiteralPath (Join-Path $PackageRoot "package-report.json") | ConvertFrom-Json
if ($packageReport.status -ne "PASS" -or $packageReport.version -ne $ExpectedVersion -or $packageReport.program_id -ne $ProgramId -or $packageReport.competition_hud -ne "included" -or -not $packageReport.competition_available -or $packageReport.competition_enabled -or $packageReport.competition_hud_sha256 -ne $ExpectedHudSha256) { throw "Package report failed release identity checks." }
$zipPath = [string]$packageReport.zip.path
if (-not (Test-Path -LiteralPath $zipPath -PathType Leaf) -or (Get-FileHash -Algorithm SHA256 -LiteralPath $zipPath).Hash -ne $packageReport.zip.sha256) { throw "ZIP hash does not match its package report." }
$sidecar = Get-Content -Raw -LiteralPath "$zipPath.sha256"
if ($sidecar -notmatch '^([0-9A-Fa-f]{64}) \*') { throw "ZIP checksum sidecar is malformed." }
if ($Matches[1].ToUpperInvariant() -ne $packageReport.zip.sha256) { throw "ZIP checksum sidecar does not match." }

$extractRoot = Join-Path $VerifyRoot "unpacked"
if (Test-Path -LiteralPath $extractRoot) { Remove-Item -LiteralPath $extractRoot -Recurse -Force }
New-Item -ItemType Directory -Force -Path $extractRoot | Out-Null
Expand-Archive -LiteralPath $zipPath -DestinationPath $extractRoot
$top = @(Get-ChildItem -LiteralPath $extractRoot -Directory)
if ($top.Count -ne 1) { throw "ZIP must contain exactly one top-level package directory." }
$expandedPackage = $top[0].FullName
$manifest = Get-Content -Raw -LiteralPath (Join-Path $expandedPackage "PACKAGE_MANIFEST.json") | ConvertFrom-Json
if ($manifest.version -ne $ExpectedVersion -or $manifest.program_id -ne $ProgramId -or $manifest.exlaunch_commit -ne $ExpectedCommit -or $manifest.competition_hud -ne "included" -or -not $manifest.competition_available -or $manifest.competition_enabled -or $manifest.competition_hud_sha256 -ne $ExpectedHudSha256) { throw "Expanded package manifest failed identity checks." }

$checksumLines = @(Get-Content -LiteralPath (Join-Path $expandedPackage "CHECKSUMS.txt"))
foreach ($line in $checksumLines) {
    if ($line -notmatch '^([0-9A-Fa-f]{64}) \*(.+)$') { throw "Malformed package checksum: $line" }
    $path = Join-Path $expandedPackage $Matches[2].Replace('/', [IO.Path]::DirectorySeparatorChar)
    if (-not (Test-Path -LiteralPath $path -PathType Leaf) -or (Get-FileHash -Algorithm SHA256 -LiteralPath $path).Hash -ne $Matches[1].ToUpperInvariant()) { throw "Package checksum mismatch: $($Matches[2])" }
}
$expandedFiles = @(Get-ChildItem -LiteralPath $expandedPackage -Recurse -File)
$expandedHud = Join-Path $expandedPackage "payload\contents\$ProgramId\romfs\LayoutData\OCoopScoreBoard.szs"
if (-not (Test-Path -LiteralPath $expandedHud -PathType Leaf) -or (Get-FileHash -Algorithm SHA256 -LiteralPath $expandedHud).Hash -ne $ExpectedHudSha256) { throw "Packaged competition HUD is missing or has the wrong hash." }
if (@($expandedFiles | Where-Object { $_.Extension -eq '.xdelta' }).Count -ne 0) { throw "Direct-bundle package must not contain an obsolete HUD patch." }
$expandedSettings = Get-Content -Raw -LiteralPath (Join-Path $expandedPackage "payload\contents\$ProgramId\romfs\OCoop\settings.ini")
if ($expandedSettings -notmatch '(?m)^competition\.coin\.enabled=0\s*$' -or $expandedSettings -notmatch '(?m)^competition\.moon\.enabled=0\s*$') { throw "Packaged competition settings are not disabled." }

$installRoot = Join-Path $VerifyRoot "install-tests"
if (Test-Path -LiteralPath $installRoot) { Remove-Item -LiteralPath $installRoot -Recurse -Force }
& (Join-Path $expandedPackage "install.ps1") -Target Ryujinx -ContentsRoot (Join-Path $installRoot "ryujinx\contents")
& (Join-Path $expandedPackage "install.ps1") -Target Atmosphere -ContentsRoot (Join-Path $installRoot "atmosphere\contents")
foreach ($target in @("ryujinx", "atmosphere")) {
    $installedSubsdk = Join-Path $installRoot "$target\contents\$ProgramId\exefs\subsdk9"
    if ((Get-FileHash -Algorithm SHA256 -LiteralPath $installedSubsdk).Hash -ne (Get-FileHash -Algorithm SHA256 -LiteralPath $subsdk).Hash) { throw "$target installer test produced the wrong subsdk9." }
    $installedNpdm = Join-Path $installRoot "$target\contents\$ProgramId\exefs\main.npdm"
    if (-not (Test-Path -LiteralPath $installedNpdm -PathType Leaf) -or (Get-FileHash -Algorithm SHA256 -LiteralPath $installedNpdm).Hash -ne (Get-FileHash -Algorithm SHA256 -LiteralPath $npdm).Hash) { throw "$target installer test produced the wrong main.npdm." }
    $installedHud = Join-Path $installRoot "$target\contents\$ProgramId\romfs\LayoutData\OCoopScoreBoard.szs"
    if (-not (Test-Path -LiteralPath $installedHud -PathType Leaf) -or (Get-FileHash -Algorithm SHA256 -LiteralPath $installedHud).Hash -ne $ExpectedHudSha256) { throw "$target installer test produced the wrong competition HUD." }
}

$report = [ordered]@{
    schema_version = 1; status = "PASS"; version = $ExpectedVersion; program_id = $ProgramId
    exlaunch_commit = $ExpectedCommit; release_elf_forbidden_findings = 0
    ci_workflow_pins = "PASS"; ci_equivalent_public_tree_build = "PASS"; hosted_actions_execution = "pending Gate I public staging"
    zip_sha256 = [string]$packageReport.zip.sha256; package_file_count = $expandedFiles.Count
    hud_archive_present = $true; hud_archive_sha256 = $ExpectedHudSha256; competition_available = $true; competition_enabled = $false
    installer_tests = @([ordered]@{ target = "Ryujinx"; status = "PASS" }, [ordered]@{ target = "Atmosphere"; status = "PASS"; support = "experimental" })
}
New-Item -ItemType Directory -Force -Path $VerifyRoot | Out-Null
[IO.File]::WriteAllText($ReportPath, (($report | ConvertTo-Json -Depth 8) + "`n"), $Utf8NoBom)
Write-Host "Public release verification: PASS"
Write-Host "Report: $ReportPath"
