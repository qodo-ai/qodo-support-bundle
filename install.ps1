[CmdletBinding()]
param(
    [string]$Version,
    [string]$SourceDir,
    [string]$InstallDir,
    [switch]$AddToPath
)

$ErrorActionPreference = 'Stop'
$script:QodoScoutBaseUrl = 'https://get.qodo.ai/support-bundle'

function Assert-QodoScoutVersion {
    param([Parameter(Mandatory)][string]$Value)

    if ($Value -notmatch '^[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z][0-9A-Za-z.-]*)?$') {
        throw "invalid version: $Value"
    }
}

function Get-QodoScoutReleaseBaseUrl {
    param([Parameter(Mandatory)][string]$Version)

    Assert-QodoScoutVersion -Value $Version
    return "$script:QodoScoutBaseUrl/releases/$Version"
}

function Get-QodoScoutAssetUrl {
    param(
        [Parameter(Mandatory)][string]$Version,
        [Parameter(Mandatory)][string]$AssetName
    )

    return "$(Get-QodoScoutReleaseBaseUrl -Version $Version)/$AssetName"
}

function Resolve-QodoScoutAsset {
    param(
        [Parameter(Mandatory)][string]$OperatingSystem,
        [Parameter(Mandatory)][string]$Architecture
    )

    if ($OperatingSystem -eq 'windows' -and $Architecture -eq 'X64') {
        return 'qodo-support-bundle-windows-amd64.exe'
    }
    if ($OperatingSystem -eq 'windows' -and $Architecture -eq 'Arm64') {
        return 'qodo-support-bundle-windows-arm64.exe'
    }
    throw "unsupported platform: $OperatingSystem $Architecture"
}

function ConvertTo-QodoScoutArchitecture {
    param([Parameter(Mandatory)][string]$Value)

    switch ($Value.Trim().ToUpperInvariant()) {
        'AMD64' { return 'X64' }
        'X64' { return 'X64' }
        'ARM64' { return 'Arm64' }
        default { throw "unsupported Windows architecture: $Value" }
    }
}

function Resolve-QodoScoutArchitecture {
    param(
        [AllowNull()][object]$RuntimeArchitecture,
        [AllowNull()][string]$ProcessorArchitectureW6432 = (
            $env:PROCESSOR_ARCHITEW6432
        ),
        [AllowNull()][string]$ProcessorArchitecture = (
            $env:PROCESSOR_ARCHITECTURE
        )
    )

    if (-not [string]::IsNullOrWhiteSpace($ProcessorArchitectureW6432)) {
        return ConvertTo-QodoScoutArchitecture `
            -Value $ProcessorArchitectureW6432
    }
    if (-not $PSBoundParameters.ContainsKey('RuntimeArchitecture')) {
        try {
            $RuntimeArchitecture = (
                [Runtime.InteropServices.RuntimeInformation]::OSArchitecture
            )
        }
        catch {
            $RuntimeArchitecture = $null
        }
    }
    if (-not [string]::IsNullOrWhiteSpace([string]$RuntimeArchitecture)) {
        return ConvertTo-QodoScoutArchitecture `
            -Value ([string]$RuntimeArchitecture)
    }

    if ([string]::IsNullOrWhiteSpace($ProcessorArchitecture)) {
        throw 'unable to detect a supported Windows architecture'
    }
    return ConvertTo-QodoScoutArchitecture -Value $ProcessorArchitecture
}

function Get-QodoScoutManifestDigest {
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$ManifestText,
        [Parameter(Mandatory)][string]$AssetName
    )

    $digests = @()
    foreach ($line in ($ManifestText -split "`r?`n")) {
        if ($line -notmatch ([regex]::Escape($AssetName) + '$')) {
            continue
        }
        $row = [regex]::Match(
            $line,
            '^([0-9A-Fa-f]{64})[ \t]+(' + [regex]::Escape($AssetName) + ')$',
            [Text.RegularExpressions.RegexOptions]::CultureInvariant
        )
        if (-not $row.Success) {
            throw "checksum row for $AssetName is malformed"
        }
        $digests += $row.Groups[1].Value.ToLowerInvariant()
    }
    if ($digests.Count -ne 1) {
        throw "expected exactly one checksum row for $AssetName"
    }
    return $digests[0]
}

function Invoke-QodoScoutDownload {
    param(
        [Parameter(Mandatory)][uri]$Uri,
        [Parameter(Mandatory)][string]$Destination
    )

    if (-not (Get-Command 'curl.exe' -ErrorAction SilentlyContinue)) {
        throw 'curl.exe is required for network installation'
    }
    & curl.exe `
        --fail `
        --location `
        --proto '=https' `
        --proto-redir '=https' `
        --tlsv1.2 `
        --retry 3 `
        --retry-delay 1 `
        --output $Destination `
        $Uri.AbsoluteUri
    if ($LASTEXITCODE -ne 0) {
        throw "download failed: $($Uri.AbsoluteUri)"
    }
}

function Invoke-QodoScoutSmokeCheck {
    param([Parameter(Mandatory)][string]$Executable)

    & $Executable version
    if ($LASTEXITCODE -ne 0) {
        throw 'installed qodo-scout failed its non-collecting version check'
    }
}

function Join-QodoScoutUserPath {
    param(
        [AllowEmptyString()][string]$CurrentUserPath,
        [Parameter(Mandatory)][string]$InstallDirectory
    )

    $entries = @(
        $CurrentUserPath -split ';' |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
    )
    $normalizedInstall = $InstallDirectory.TrimEnd('\')
    foreach ($entry in $entries) {
        if ($entry.TrimEnd('\').Equals(
                $normalizedInstall,
                [StringComparison]::OrdinalIgnoreCase
            )) {
            return ($entries -join ';')
        }
    }
    return (@($entries) + $InstallDirectory) -join ';'
}

function ConvertTo-QodoScoutPowerShellLiteral {
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Value)

    return "'" + $Value.Replace("'", "''") + "'"
}

function Test-QodoScoutFullyQualifiedPath {
    param([Parameter(Mandatory)][string]$Value)

    return (
        $Value -match '^[A-Za-z]:[\\/]' -or
        $Value -match '^[\\/]{2}[^\\/]+[\\/][^\\/]+'
    )
}

function Add-QodoScoutToUserPath {
    param([Parameter(Mandatory)][string]$InstallDirectory)

    $userSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $mutexName = "Global\QodoScoutInstaller.UserPath.$userSid"
    $mutex = [System.Threading.Mutex]::new($false, $mutexName)
    $acquired = $false
    $changed = $false
    try {
        try {
            $acquired = $mutex.WaitOne([TimeSpan]::FromSeconds(30))
        }
        catch [System.Threading.AbandonedMutexException] {
            $acquired = $true
        }
        if (-not $acquired) {
            throw 'timed out waiting to update the current user PATH'
        }

        $current = [Environment]::GetEnvironmentVariable('Path', 'User')
        $updated = Join-QodoScoutUserPath `
            -CurrentUserPath $current `
            -InstallDirectory $InstallDirectory
        if ($updated -ne $current) {
            [Environment]::SetEnvironmentVariable('Path', $updated, 'User')
            $changed = $true
        }
    }
    finally {
        if ($acquired) {
            $mutex.ReleaseMutex()
        }
        $mutex.Dispose()
    }
    if ($changed) {
        Write-Output "Added $InstallDirectory to the current user's PATH."
    }
    $directoryLiteral = ConvertTo-QodoScoutPowerShellLiteral -Value $InstallDirectory
    Write-Output 'Open a new terminal for the persisted PATH update to take effect.'
    Write-Output "For this PowerShell session, run: `$env:Path = $directoryLiteral + ';' + `$env:Path"
}

function Restore-QodoScoutInstallation {
    param(
        [Parameter(Mandatory)][string]$RollbackFile,
        [Parameter(Mandatory)][string]$Target
    )

    [IO.File]::Replace($RollbackFile, $Target, $null)
}

function Install-QodoScout {
    param(
        [string]$RequestedVersion,
        [string]$RequestedInstallDirectory,
        [string]$RequestedSourceDirectory,
        [string]$RuntimeArchitecture,
        [switch]$UpdateUserPath
    )

    if (-not [Runtime.InteropServices.RuntimeInformation]::IsOSPlatform(
            [Runtime.InteropServices.OSPlatform]::Windows
        )) {
        throw 'unsupported platform: install.ps1 requires Windows'
    }
    if ($PSBoundParameters.ContainsKey('RuntimeArchitecture')) {
        $resolvedArchitecture = ConvertTo-QodoScoutArchitecture `
            -Value $RuntimeArchitecture
    }
    else {
        $resolvedArchitecture = Resolve-QodoScoutArchitecture
    }
    $asset = Resolve-QodoScoutAsset `
        -OperatingSystem 'windows' `
        -Architecture $resolvedArchitecture

    if ([string]::IsNullOrWhiteSpace($RequestedInstallDirectory)) {
        if ([string]::IsNullOrWhiteSpace($env:LOCALAPPDATA)) {
            throw 'LOCALAPPDATA is required for the default user-local installation'
        }
        $RequestedInstallDirectory = Join-Path $env:LOCALAPPDATA 'Qodo\bin'
    }
    if (-not (Test-QodoScoutFullyQualifiedPath -Value $RequestedInstallDirectory)) {
        throw 'install directory must be an absolute path'
    }

    if ([string]::IsNullOrWhiteSpace($RequestedVersion)) {
        throw '-Version is required; install an explicit release'
    }
    Assert-QodoScoutVersion -Value $RequestedVersion
    if (-not [string]::IsNullOrWhiteSpace($RequestedSourceDirectory)) {
        if ([string]::IsNullOrWhiteSpace($RequestedVersion)) {
            throw '-SourceDir requires -Version so the local release is explicit'
        }
        if (-not (Test-QodoScoutFullyQualifiedPath -Value $RequestedSourceDirectory)) {
            throw 'source directory must be an absolute path'
        }
        if (-not (Test-Path -LiteralPath $RequestedSourceDirectory -PathType Container)) {
            throw "source directory does not exist: $RequestedSourceDirectory"
        }
    }

    $temporaryDirectory = Join-Path `
        ([IO.Path]::GetTempPath()) `
        ('qodo-scout-' + [guid]::NewGuid().ToString('N'))
    [IO.Directory]::CreateDirectory($temporaryDirectory) | Out-Null
    $stagedInstall = $null
    $rollbackFile = $null
    try {
        $releaseBaseUrl = Get-QodoScoutReleaseBaseUrl -Version $RequestedVersion
        $assetUrl = Get-QodoScoutAssetUrl `
            -Version $RequestedVersion `
            -AssetName $asset
        $binaryPath = Join-Path $temporaryDirectory $asset
        $manifestPath = Join-Path $temporaryDirectory 'checksums.sha256'
        if (-not [string]::IsNullOrWhiteSpace($RequestedSourceDirectory)) {
            Copy-Item `
                -LiteralPath (Join-Path $RequestedSourceDirectory $asset) `
                -Destination $binaryPath
            Copy-Item `
                -LiteralPath (Join-Path $RequestedSourceDirectory 'checksums.sha256') `
                -Destination $manifestPath
        }
        else {
            Invoke-QodoScoutDownload `
                -Uri $assetUrl `
                -Destination $binaryPath
            Invoke-QodoScoutDownload `
                -Uri "$releaseBaseUrl/checksums.sha256" `
                -Destination $manifestPath
        }

        $manifestText = Get-Content -LiteralPath $manifestPath -Raw
        $expectedDigest = Get-QodoScoutManifestDigest `
            -ManifestText $manifestText `
            -AssetName $asset
        $actualDigest = (
            Get-FileHash -LiteralPath $binaryPath -Algorithm SHA256
        ).Hash.ToLowerInvariant()
        if ($actualDigest -ne $expectedDigest) {
            throw 'checksum verification failed for the selected Qodo Scout artifact'
        }

        [IO.Directory]::CreateDirectory($RequestedInstallDirectory) | Out-Null
        $target = Join-Path $RequestedInstallDirectory 'qodo-scout.exe'
        $stagedInstall = Join-Path `
            $RequestedInstallDirectory `
            ('.qodo-scout.' + [guid]::NewGuid().ToString('N') + '.tmp')
        [IO.File]::Copy($binaryPath, $stagedInstall, $false)

        $hadExisting = [IO.File]::Exists($target)
        if ($hadExisting) {
            $rollbackFile = Join-Path `
                $RequestedInstallDirectory `
                ('.qodo-scout.rollback.' + [guid]::NewGuid().ToString('N'))
            [IO.File]::Replace($stagedInstall, $target, $rollbackFile)
        }
        else {
            [IO.File]::Move($stagedInstall, $target)
        }
        $stagedInstall = $null

        try {
            Invoke-QodoScoutSmokeCheck -Executable $target
        }
        catch {
            $smokeFailure = $_
            if ($hadExisting -and [IO.File]::Exists($rollbackFile)) {
                try {
                    Restore-QodoScoutInstallation `
                        -RollbackFile $rollbackFile `
                        -Target $target
                    $rollbackFile = $null
                }
                catch {
                    throw (
                        'installed qodo-scout failed its version check and rollback failed; ' +
                        "the previous executable is preserved at $rollbackFile. " +
                        "Rollback error: $($_.Exception.Message)"
                    )
                }
            }
            elseif ([IO.File]::Exists($target)) {
                [IO.File]::Delete($target)
            }
            throw $smokeFailure
        }
        if ($rollbackFile -and [IO.File]::Exists($rollbackFile)) {
            [IO.File]::Delete($rollbackFile)
            $rollbackFile = $null
        }

        Write-Output "Installed Qodo Scout $RequestedVersion to $target"
        if ($UpdateUserPath) {
            Add-QodoScoutToUserPath -InstallDirectory $RequestedInstallDirectory
        }
        elseif (($env:Path -split ';') -notcontains $RequestedInstallDirectory) {
            Write-Output "$RequestedInstallDirectory is not on PATH."
            Write-Output 'Re-run with -AddToPath, or add it to your user PATH.'
        }
        $targetLiteral = ConvertTo-QodoScoutPowerShellLiteral -Value $target
        Write-Output "Run now with: & $targetLiteral collect --interactive"
        Write-Output 'After PATH is active: qodo-scout collect --interactive'
    }
    finally {
        if ($stagedInstall -and [IO.File]::Exists($stagedInstall)) {
            [IO.File]::Delete($stagedInstall)
        }
        if ([IO.Directory]::Exists($temporaryDirectory)) {
            [IO.Directory]::Delete($temporaryDirectory, $true)
        }
    }
}

if ($env:QODO_SCOUT_INSTALLER_TESTING -ne '1') {
    Install-QodoScout `
        -RequestedVersion $Version `
        -RequestedInstallDirectory $InstallDir `
        -RequestedSourceDirectory $SourceDir `
        -UpdateUserPath:$AddToPath
}
