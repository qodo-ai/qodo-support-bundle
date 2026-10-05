$ErrorActionPreference = 'Stop'

BeforeAll {
    $script:RepositoryRoot = Split-Path -Parent $PSScriptRoot
    $env:QODO_SCOUT_INSTALLER_TESTING = '1'
    . (Join-Path $script:RepositoryRoot 'install.ps1')
}

AfterAll {
    Remove-Item Env:QODO_SCOUT_INSTALLER_TESTING -ErrorAction SilentlyContinue
}

Describe 'Qodo Scout Windows installer contracts' {
    It 'maps native Windows architectures to their published assets' {
        Resolve-QodoScoutAsset -OperatingSystem 'windows' -Architecture 'X64' |
            Should -Be 'qodo-support-bundle-windows-amd64.exe'
        Resolve-QodoScoutAsset -OperatingSystem 'windows' -Architecture 'Arm64' |
            Should -Be 'qodo-support-bundle-windows-arm64.exe'
        {
            Resolve-QodoScoutAsset -OperatingSystem 'windows' -Architecture 'X86'
        } | Should -Throw '*unsupported platform*'
    }

    It 'constructs the immutable release base URL from the selected version' {
        Get-QodoScoutReleaseBaseUrl -Version '1.2.3' |
            Should -Be 'https://get.qodo.ai/support-bundle/releases/1.2.3'
        Get-QodoScoutAssetUrl `
            -Version '1.2.3' `
            -AssetName 'qodo-support-bundle-windows-arm64.exe' |
            Should -Be (
                'https://get.qodo.ai/support-bundle/releases/1.2.3/' +
                'qodo-support-bundle-windows-arm64.exe'
            )
    }

    It 'selects one exact well-formed checksum row' {
        $digest = 'a' * 64
        Get-QodoScoutManifestDigest `
            -ManifestText "$digest  qodo-support-bundle-windows-arm64.exe`n" `
            -AssetName 'qodo-support-bundle-windows-arm64.exe' |
            Should -Be $digest
    }

    It 'rejects missing duplicate and malformed checksum rows' {
        $asset = 'qodo-support-bundle-windows-amd64.exe'
        $digest = 'b' * 64
        {
            Get-QodoScoutManifestDigest -ManifestText '' -AssetName $asset
        } | Should -Throw '*exactly one*'
        {
            Get-QodoScoutManifestDigest `
                -ManifestText "$digest  $asset`n$digest  $asset`n" `
                -AssetName $asset
        } | Should -Throw '*exactly one*'
        {
            Get-QodoScoutManifestDigest `
                -ManifestText "invalid  $asset`n" `
                -AssetName $asset
        } | Should -Throw '*malformed*'
    }

    It 'deduplicates a user PATH entry without changing other entries' {
        Join-QodoScoutUserPath `
            -CurrentUserPath 'C:\Existing;C:\Qodo Bin' `
            -InstallDirectory 'C:\Qodo Bin' |
            Should -Be 'C:\Existing;C:\Qodo Bin'
    }

    It 'escapes apostrophes in printed PowerShell path literals' {
        ConvertTo-QodoScoutPowerShellLiteral -Value "C:\Users\O'Brien\bin" |
            Should -Be "'C:\Users\O''Brien\bin'"
    }

    It 'distinguishes fully qualified Windows paths from current-drive paths' {
        Test-QodoScoutFullyQualifiedPath -Value 'C:\Qodo\bin' | Should -BeTrue
        Test-QodoScoutFullyQualifiedPath -Value '\\server\share\release' |
            Should -BeTrue
        Test-QodoScoutFullyQualifiedPath -Value '\Qodo\bin' | Should -BeFalse
        Test-QodoScoutFullyQualifiedPath -Value 'Qodo\bin' | Should -BeFalse
    }

    It 'fails clearly when curl.exe is unavailable in network mode' {
        Mock Get-Command { $null }
        {
            Invoke-QodoScoutDownload `
                -Uri 'https://get.qodo.ai/support-bundle/releases/1.2.3/install.ps1' `
                -Destination (Join-Path $TestDrive 'install.ps1')
        } | Should -Throw '*curl.exe is required*'
    }

    It 'does not weaken Windows security controls' {
        $text = Get-Content (Join-Path $script:RepositoryRoot 'install.ps1') -Raw
        $text | Should -Not -Match 'Unblock-File'
        $text | Should -Not -Match 'Zone\.Identifier'
        $text | Should -Not -Match 'ExecutionPolicy\s+Bypass'
    }

    It 'serializes the user PATH read modify write sequence' {
        $text = Get-Content (Join-Path $script:RepositoryRoot 'install.ps1') -Raw
        $pathUpdate = [regex]::Match(
            $text,
            '(?s)function Add-QodoScoutToUserPath \{.*?' +
                'function Restore-QodoScoutInstallation'
        ).Value

        $pathUpdate | Should -Match 'System\.Threading\.Mutex'
        $pathUpdate | Should -Match '\.WaitOne\('
        $pathUpdate | Should -Match '(?s)finally\s*\{.*?\.ReleaseMutex\(\)'
    }
}

Describe 'Qodo Scout local source installation' -Skip:(-not $IsWindows) {
    BeforeEach {
        $script:CaseRoot = Join-Path $TestDrive 'case with spaces'
        $script:SourceDirectory = Join-Path $script:CaseRoot 'source'
        $script:InstallDirectory = Join-Path $script:CaseRoot 'install'
        New-Item -ItemType Directory -Path $script:SourceDirectory -Force | Out-Null
        $script:Asset = 'qodo-support-bundle-windows-amd64.exe'
        $script:AssetPath = Join-Path $script:SourceDirectory $script:Asset
        [IO.File]::WriteAllBytes($script:AssetPath, [byte[]](1, 2, 3, 4))
        $digest = (Get-FileHash -LiteralPath $script:AssetPath -Algorithm SHA256).Hash.ToLowerInvariant()
        Set-Content `
            -LiteralPath (Join-Path $script:SourceDirectory 'checksums.sha256') `
            -Value "$digest  $script:Asset" `
            -NoNewline
        Mock Invoke-QodoScoutSmokeCheck {}
    }

    It 'installs verified bytes under the stable command name and is idempotent' {
        Install-QodoScout `
            -RequestedVersion '1.2.3' `
            -RequestedInstallDirectory $script:InstallDirectory `
            -RequestedSourceDirectory $script:SourceDirectory `
            -RuntimeArchitecture 'X64'
        Install-QodoScout `
            -RequestedVersion '1.2.3' `
            -RequestedInstallDirectory $script:InstallDirectory `
            -RequestedSourceDirectory $script:SourceDirectory `
            -RuntimeArchitecture 'X64'

        $installed = Join-Path $script:InstallDirectory 'qodo-scout.exe'
        [Convert]::ToBase64String([IO.File]::ReadAllBytes($installed)) |
            Should -Be 'AQIDBA=='
        Assert-MockCalled Invoke-QodoScoutSmokeCheck -Times 2 -Exactly
    }

    It 'installs the verified ARM64 asset from a local source directory' {
        $armAsset = 'qodo-support-bundle-windows-arm64.exe'
        $armAssetPath = Join-Path $script:SourceDirectory $armAsset
        [IO.File]::WriteAllBytes($armAssetPath, [byte[]](5, 6, 7, 8))
        $digest = (
            Get-FileHash -LiteralPath $armAssetPath -Algorithm SHA256
        ).Hash.ToLowerInvariant()
        Set-Content `
            -LiteralPath (Join-Path $script:SourceDirectory 'checksums.sha256') `
            -Value "$digest  $armAsset" `
            -NoNewline

        Install-QodoScout `
            -RequestedVersion '1.2.3' `
            -RequestedInstallDirectory $script:InstallDirectory `
            -RequestedSourceDirectory $script:SourceDirectory `
            -RuntimeArchitecture 'Arm64'

        $installed = Join-Path $script:InstallDirectory 'qodo-scout.exe'
        [Convert]::ToBase64String([IO.File]::ReadAllBytes($installed)) |
            Should -Be 'BQYHCA=='
        Assert-MockCalled Invoke-QodoScoutSmokeCheck -Times 1 -Exactly
    }

    It 'preserves an existing install when verification fails' {
        New-Item -ItemType Directory -Path $script:InstallDirectory -Force | Out-Null
        $installed = Join-Path $script:InstallDirectory 'qodo-scout.exe'
        [IO.File]::WriteAllBytes($installed, [byte[]](9, 9))
        Set-Content `
            -LiteralPath (Join-Path $script:SourceDirectory 'checksums.sha256') `
            -Value "$('0' * 64)  $script:Asset" `
            -NoNewline

        {
            Install-QodoScout `
                -RequestedVersion '1.2.3' `
                -RequestedInstallDirectory $script:InstallDirectory `
                -RequestedSourceDirectory $script:SourceDirectory `
                -RuntimeArchitecture 'X64'
        } | Should -Throw '*checksum*'
        [Convert]::ToBase64String([IO.File]::ReadAllBytes($installed)) |
            Should -Be 'CQk='
    }

    It 'retains the previous executable when rollback itself fails' {
        New-Item -ItemType Directory -Path $script:InstallDirectory -Force | Out-Null
        $installed = Join-Path $script:InstallDirectory 'qodo-scout.exe'
        [IO.File]::WriteAllBytes($installed, [byte[]](9, 9))
        Mock Invoke-QodoScoutSmokeCheck { throw 'smoke failed' }
        Mock Restore-QodoScoutInstallation { throw 'target is locked' }

        {
            Install-QodoScout `
                -RequestedVersion '1.2.3' `
                -RequestedInstallDirectory $script:InstallDirectory `
                -RequestedSourceDirectory $script:SourceDirectory `
                -RuntimeArchitecture 'X64'
        } | Should -Throw '*previous executable is preserved at*'
        $rollback = @(
            Get-ChildItem `
                -LiteralPath $script:InstallDirectory `
                -Filter '.qodo-scout.rollback.*'
        )
        $rollback.Count | Should -Be 1
        [Convert]::ToBase64String([IO.File]::ReadAllBytes($rollback[0].FullName)) |
            Should -Be 'CQk='
    }
}

Describe 'Qodo Scout pinned network installation' -Skip:(-not $IsWindows) {
    BeforeEach {
        $script:DownloadedUris = @()
        $script:InstallerTempDirectory = $null
        $script:LatestInstallDirectory = Join-Path $TestDrive 'latest install'
        Mock Invoke-QodoScoutSmokeCheck {}
        Mock Invoke-QodoScoutDownload {
            param([uri]$Uri, [string]$Destination)

            $script:DownloadedUris += $Uri.AbsoluteUri
            $script:InstallerTempDirectory = Split-Path -Parent $Destination
            if ($Uri.AbsolutePath.EndsWith('/checksums.sha256')) {
                $assetPath = Join-Path `
                    (Split-Path -Parent $Destination) `
                    'qodo-support-bundle-windows-amd64.exe'
                $digest = (
                    Get-FileHash -LiteralPath $assetPath -Algorithm SHA256
                ).Hash.ToLowerInvariant()
                Set-Content `
                    -LiteralPath $Destination `
                    -Value "$digest  qodo-support-bundle-windows-amd64.exe" `
                    -NoNewline
                return
            }
            [IO.File]::WriteAllBytes($Destination, [byte[]](5, 6, 7, 8))
        }
    }

    It 'requires an explicit version' {
        {
            Install-QodoScout `
                -RequestedInstallDirectory $script:LatestInstallDirectory `
                -RuntimeArchitecture 'X64'
        } | Should -Throw '*-Version is required*'
        Assert-MockCalled Invoke-QodoScoutDownload -Times 0 -Exactly
    }

    It 'downloads only from one immutable release directory' {
        Install-QodoScout `
            -RequestedVersion '4.5.6' `
            -RequestedInstallDirectory $script:LatestInstallDirectory `
            -RuntimeArchitecture 'X64'

        $expectedUris = @(
            'https://get.qodo.ai/support-bundle/releases/4.5.6/qodo-support-bundle-windows-amd64.exe',
            'https://get.qodo.ai/support-bundle/releases/4.5.6/checksums.sha256'
        ) -join "`n"
        ($script:DownloadedUris -join "`n") | Should -Be $expectedUris
        Test-Path $script:InstallerTempDirectory | Should -BeFalse
        Assert-MockCalled Invoke-QodoScoutSmokeCheck -Times 1 -Exactly
    }

    It 'downloads and verifies the ARM64 asset from the immutable release URL' {
        Mock Invoke-QodoScoutDownload {
            param([uri]$Uri, [string]$Destination)

            $script:DownloadedUris += $Uri.AbsoluteUri
            if ($Uri.AbsolutePath.EndsWith('/checksums.sha256')) {
                $asset = 'qodo-support-bundle-windows-arm64.exe'
                $assetPath = Join-Path (Split-Path -Parent $Destination) $asset
                $digest = (
                    Get-FileHash -LiteralPath $assetPath -Algorithm SHA256
                ).Hash.ToLowerInvariant()
                Set-Content `
                    -LiteralPath $Destination `
                    -Value "$digest  $asset" `
                    -NoNewline
                return
            }
            [IO.File]::WriteAllBytes($Destination, [byte[]](5, 6, 7, 8))
        }

        Install-QodoScout `
            -RequestedVersion '4.5.6' `
            -RequestedInstallDirectory $script:LatestInstallDirectory `
            -RuntimeArchitecture 'Arm64'

        $expectedUris = @(
            'https://get.qodo.ai/support-bundle/releases/4.5.6/qodo-support-bundle-windows-arm64.exe',
            'https://get.qodo.ai/support-bundle/releases/4.5.6/checksums.sha256'
        ) -join "`n"
        ($script:DownloadedUris -join "`n") | Should -Be $expectedUris
        Assert-MockCalled Invoke-QodoScoutSmokeCheck -Times 1 -Exactly
    }

    It 'does not replace an existing install when a download fails' {
        New-Item `
            -ItemType Directory `
            -Path $script:LatestInstallDirectory `
            -Force | Out-Null
        $installed = Join-Path $script:LatestInstallDirectory 'qodo-scout.exe'
        [IO.File]::WriteAllBytes($installed, [byte[]](9, 9))
        Mock Invoke-QodoScoutDownload { throw 'download failed: fixture' }

        {
            Install-QodoScout `
                -RequestedVersion '4.5.6' `
                -RequestedInstallDirectory $script:LatestInstallDirectory `
                -RuntimeArchitecture 'X64'
        } | Should -Throw '*download failed*'
        [Convert]::ToBase64String([IO.File]::ReadAllBytes($installed)) |
            Should -Be 'CQk='
    }
}
