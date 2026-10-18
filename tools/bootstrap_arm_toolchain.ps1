[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$toolchainRoot = Join-Path $projectRoot 'build\toolchains\arm-gnu-14.3'
$archive = Join-Path $toolchainRoot 'arm-gnu-toolchain.zip'
$extractDir = Join-Path $toolchainRoot 'unpacked'
$gcc = Join-Path $extractDir 'bin\arm-none-eabi-gcc.exe'
$url = 'https://developer.arm.com/-/media/Files/downloads/gnu/14.3.rel1/binrel/arm-gnu-toolchain-14.3.rel1-mingw-w64-i686-arm-none-eabi.zip'
$expectedSha256 = '836ebe51fd71b6542dd7884c8fb2011192464b16c28e4b38fddc9350daba5ee8'

New-Item -ItemType Directory -Force -Path $toolchainRoot | Out-Null
if (-not (Test-Path -LiteralPath $archive -PathType Leaf)) {
    Invoke-WebRequest -Uri $url -OutFile $archive
}

$actualSha256 = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
if ($actualSha256 -ne $expectedSha256) {
    throw "Arm toolchain archive SHA-256 mismatch. Expected $expectedSha256, got $actualSha256."
}

if (Test-Path -LiteralPath $extractDir) {
    if (-not (Test-Path -LiteralPath $gcc -PathType Leaf)) {
        throw "Extraction directory exists but the compiler is missing: $extractDir"
    }
} else {
    Expand-Archive -LiteralPath $archive -DestinationPath $extractDir
}

if (-not (Test-Path -LiteralPath $gcc -PathType Leaf)) {
    throw "Verified archive did not contain the expected compiler: $gcc"
}

Write-Output "Verified archive SHA-256: $actualSha256"
Write-Output "Compiler: $(& $gcc --version | Select-Object -First 1)"
Write-Output "Toolchain bin: $(Join-Path $extractDir 'bin')"
