$ErrorActionPreference = 'Stop'

# Downloads and silently installs the official Relix-Q Community MSI.
# The MSI is mirrored on the website (public); at GA, point url at the GitHub
# release asset instead. Checksum verified by Chocolatey before install.
$packageArgs = @{
  packageName    = 'relixq'
  fileType       = 'msi'
  url            = 'https://relixq-website.vercel.app/downloads/relixq_0.1.0_windows_amd64.msi'
  checksum       = '42f50a8c8f73fc799882a4cac9ca8e58ddd0168bd8915c25313c09cb4392345c'
  checksumType   = 'sha256'
  silentArgs     = '/qn /norestart'
  validExitCodes = @(0, 3010, 1641)  # 0 ok, 3010 reboot required, 1641 reboot initiated
}

Install-ChocolateyPackage @packageArgs

Write-Host ''
Write-Host 'relixq installed. Open a NEW terminal and run:  relixq version'
Write-Host 'For the web dashboard instead, see https://relixq-website.vercel.app/#download'
