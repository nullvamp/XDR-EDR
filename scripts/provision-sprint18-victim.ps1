$ErrorActionPreference = 'Stop'

$vmName = 'XDR-Victim-Sprint18'
$vmRoot = [IO.Path]::GetFullPath('D:\VMs\XDR-Victim-Sprint18')
$vhdPath = Join-Path $vmRoot 'Virtual Hard Disks\XDR-Victim-Sprint18.vhdx'
$isoPath = [IO.Path]::GetFullPath('D:\VMs\Media\Windows11EnterpriseEval-x64-en-us.iso')
$credentialPath = Join-Path $vmRoot 'victim-credential.xml'
$expectedIsoHash = 'A61ADEAB895EF5A4DB436E0A7011C92A2FF17BB0357F58B13BBC4062E535E7B9'

Import-Module Hyper-V
if ((Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All).State -ne 'Enabled') { throw 'Hyper-V is not enabled.' }
if ((Get-Service vmms).Status -ne 'Running') { throw 'Hyper-V Virtual Machine Management is not running.' }
if (-not (Get-VMSwitch -Name 'Default Switch' -ErrorAction SilentlyContinue)) { throw 'Hyper-V Default Switch is unavailable.' }
if (-not (Test-Path -LiteralPath $isoPath)) { throw "Victim ISO is missing: $isoPath" }
if ((Get-FileHash -LiteralPath $isoPath -Algorithm SHA256).Hash -ne $expectedIsoHash) { throw 'Victim ISO checksum does not match the verified Microsoft media.' }
if (Get-VM -Name $vmName -ErrorAction SilentlyContinue) { throw "VM already exists: $vmName" }
if (Test-Path -LiteralPath $vhdPath) { throw "VHD already exists: $vhdPath" }
if ((Get-PSDrive D).Free -lt 30GB) { throw 'At least 30 GB free is required before victim provisioning.' }

New-Item -ItemType Directory -Path (Split-Path $vhdPath) -Force | Out-Null
$random = New-Object byte[] 18
$rng = [Security.Cryptography.RandomNumberGenerator]::Create()
try { $rng.GetBytes($random) } finally { $rng.Dispose() }
$password = 'V!' + ([Convert]::ToBase64String($random).Replace('/', 'x').Replace('+', 'Y').TrimEnd('=')) + 'a1'
$secure = ConvertTo-SecureString $password -AsPlainText -Force
[pscredential]::new('xdrvictim', $secure) | Export-Clixml -LiteralPath $credentialPath

New-VHD -Path $vhdPath -Dynamic -SizeBytes 64GB | Out-Null
$vhd = Mount-VHD -Path $vhdPath -PassThru
$isoMounted = $false
try {
    $disk = $vhd | Get-Disk
    Initialize-Disk -Number $disk.Number -PartitionStyle GPT | Out-Null
    $efi = New-Partition -DiskNumber $disk.Number -Size 260MB -AssignDriveLetter -GptType '{C12A7328-F81F-11D2-BA4B-00A0C93EC93B}'
    Format-Volume -Partition $efi -FileSystem FAT32 -NewFileSystemLabel 'SYSTEM' -Confirm:$false | Out-Null
    $windows = New-Partition -DiskNumber $disk.Number -UseMaximumSize -AssignDriveLetter
    Format-Volume -Partition $windows -FileSystem NTFS -NewFileSystemLabel 'Windows' -Confirm:$false | Out-Null

    $iso = Mount-DiskImage -ImagePath $isoPath -PassThru
    $isoMounted = $true
    $isoVolume = $iso | Get-Volume
    $install = "$($isoVolume.DriveLetter):\sources\install.wim"
    $windowsRoot = "$($windows.DriveLetter):\"
    & dism.exe /English /Apply-Image /ImageFile:$install /Index:1 /ApplyDir:$windowsRoot
    if ($LASTEXITCODE -ne 0) { throw "DISM Apply-Image failed with exit code $LASTEXITCODE" }

    $panther = Join-Path $windowsRoot 'Windows\Panther'
    New-Item -ItemType Directory -Path $panther -Force | Out-Null
    $escaped = [Security.SecurityElement]::Escape($password)
    $unattend = @"
<?xml version="1.0" encoding="utf-8"?>
<unattend xmlns="urn:schemas-microsoft-com:unattend">
  <settings pass="specialize">
    <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">
      <ComputerName>XDR-VICTIM18</ComputerName>
      <TimeZone>Arab Standard Time</TimeZone>
    </component>
  </settings>
  <settings pass="oobeSystem">
    <component name="Microsoft-Windows-International-Core" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">
      <InputLocale>0409:00000409</InputLocale><SystemLocale>en-US</SystemLocale><UILanguage>en-US</UILanguage><UserLocale>en-US</UserLocale>
    </component>
    <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">
      <OOBE><HideEULAPage>true</HideEULAPage><HideOnlineAccountScreens>true</HideOnlineAccountScreens><HideWirelessSetupInOOBE>true</HideWirelessSetupInOOBE><NetworkLocation>Work</NetworkLocation><ProtectYourPC>3</ProtectYourPC></OOBE>
      <UserAccounts><LocalAccounts><LocalAccount wcm:action="add"><Name>xdrvictim</Name><DisplayName>XDR Victim</DisplayName><Group>Administrators</Group><Description>Disposable Sprint 18 qualification account</Description><Password><Value>$escaped</Value><PlainText>true</PlainText></Password></LocalAccount></LocalAccounts></UserAccounts>
      <AutoLogon><Enabled>true</Enabled><LogonCount>2</LogonCount><Username>xdrvictim</Username><Password><Value>$escaped</Value><PlainText>true</PlainText></Password></AutoLogon>
    </component>
  </settings>
</unattend>
"@
    [IO.File]::WriteAllText((Join-Path $panther 'Unattend.xml'), $unattend, [Text.UTF8Encoding]::new($false))
    & bcdboot.exe "$windowsRoot`Windows" /s "$($efi.DriveLetter):" /f UEFI
    if ($LASTEXITCODE -ne 0) { throw "BCDBoot failed with exit code $LASTEXITCODE" }
}
finally {
    if ($isoMounted) { Dismount-DiskImage -ImagePath $isoPath -ErrorAction SilentlyContinue }
    Dismount-VHD -Path $vhdPath -ErrorAction SilentlyContinue
    $password = $null
    $escaped = $null
    $unattend = $null
}

$vm = New-VM -Name $vmName -Generation 2 -MemoryStartupBytes 4GB -VHDPath $vhdPath -Path $vmRoot -SwitchName 'Default Switch'
Set-VM -VM $vm -ProcessorCount 2 -AutomaticStartAction Nothing -AutomaticStopAction Save -AutomaticCheckpointsEnabled $false -CheckpointType Standard
Set-VMMemory -VMName $vmName -DynamicMemoryEnabled $true -MinimumBytes 2GB -StartupBytes 4GB -MaximumBytes 8GB
Set-VMFirmware -VMName $vmName -EnableSecureBoot On -SecureBootTemplate MicrosoftWindows
Set-VMKeyProtector -VMName $vmName -NewLocalKeyProtector
Enable-VMTPM -VMName $vmName
Enable-VMIntegrationService -VMName $vmName -Name 'Guest Service Interface'
Start-VM -Name $vmName | Out-Null

Get-VM -Name $vmName | Select-Object Name, State, Generation, ProcessorCount, MemoryStartup, Path, AutomaticStartAction, AutomaticCheckpointsEnabled, CheckpointType
Get-VMHardDiskDrive -VMName $vmName | Select-Object Path, ControllerType, ControllerNumber, ControllerLocation
Get-VMSecurity -VMName $vmName | Select-Object TpmEnabled, EncryptStateAndVmMigrationTraffic
