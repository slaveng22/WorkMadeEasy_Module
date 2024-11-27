$ModulePath=Read-Host -Prompt "Enter a path to your .psd1 file"

if (!(Test-Path $ModulePath)){

    Write-Error -Message "Invalid path of .psd1 file doesn't exist. Enter correct path or create .psd1 file"
    Start-Sleep -Seconds 10
    exit
}

New-ModuleManifest -Path $ModulePath `
-Author "slaveng22"`
-Description "Module for simplifying administrative tasks"`
-ModuleVersion "1.0.2"`
-Copyright "(c) 2024 slaveng22. Licensed under MIT License. See LICENSE for details"`
-FunctionsToExport "Format-Bytes, unzip, Get-WinRShortcut, Open-AsAdmin, Update-Software, Get-RDPHealth, Set-PowerPlan, Get-NetworkInstalledPrinters, Get-LoggedInUserSession, Close-LoggedInUserSession, Get-InstalledSoftwareList, Get-LocalProfiles, Remove-LocalProfile, Get-LargestMailbox, Add-UserToSharedMailbox, Find-SPSOwner, Get-MailboxPermissionList, Find-BitLockerPC, Copy-ADGroupMembership, Get-InactiveUser"`
-PowerShellVersion 7.0