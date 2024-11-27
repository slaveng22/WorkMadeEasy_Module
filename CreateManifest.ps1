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
-FunctionsToExport "Get-MyFunction"`
-PowerShellVersion 7.0