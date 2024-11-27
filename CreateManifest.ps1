Set-Location -Path .\WorkMadeEasy

New-ModuleManifest -Path WorkMadeEasy.psd1 `
-Author "slaveng22"`
-Description "Module for simplifying administrative tasks"`
-ModuleVersion "1.0.2"`
-Copyright "(c) 2024 slaveng22. Licensed under MIT License. See LICENSE for details"`
-PowerShellVersion 7.0 `
-RootModule WorkMadeEasy.psm1