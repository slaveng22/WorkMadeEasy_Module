# DATA MANIPULATION
#----------------------------------------------------------------------------------------
# Get-RandomPassword
#----------------------------------------------------------------------------------------
function Get-RandomPassword {
    <#
        .SYNOPSIS
        Get random password.
        .DESCRIPTION
        Get random password. You can specify characters you want to include and password lenght
        .EXAMPLE
        Get-RandomPIN -Lenght 14
        .EXAMPLE
        Get-RandomPIN -Lenght 20 -LettersOnly
        .EXAMPLE
        Get-RandomPIN -Lenght 24 -NoSpecialCharacters
    #>
    param(
    [Parameter(Mandatory = $true)] 
    [int64]$Lenght,

    [Parameter()]
    [switch]$LettersOnly,
    [switch]$NoSpecialCharacters

    )
    if ($LettersOnly) {
        $uppercase = -join ((65..90) | Get-Random -Count 6 | ForEach-Object { [char]$_ })
        $lowercase = -join ((97..122) | Get-Random -Count 6 | ForEach-Object { [char]$_ })
        $allCharacters = $uppercase + $lowercase
        $randomPassword = -join ($allCharacters.ToCharArray() | Get-Random -Count $Lenght)        
    }
    elseif ($NoSpecialCharacters) {
        $uppercase = -join ((65..90) | Get-Random -Count 6 | ForEach-Object { [char]$_ })
        $lowercase = -join ((97..122) | Get-Random -Count 6 | ForEach-Object { [char]$_ })
        $numbers = -join ((48..57) | Get-Random -Count 6 | ForEach-Object { [char]$_ })
        $allCharacters = $uppercase + $lowercase + $numbers
        $randomPassword = -join ($allCharacters.ToCharArray() | Get-Random -Count $Lenght)
    }
    else {
        $uppercase = -join ((65..90) | Get-Random -Count 6 | ForEach-Object { [char]$_ })
        $lowercase = -join ((97..122) | Get-Random -Count 6 | ForEach-Object { [char]$_ })
        $numbers = -join ((48..57) | Get-Random -Count 6 | ForEach-Object { [char]$_ })
        $specialChars = -join ((33..47) + (58..64) + (91..96) + (123..126) | Get-Random -Count 6 | ForEach-Object { [char]$_ })
        $allCharacters = $uppercase + $lowercase + $numbers + $specialChars
        $randomPassword = -join ($allCharacters.ToCharArray() | Get-Random -Count $Lenght)
    }
    return $randomPassword
}

#----------------------------------------------------------------------------------------
# Get-RandomPIN
#----------------------------------------------------------------------------------------
function Get-RandomPIN {
    <#
        .SYNOPSIS
        Get random 4 digits number
        .DESCRIPTION
        Get random 4 digits number to user for pins
        .EXAMPLE
        Get-RandomPIN
    #>
    return Get-Random -Minimum 1000 -Maximum 9999
}


#----------------------------------------------------------------------------------------
# Format-Bytes
#----------------------------------------------------------------------------------------

function Format-Bytes {
    <#
        .SYNOPSIS
        Convert from bytes to KB, MB, GB or TB
        .DESCRIPTION
        This command will automatically convert bytes to the best possible human readable value (kb, mb, gb or tb).
        .EXAMPLE
        Format-Bytes -Bytes 137814462464
    #>
    
    param([int64]$Bytes)
    if ($Bytes -lt 1000) { return "$Bytes bytes" }
    $Bytes /= 1000
    if ($Bytes -lt 1000) { return "$($Bytes)KB" }
    $Bytes /= 1000
    if ($Bytes -lt 1000) { return "$($Bytes)MB" }
    $Bytes /= 1000
    if ($Bytes -lt 1000) { return "$($Bytes)GB" }
    $Bytes /= 1000
    return "$($Bytes)TB"
}

#----------------------------------------------------------------------------------------
# unzip
#----------------------------------------------------------------------------------------

function unzip {

    <#
        .SYNOPSIS
        Unzip file
        .DESCRIPTION
        This command will unzip specified file
        .EXAMPLE
        unzip -file test.zip
        .EXAMPLE
        unzip -file "C:\Users\usr\Desktop\test.zip"
    #>

    param (
        [Parameter(Mandatory = $true)] 
        $File
    )

    $DestinationPath = Split-Path -Path $file
    if ([string]::IsNullOrEmpty($DestinationPath)) {
        
        $DestinationPath = $PWD
    }

    if (Test-Path ($File)) {
    
        Write-Output "Extracting $File to $DestinationPath"
        Expand-Archive -Path $File -DestinationPath $DestinationPath

    }
    else {
        $FileName = Split-Path $File -leaf
        Write-Output "File $FileName does not exist"
    }  

}

# WINDOWS

#----------------------------------------------------------------------------------------
# Get-TerminalCheatsheeet
#----------------------------------------------------------------------------------------

function Get-TerminalCheatsheeet {
    <#
        .SYNOPSIS
        List Windows Terminal Shortcuts
        .DESCRIPTION
        This command will list all important Windows Terminal shortcut. You can filter them with -Filter.
        .EXAMPLE
        Get-TerminalCheatsheeet
        .EXAMPLE
        Get-TerminalCheatsheeet -Filter "Split"
        .EXAMPLE
        Get-TerminalCheatsheeet -Filter "SHIFT"
    #>
    param (
        [Parameter()]
        [string]$Filter
    )

    $table = New-Object System.Data.DataTable

    [void]$table.Columns.Add("Shortcut")
    [void]$table.Columns.Add("Action")

    [void]$table.Rows.Add("CTRL SHIFT F", "Find")
    [void]$table.Rows.Add("CTRL SHIFT D", "Duplicate tab")
    [void]$table.Rows.Add("CTRL SHIFT T", "New tab")
    [void]$table.Rows.Add("CTRL TAB", "Next tab")
    [void]$table.Rows.Add("CTRL SHIFT TAB", "Previous tab")
    [void]$table.Rows.Add("ALT SHIFT D ", "Duplicate pane (vertically)")
    [void]$table.Rows.Add("ALT SHIFT +", "Split vertically (Doesn't work with NUM)")
    [void]$table.Rows.Add("ALT SHIFT -", "Split horizontally (Doesn't work with NUM)")
    [void]$table.Rows.Add("ALT SHIFT Left or right arrow key", "Resize vertical pane")
    [void]$table.Rows.Add("ALT SHIFT Up or down arrow key", "Resize horizontal pane")
    [void]$table.Rows.Add("ALT Arrow keys", "Move between panes")
    [void]$table.Rows.Add("CTRL SHIFT W", "Close pane, tab or window")
    
    if ($Filter) {
        $table | Where-Object { $_.Action -match $Filter -or $_.Shortcut -match $Filter }

    }
    else {

        $table
    }

}

#----------------------------------------------------------------------------------------
# Get-WinRShortcut
#----------------------------------------------------------------------------------------

function Get-WinRShortcut {

    <#
        .SYNOPSIS
        Find Win+R shortcut
        .DESCRIPTION
        This command will get you a windows + r shortcut based on description you provide. When used with -run switch, it will run the shortcut.
        .EXAMPLE
        Get-WinRShortcut -Filter "Resource Monitor"
        .EXAMPLE
        Get-WinRShortcut -Filter "Resource Monitor" -Run
    #>

    param (
        [Parameter(mandatory = $true)]
        $Filter,
    
        [Parameter()]
        [switch]$Run
    )

    $shortcuts = @{

        "msconfig"            = "System Settings, Manage Services, Boot in Safe Mode";
        "msinfo32"            = "System Information";
        "sysdm.cpl"           = "System Properties, Rename PC, Add to Domain, Remove user profiles, Enable RDP";
        "resmon"              = "Resource Monitor";
        "main.cpl"            = "Mouse Settings";
        "mstsc"               = "Remote Desktop Service";
        "cmd"                 = "The Command Prompt";
        "certmgr.msc"         = "Current User Certificates";
        "explorer"            = "Windows Explorer";
        "taskmgr"             = "Task Manager";
        "shutdown"            = "Windows Shutdown";
        "chkdsk"              = "Check Disk Utility";
        "cleanmgr"            = "Clean Disk Manager";
        "dxdiag"              = "DirectX Options";
        "powershell"          = "Windows PowerShell Console";
        "winver"              = "Windows Version";
        "control folders"     = "Folder Options";
        "diskmgmt.msc"        = "Disk Manager Format Disk Resize Volume";
        "eventvwr.msc"        = "Event Viewer";
        "gpedit.msc"          = "Local Group Policy Editor";
        "secpol.msc"          = "Local Security Policy";
        "regedit"             = "Registry Editor";
        "powercfg.cpl"        = "Power Options";
        "magnify"             = "Magnifier";
        "charmap"             = "Windows Character Table";
        "ncpa.cpl"            = "Network Connections";
        "mrt"                 = "Malware Removal Tool";
        "devmgmt.msc"         = "Device Manager";
        "netplwiz"            = "User accounts";
        "services.msc"        = "Services";
        "appwiz.cpl"          = "Programs and Components";
        "control"             = "Control Panel";
        "."                   = "Open the folder of the current user";
        "osk"                 = "On-Screen Keyboard";
        "snippingtool"        = "Screenshot Tool";
        "mdsched"             = "Windows memory checker";
        "Outlook /cleanviews" = "Resets view on Outlook";
        "psr"                 = "Steps recorder";
        "mmc"                 = "Microsoft Management Console";
        "lusrmgr.msc"         = "Local Users and Groups";
    }    
    
    # Filter the shortcuts based on the description
    $filteredShortcuts = $shortcuts.GetEnumerator() | Where-Object { $_.Value -like "*$Filter*" }

    foreach ($item in $filteredShortcuts) {
        Write-Host "`nShortcut: " -NoNewline
        Write-Host $item.Key -NoNewline -ForegroundColor Green
        Write-Host "`nDescription: " -NoNewline
        Write-Host $item.Value
    }
    # Run based on shortcut type
    if ($Run) {
        $command = $item.Key

        if ($command -match " ") {
            if ($command -match "/") {
                
                $splitCommand = $command.Split(" ", 2)
                $cmd = $splitCommand[0]
                $arglst = $splitCommand[1]
                Start-Process -FilePath $cmd -ArgumentList $arglst
            }
            else {
                
                Invoke-Expression $command
            }
        }
        else {
            
            Start-Process -FilePath $command
        }
    }
        
}

#----------------------------------------------------------------------------------------
# Open-AsAdmin
#----------------------------------------------------------------------------------------

function Open-AsAdmin {

    <#
        .SYNOPSIS
        Open Windows Terminal as admin or run command as admi
        .DESCRIPTION
        This command will run windows terminal as admin. If you specify a command after, it will run it as admin. (similar to sudo)
        .EXAMPLE
        Open-AsAdmin
        .EXAMPLE
        Open-AsAdmin Get-Service
    #>

    if ($args.Count -gt 0) {   
        $argList = @("powershell.exe", "-NoExit") + $args
        Start-Process "wt.exe" -Verb runAs -ArgumentList $argList
    }
    else {
        Start-Process "wt.exe" -Verb runAs -ArgumentList "powershell.exe -NoExit"
    }
}


#----------------------------------------------------------------------------------------
# Update-Software
#----------------------------------------------------------------------------------------
function Update-Software {

    <#
        .SYNOPSIS
        Update software on local or remote computer
        .DESCRIPTION
        This command will silently update all software on local or specified computer.
        If you run this command with -ComputerName parameter you will be prompted for admin credentials for specified computer.
        .EXAMPLE
        Update-Software
        .EXAMPLE
        Update-Software -ComputerName PC01
    #>

    param (
        $ComputerName
    )

    if ($ComputerName) {
        $cred = Get-Credential
        $s = New-PSSession -ComputerName $ComputerName -Credential $cred

        Invoke-Command -Session $s -ScriptBlock {
            if (!(Get-AppxPackage Microsoft.DesktopAppInstaller)) {
                try { Add-AppPackage -RegisterByFamilyName -MainPackage Microsoft.DesktopAppInstaller_8wekyb3d8bbwe }
                catch { Write-Error "Couldn't install Winget!!!" -Category NotInstalled -RecommendedAction "Try to install from microsoft store!" }
            }
            else {
                try {
                    winget upgrade --all --accept-source-agreements --accept-package-agreements --force --silent
                    Write-Host 'Software updated. Please restart your PC to verify update!' -ForegroundColor Green
                }
                catch {
                    Write-Host 'An error occurred while updating the software.' -ForegroundColor Red
                    Write-Host "Error details: $_" -ForegroundColor Red
                }                
            }
        }
    }
    else {
        if (!(Get-AppxPackage Microsoft.DesktopAppInstaller)) {
            try { Add-AppPackage -RegisterByFamilyName -MainPackage Microsoft.DesktopAppInstaller_8wekyb3d8bbwe }
            catch { Write-Error "Couldn't install Winget!!!" -Category NotInstalled -RecommendedAction "Try to install from microsoft store!" }
        }
        else {
            try {
                winget upgrade --all --accept-source-agreements --accept-package-agreements --force --silent
                Write-Host 'Software updated. Please restart your PC to verify update!' -ForegroundColor Green
            }
            catch {
                Write-Host 'An error occurred while updating the software.' -ForegroundColor Red
                Write-Host "Error details: $_" -ForegroundColor Red
            }
        }
    }
}

#----------------------------------------------------------------------------------------
# Get-RDPHealth
#----------------------------------------------------------------------------------------

function Get-RDPHealth {

    <#
        .SYNOPSIS
        Troubleshoot RDP
        .DESCRIPTION
        This command will troubleshoot RDP services on local PC or on specified remote computer and provide a report for you. 
        .EXAMPLE
        Get-RDPHealth
        .EXAMPLE
        Get-RDPHealth -ComputerName PC01
    #>

    [cmdletBinding()]
    param (
        [string]$ComputerName = $env:COMPUTERNAME
    )
    
    #RDP Service array
    $RDPServices = @("TermService", "UmRdpService")
    
    $ParamHash = [ordered]@{
        Ping        = "Failed"
        FQDN        = "Failed"
        RDPPort     = "Failed"
        RDPServices = "Failed"
        RDPSettings = "Disabled"
        RDPwithNLA  = "Enabled"
    }
    try {
    
        #Check FQDN
        if ($DNS = ([System.Net.Dns]::GetHostEntry($ComputerName)).HostName) { $ParamHash["FQDN"] = "Ok" ; $ComputerName = $DNS }
                
    
        if (Test-Connection -ComputerName $ComputerName -Count 1 -Quiet) {
    
            $ParamHash["Ping"] = "Ok"
                            
            #Check the Firewall            
            if (New-Object Net.sockets.TcpClient($ComputerName, 3389)) { 
                $ParamHash["RDPPort"] = "Ok" 
            }
            else { 
                $ParamHash["RDPPort"] = "Failed" 
            }
                
            #Check the Services            
            if ($RDPServices | ForEach-Object { Get-WmiObject Win32_Service -ComputerName $ComputerName -Filter "Name = '$($_)' and state = 'Stopped'" }) {
                $ParamHash["RDPServices"] = "Failed"
            }
            else {
                $ParamHash["RDPServices"] = "Ok" 
            }
                           
            #Check the RDP Settings(Enabled\Disabled)
            if ((Get-WmiObject -Class Win32_TerminalServiceSetting -Namespace root\CIMV2\TerminalServices -ComputerName $ComputerName -Authentication 6).AllowTSConnections -eq 1) {
                $ParamHash["RDPSettings"] = "Enabled"          
            }
                             
            #Check the RDP NLA Settings	
            if ((Get-WmiObject -class Win32_TSGeneralSetting -Namespace root\cimv2\terminalservices -ComputerName $ComputerName -Filter "TerminalName='RDP-tcp'" -Authentication 6).UserAuthenticationRequired -eq 0 ) {
                $ParamHash["RDPwithNLA"] = "Disabled"
                                     
            }
        }
        else {
                          
            $ParamHash["RDPSettings"] = "Failed"
            $ParamHash["RDPwithNLA"] = "Failed"
        }
                                  
    }
    catch {
                
        Write-Host "$ComputerName :: $_.Exception.Message" -ForegroundColor Red
        $ParamHash["RDPSettings"] = "Failed"
        $ParamHash["RDPwithNLA"] = "Failed"
    }
        
    Write-Host ("`t`t`t`RDP Connectivity Check : $ComputerName").ToUpper()  -ForegroundColor Green
        
    #Format the Output
    $length = 0
    $ParamHash.Keys | ForEach-Object { if (($_).length -ge $length) { $length = ($_).length } }
    $ParamHash.Keys | ForEach-Object { Write-Host "$(($_).PadRight($length,'.'))..................................................$($ParamHash[$_]) " -ForegroundColor Yellow }
    
}

#----------------------------------------------------------------------------------------
# Set-PowerPlan
#----------------------------------------------------------------------------------------

function Set-PowerProfile {
    
    <#
        .SYNOPSIS
        Sets a power plan
        .DESCRIPTION
        This command will configure a power plan for you Battery life or for Best performance and set it active.
        It also allows you to go back to Balanced plan
        .EXAMPLE
        Set-PowerProfile -BatteryLife
        .EXAMPLE
        Set-PowerProfile -Performance
        .EXAMPLE
        Set-PowerProfile -Balanced
        
    #>
    
    
    [CmdletBinding()]
    param (
        [switch]$BatteryLife,
        [switch]$Performance,
        [switch]$Balanced
    )

    if ($BatteryLife) {
        
        # Batery Life
        $PowerPlan = powercfg -duplicatescheme a1841308-3541-4fab-bc81-f71556f20b4a
        $regex = [regex]"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"
        $guid = $regex.Match($PowerPlan).Value
        $guid

        powercfg -changename $guid "Battery Life Optimized"
        powercfg -change -monitor-timeout-ac 5
        powercfg -change -monitor-timeout-dc 2
        powercfg -change -disk-timeout-ac 10
        powercfg -change -disk-timeout-dc 5
        powercfg -change -standby-timeout-ac 15
        powercfg -change -standby-timeout-dc 10
        powercfg -change -hibernate-timeout-ac 30
        powercfg -change -hibernate-timeout-dc 15
        powercfg -change -processor-throttle-ac 0
        powercfg -change -processor-throttle-dc 0
        powercfg -setacvalueindex $guid SUB_PROCESSOR PROCTHROTTLEMAX 50
        powercfg -setdcvalueindex $guid SUB_PROCESSOR PROCTHROTTLEMAX 30

        powercfg -setactive $guid

    }
    elseif ($Performance) {
        
        # Best Performance
        $PowerPlan = powercfg -duplicatescheme 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c
        $regex = [regex]"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"
        $guid = $regex.Match($PowerPlan).Value
        $guid


        powercfg -changename $guid "Best Performance"

        powercfg -change -monitor-timeout-ac 0
        powercfg -change -monitor-timeout-dc 0
        powercfg -change -disk-timeout-ac 0
        powercfg -change -disk-timeout-dc 0
        powercfg -change -standby-timeout-ac 0
        powercfg -change -standby-timeout-dc 0
        powercfg -change -hibernate-timeout-ac 0
        powercfg -change -hibernate-timeout-dc 0
        powercfg -change -processor-throttle-ac 100
        powercfg -change -processor-throttle-dc 100
        powercfg -setacvalueindex $guid SUB_PROCESSOR PROCTHROTTLEMAX 100
        powercfg -setdcvalueindex $guid SUB_PROCESSOR PROCTHROTTLEMAX 100
        powercfg -setacvalueindex $guid SUB_PROCESSOR PROCTHROTTLEMIN 100
        powercfg -setdcvalueindex $guid SUB_PROCESSOR PROCTHROTTLEMIN 100
        powercfg -setacvalueindex $guid SUB_PROCESSOR PERFINCTHRESHOLD 100
        powercfg -setdcvalueindex $guid SUB_PROCESSOR PERFINCTHRESHOLD 100

        powercfg -setactive $guid

    }
    elseif ($Balanced) {

        # Balanced
        powercfg -setactive 381b4222-f694-41f0-9685-ff5bb260df2e
    }
    else {
        Write-Output "Please specify a configuration -BatteryLife, -Performance, or -Balanced."
    }
    
}

#----------------------------------------------------------------------------------------
# Get-NetworkInstalledPrinters
#----------------------------------------------------------------------------------------
function Get-NetworkInstalledPrinters {

    <#
        .SYNOPSIS
        List all Network installed printers.
        .DESCRIPTION
        This command will provide a list of all network installed printers on local PC or on specified remote computer.
        Command only list printers which are added from print server with Computer GPO.
        .EXAMPLE
        Get-NetworkInstalledPrinters
        .EXAMPLE
        Get-NetworkInstalledPrinters -ComputerName PC01
    #>

    [cmdletBinding()]
    param (
        [string]$ComputerName
    )
    
    if ($ComputerName) {
        Invoke-Command -ComputerName $ComputerName -ScriptBlock {  
            $InstalledPrinters = Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Print\Connections"  
            $InstalledPrinters | Add-Member -Name 'PrinterName' -MemberType NoteProperty -Value ""  
            Foreach ($InstalledPrinter in $InstalledPrinters) { $InstalledPrinter.PrinterName = $InstalledPrinter.GetValue("Printer").split("\")[3] }  
            Return $InstalledPrinters | Sort-Object PrinterName | Select-Object PSComputerName, PrinterName  
        }
    }
    else {
        $InstalledPrinters = Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Print\Connections"  
        $InstalledPrinters | Add-Member -Name 'PrinterName' -MemberType NoteProperty -Value ""  
        Foreach ($InstalledPrinter in $InstalledPrinters) { $InstalledPrinter.PrinterName = $InstalledPrinter.GetValue("Printer").split("\")[3] }  
        Return $InstalledPrinters | Sort-Object PrinterName | Select-Object PrinterName

    }
}

#----------------------------------------------------------------------------------------
# Get-LoggedInUserSession Close-LoggedInUserSession
#----------------------------------------------------------------------------------------
function Get-LoggedInUserSession {
    <#
        .SYNOPSIS
        List all logged in users
        .DESCRIPTION
        This command will provide a list of all logged in users on local or specified computer.
        .EXAMPLE
        Get-LoggedInUserSession
        .EXAMPLE
        Get-LoggedInUserSession -ComputerName "PC01"
    #>

    param (
        [string]$ComputerName
    )

    $output = if ($ComputerName) {
        quser /server:$ComputerName
    } else {
        quser
    }

    if ($output -match "No user exists") {
        Write-Output "No users are currently logged in."
        return
    }

    $lines = $output -split "`n"
    $headers = $lines[0] -split "\s{2,}"
    $users = @()

    for ($i = 1; $i -lt $lines.Length; $i++) {
        $line = $lines[$i]
        if ($line -match "^\s*(\S+)\s+(\S+)?\s+(\d+)\s+(\S+)\s+(\S+)\s+(\d{2}\.\d{2}\.\d{4}\s+\d{2}:\d{2})\s*$") {
            $user = [PSCustomObject]@{
                USERNAME    = $matches[1]
                SESSIONNAME = if ($matches[2]) { $matches[2] } else { "" }
                ID          = $matches[3]
                STATE       = $matches[4]
                IDLE_TIME   = $matches[5]
                LOGON_TIME  = $matches[6]
            }
            $users += $user
        } else {
            Write-Output "Unexpected line format: $line"
        }
    }

    return $users
}

function Close-LoggedInUserSession {

    <#
        .SYNOPSIS
        Logs out user from PC
        .DESCRIPTION
        This command lets you logout specified user on local or specified computer. Use Get-LoggedInUserSession to get user ID and use it in this command.
        .EXAMPLE
        Close-LoggedInUserSession -UserSessionID 3
        .EXAMPLE
        Close-LoggedInUserSession -UserSessionID 3 -ComputerName PC01
    #>

    param (
        [Parameter(Position = 0, mandatory = $true)]
        [string]$UserSessionID,
        [string]$ComputerName
    )
    if ($ComputerName) {
        Logoff $UserSessionID /server:$ComputerName
    }
    else {
        Logoff $UserSessionID
    }
}

#----------------------------------------------------------------------------------------
# Get-InstalledSoftwareList
#----------------------------------------------------------------------------------------
function Get-InstalledSoftwareList {

    <#
        .SYNOPSIS
        List all installed software on local or remote PC.
        .DESCRIPTION
        This command will provide you a list of all installed software on local or specified computer. It needs to be run as admin!
        .EXAMPLE
        Get-InstalledSoftwareList
        .EXAMPLE
        Get-InstalledSoftwareList -ComputerName PC01
    #>

    param(
        [string]$ComputerName = $env:COMPUTERNAME
    )
    if ([bool](([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match "S-1-5-32-544")) {
        Get-CimInstance Win32_InstalledWin32Program -ComputerName $ComputerName | Select-Object Name, Version, Vendor | Sort-Object Name
    }
    else {
        Write-Error -Message "This Command needs to be run as administrator. Run Open-AsAdmin to open admin windows "
    }
}

#----------------------------------------------------------------------------------------
# Get-LocalProfiles Remove-LocalProfile
#----------------------------------------------------------------------------------------
function Get-LocalProfiles {

    <#
        .SYNOPSIS
        List all users profile on computer
        .DESCRIPTION
        This command will list all user profiles on local specified computer.
        Command can run only on remote PC. If you are not admin on specified PC, you will need to provide admin credentials with -Credential parameter.
        .EXAMPLE
        Get-LocalProfiles
        .EXAMPLE
        Get-LocalProfiles -ComputerName PC01
    #>

    param (
        [string]$ComputerName,
        [Parameter()]
        [ValidateNotNull()]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credentials = [System.Management.Automation.PSCredential]::Empty 
    )
    if ($ComputerName) {
        Invoke-Command -ComputerName $ComputerName -Credential $Credentials -ScriptBlock { Get-CimInstance -ClassName win32_userprofile } | Select-Object localpath, sid
    }
    else {
        Get-CimInstance -ClassName win32_userprofile | Select-Object localpath, sid
    }
}


function Remove-LocalProfile {

    <#
        .SYNOPSIS
        Delete user profile on computer
        .DESCRIPTION
        This command lets you delete a userprofile on local or specified computer. This command will delete also delete user folder.
        You can only run command as administrator. If you are not admin on specified PC, you will need to provide admin credentials with -Credential parameter.
        Command you prompt you to confirm deletion.
        .EXAMPLE
        Remove-LocalProfile -UserProfile USR
        .EXAMPLE
        Remove-LocalProfile -UserProfile USR -Computername PC01
        .EXAMPLE
        Remove-LocalProfile -UserProfile USR -Computername PC01 -Credentials Admin
    #>


    param (
        [Parameter(Position = 0, Mandatory = $true)]
        [string]$UserProfile,
        [string]$ComputerName,
        [Parameter()]
        [ValidateNotNull()]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credentials = [System.Management.Automation.PSCredential]::Empty
    )
    if ($ComputerName) {
        Invoke-Command -ComputerName $ComputerName -Credential $Credentials -ScriptBlock {
            param($UserProfile)
        
            $path = (Get-CimInstance -ClassName win32_userprofile | Where-Object { $_.localPath -like "*$UserProfile" }).localPath
            $elements = $path.Split('\')
            $UserName = $elements[-1]
            Write-Host "You are going to remove $UserName local profile"

            Get-CimInstance -ClassName win32_userprofile | Where-Object { $_.localPath -like "*$UserProfile" } | Remove-CimInstance -Confirm
        
            try {
                $Check = Get-CimInstance -ClassName win32_userprofile | Where-Object { $_.localPath -like "*$UserProfile" }
            
                if ([string]::IsNullOrEmpty($Check)) {
                    Write-Host "Profile removed successfully" -ForegroundColor Green
                }
                else {
                    Write-Host "Profile removing failed" -ForegroundColor Red
                }
            }
            catch {
                Write-Host "An error occurred: $_"
            }
        } -ArgumentList $UserProfile
    }
    else {
        $path = (Get-CimInstance -ClassName win32_userprofile | Where-Object { $_.localPath -like "*$UserProfile" }).localPath
        $elements = $path.Split('\')
        $UserName = $elements[-1]
        Write-Host "You are going to remove $UserName local profile"

        Get-CimInstance -ClassName win32_userprofile | Where-Object { $_.localPath -like "*$UserProfile" } | Remove-CimInstance -Confirm
    
        try {
            $Check = Get-CimInstance -ClassName win32_userprofile | Where-Object { $_.localPath -like "*$UserProfile" }
        
            if ([string]::IsNullOrEmpty($Check)) {
                Write-Host "Profile removed successfully" -ForegroundColor Green
            }
            else {
                Write-Host "Profile removing failed" -ForegroundColor Red
            }
        }
        catch {
            Write-Host "An error occurred: $_"
        }
    }
}

# MICROSOFT365

#----------------------------------------------------------------------------------------
# Get-LargestMailbox
#----------------------------------------------------------------------------------------

#This script is downloaded from the internet
function Get-LargestMailbox {

    <#
        .SYNOPSIS
        List 10 largest mailboxes
        .DESCRIPTION
        This command gives you 10 largest mailboxes in Exchange Online.
        .EXAMPLE
        Get-LargestMailbox
    #>

    # Check do you have Exchange module, if not install it.
    If (!(Get-Module -ListAvailable | Where-Object { $_.name -like "*ExchangeOnlineManagement*" })) {
        try {
            Install-Module ExchangeOnlineManagement -Scope CurrentUser -Force -ErrorAction SilentlyContinue
        }
        catch {
            Write-Error -Message "Exchange Online Management module can't be installed. Try to install module manually and run command again"
        }       
    }
    else {
        Import-Module ExchangeOnlineManagement -ErrorAction SilentlyContinue  
    }    

    # Check are you connected to Exchange Online, if not connect.
    if (!(Get-ConnectionInformation)) {
        Connect-ExchangeOnline -ShowBanner: $false
    }
    
    Get-Mailbox -ResultSize Unlimited |
    Get-MailboxStatistics |
    Select-Object DisplayName,
    @{name = "TotalItemSize (GB)"; expression = { [math]::Round((($_.TotalItemSize.Value.ToString()).Split("(")[1].Split(" ")[0].Replace(",", "") / 1GB), 2) } } |
    Sort-Object "TotalItemSize (GB)" -Descending |
    Select-Object -first 10

}

#----------------------------------------------------------------------------------------
# Add-UserToSharedMailbox
#----------------------------------------------------------------------------------------
function Add-UserToSharedMailbox {

    <#
        .SYNOPSIS
        Add User to Shared Mailbox
        .DESCRIPTION
        This command gives user Full Access Rights and Send As permission to specified shared mailbox. (Needs work on authentication)
        .EXAMPLE
        Add-UserToSharedMailbox -User user@domain.com -Mailbox sharedmailbox@domain.com
    #>

    param (
        [Parameter(Position = 0, mandatory = $true)]
        $User,
        [Parameter(Position = 1, mandatory = $true)]
        $Mailbox
    )

    # Check do you have Exchange module, if not install it.
    If (!(Get-Module -ListAvailable | Where-Object { $_.name -like "*ExchangeOnlineManagement*" })) {
        try {
            Install-Module ExchangeOnlineManagement -Scope CurrentUser -Force -ErrorAction SilentlyContinue
        }
        catch {
            Write-Error -Message "Exchange Online Management module can't be installed. Try to install module manually and run command again"
        }       
    }
    else {
        Import-Module ExchangeOnlineManagement -ErrorAction SilentlyContinue  
    }    

    # Check are you connected to Exchange Online, if not connect.
    if (!(Get-ConnectionInformation)) {
        Connect-ExchangeOnline -ShowBanner: $false
    }
    #AddUser Full Permissions to mailbox
    ADD-MailboxPermission -Identity $Mailbox -User $User -AccessRights FullAccess -AutoMapping: $false
    #Add User send as permission to mailbox
    ADD-RecipientPermission $Mailbox -AccessRights SendAs -Trustee $user -Confirm: $false
}

#----------------------------------------------------------------------------------------
# Find-SPSOwner
#----------------------------------------------------------------------------------------
function Find-SPSOwner {

    <#
        .SYNOPSIS
        List all SP sites where user is owner.
        .DESCRIPTION
        This command gives a list of all SharePoint sites where user is owner.
        .EXAMPLE
        Find-SPSOwner -User user@domain.com
    #>

    param (
        [parameter(mandatory = $true)]
        [string]$User
    )

    # Check if MS Graph is installed, if not install it.

    if (!(Get-InstalledModule Microsoft.Graph)) {
        Install-Module Microsoft.Graph -Scope CurrentUser -Force
    }

    # Check if you are connected to MS Graph, if not connect
    $scopes = (Get-MgContext | Select-Object -ExpandProperty Scopes)
    if (!($scopes -contains 'User.Read.All' -and $scopes -contains 'Group.Read.All')) {
        Connect-MgGraph -Scopes Group.Read.All, User.Read.All -NoWelcome
    }

    $UserCheck = Get-MGUSer -UserId $User -ErrorAction SilentlyContinue
    if ($UserCheck) {
        $Groups = Get-MgGroup -All

        foreach ($Group in $Groups) {

            $Users = Get-MgGroupOwner -GroupId $Group.Id
            $GroupName = $Group.DisplayName


            foreach ($U in $Users) {
                $Owner = (Get-MgUser -UserId $U.Id).Mail
                if ($Owner -eq $User) {
       
                    Write-Host "$Owner owns $GroupName"

                }
            }
        }
    }
    else {
        Write-Error -Message "User can't be found. Check spelling and make sure you are using UPN"
    }
}

#----------------------------------------------------------------------------------------
# Get-MailboxPermissionList
#----------------------------------------------------------------------------------------

function Get-MailboxPermissionList {

    <#
        .SYNOPSIS
        Creates a list of exchange mailbox permissions for specific user.
        .DESCRIPTION
        This command will create a list of mailboxes to which specific user has permissions to.
        .EXAMPLE
        Get-MailboxPermissionList -User

    #>

    param (
        [parameter(mandatory = $true)]
        [string]$User
    )

    # Check do you have Exchange module, if not install it.
    If (!(Get-Module -ListAvailable | Where-Object { $_.name -like "*ExchangeOnlineManagement*" })) {
        try {
            Install-Module ExchangeOnlineManagement -Scope CurrentUser -Force -ErrorAction SilentlyContinue
        }
        catch {
            Write-Error -Message "Exchange Online Management module can't be installed. Try to install module manually and run command again"
        }       
    }
    else {
        Import-Module ExchangeOnlineManagement -ErrorAction SilentlyContinue  
    }       

    # Check if you are connected to Exchange online, if not connect.
    if (!(Get-ConnectionInformation)) {
        Connect-ExchangeOnline -ShowBanner: $false
    }
    # Get a list of mailboxes
    $mailboxes = Get-Mailbox -ResultSize Unlimited
    # Load array
    $permissions = @()
    # Go trough each mailbox and write all mailboxes to which specific user has permissions and write it in output
    foreach ($mailbox in $mailboxes) {

        Write-Progress -activity "Getting permissions for mailbox $($mailbox.UserPrincipalName)" -status "Processing..."
        $permissions += Get-MailboxPermission -Identity $mailbox.UserPrincipalName | Where-Object { $_.User -eq $User }

    }
    $permissions | Format-Table

}

#----------------------------------------------------------------------------------------
# Get-DeviceOwner
#----------------------------------------------------------------------------------------

function Get-DeviceOwner {

    <#
        .SYNOPSIS
        Find who is owner of device
        .DESCRIPTION
        List all users that have logged in to Microsoft 365 to specific device.
        .EXAMPLE
        Get-DeviceOwner -ComputerName PC01

    #>

    param (
        [parameter(mandatory = $true)]
        [string]$ComputerName
    )
    
    # Connect to MS Graph
    $scopes = (Get-MgContext | Select-Object -ExpandProperty Scopes)
    if (!($scopes -contains 'Directory.Read.All' -and $scopes -contains 'Device.Read.All' -and $scopes -contains 'User.Read.All')) {
        Connect-MgGraph -Scopes Directory.Read.All, Device.Read.All, User.Read.All -NoWelcome
    }

    $Devices = Get-MgDevice -Filter "DisplayName eq '$ComputerName'" -Property *
    if (!$Devices) {
        Write-Host "Device $ComputerName not found." -ForegroundColor Red
        return
    }

    $AllRegisteredUsers = @()
    $Devices | ForEach-Object {
    
        $RegisteredUsers = Get-MgDeviceRegisteredUser -DeviceId $_.Id
        $AllRegisteredUsers += $RegisteredUsers

    }

    $UserNames = @()
    $AllRegisteredUsers | ForEach-Object {

        $UserName = Get-MgUser -UserId $_.Id
        $UserNames += $UserName

    }

    if ($AllRegisteredUsers) {
        Write-Host "Users associated with device $ComputerName" -ForegroundColor Green
        Write-Host "--------------------------------------------------------------------------------"
        $UserNames | ForEach-Object {
            Write-Host "User: $($_.DisplayName) ($($_.UserPrincipalName))"
            Write-Host "--------------------------------------------------------------------------------"
        }
    }
    else {
        Write-Host "No users found for device $ComputerName" -ForegroundColor Yellow
    }

}

#----------------------------------------------------------------------------------------
# Get-LastUsedDevices
#----------------------------------------------------------------------------------------

function Get-LastUsedDevices {

    <#
        .SYNOPSIS
        Find last 5 devices, user has been logged in to
        .DESCRIPTION
        List all 5 devices to which specific user has been logged in to. Gives info about PC OS, and time when user logged in to PC
        .EXAMPLE
        Get-LastUsedDevices -User user@contoso.com

    #>

    param (
        [parameter(mandatory = $true)]
        $User
    )
    

    $scopes = (Get-MgContext | Select-Object -ExpandProperty Scopes)
    if (!($scopes -contains 'User.Read.All' -and $scopes -contains 'Device.Read.All')) {
        Connect-MgGraph -Scopes User.Read.All, Device.Read.All -NoWelcome
    }

    $UserID = (Get-MgUser -Filter "userPrincipalName eq '$User'").Id

    if (!$UserID) {
        Write-Host "User $User not found." -ForegroundColor Red
        return
    }


    $RegisteredDevices = Get-MgUserRegisteredDevice -UserId $UserID -All:$true

    $DevicesProperties = $RegisteredDevices | Foreach-Object {

        Get-MgDevice -DeviceId $_.Id -Property * | Select-Object DisplayName, OperatingSystem, OperatingSystemVersion, ApproximateLastSignInDateTime 

    }


    Write-Host "User $User last used devices:" -ForegroundColor Green
    Write-Host ""
    Write-Host "--------------------------------------------------------------------------------------------------------------" -ForegroundColor Green
    $DevicesProperties | Sort-Object -Property ApproximateLastSignInDateTime -Descending | Select-Object -First 5

}


#----------------------------------------------------------------------------------------
# Get-AllSharedMailboxesPermissions
#----------------------------------------------------------------------------------------

function Get-AllSharedMailboxesPermissions {

    <#
    .SYNOPSIS
    Creates a list of all shared mailboxes and users who have full access to them
    .DESCRIPTION
    Cycles trough each shared mailbox, Full Access permission on this mailbox and creates a report
    .EXAMPLE
    Get-AllSharedMailboxesPermissions
#>


    # Check do you have Exchange module, if not install it.
    If (!(Get-Module -ListAvailable | Where-Object { $_.name -like "*ExchangeOnlineManagement*" })) {
        try {
            Install-Module ExchangeOnlineManagement -Scope CurrentUser -Force -ErrorAction SilentlyContinue
        }
        catch {
            Write-Error -Message "Exchange Online Management module can't be installed. Try to install module manually and run command again"
        }       
    }
    else {
        Import-Module ExchangeOnlineManagement -ErrorAction SilentlyContinue  
    }    

    # Check are you connected to Exchange Online, if not connect.
    if (!(Get-ConnectionInformation)) {
        Connect-ExchangeOnline -ShowBanner: $false
    }

    # Get all mailboxes and generate report
    $mailboxes = Get-Mailbox -ResultSize Unlimited -Filter ('RecipientTypeDetails -eq "SharedMailbox"')
    foreach ($m in $mailboxes) { 
        Write-Host "Users that have permissions to $($m.UserPrincipalName)" -ForegroundColor Green
        Write-Host "----------------------------------------------------------------------------------------" -ForegroundColor Green
        Get-MailboxPermission -Identity $m.UserPrincipalName -ResultSize Unlimited | `
            Where-Object { ($_.IsInherited -eq $false) -and ($_.User -ne "NT AUTHORITY\SELF") } | `
            Select-Object Identity, User, AccessRights | Format-Table 

    }

}


# ACTIVE DIRECTORY

#----------------------------------------------------------------------------------------
# Find-BitLockerPC
#----------------------------------------------------------------------------------------

#This script is downloaded from the internet
function Find-BitLockerPC {

    <#  
        .SYNOPSIS
        Create report of AD joined computers which have BitLocker enabled
        .DESCRIPTION
        This command gives a list of all workstations in the domain which have BitLocker enabled and creates report. 
        Report will be created in the path where the command is run from, unless -ReportPath is specified.
        You can search the whole domain, or specify the OU with -SearchBase parameter.
        .EXAMPLE
        Find-BitLockerPC
        .EXAMPLE
        Find-BitLockerPC -SearchBase "OU=Company-Computers,DC=domain,DC=local" -ReportPath "C:\Users\usr\Documents\WorkstationsWithBitLocker.csv"
    #>

    [CmdletBinding()]
    Param (
        [string]$SearchBase = (Get-ADDomain).DistinguishedName,
        [string]$ReportPath = $(Join-Path (Split-Path $MyInvocation.MyCommand.Path) -ChildPath "WorkstationsWithBitLocker.csv")
    )
    #AD module is not necessary in my current environment. Uncomment if you change environment
    #Try { Import-Module ActiveDirectory -ErrorAction Stop }
    #Catch { Write-Warning "Unable to load Active Directory module because $($Error[0])"; Exit }


    Write-Verbose "Getting Workstations..." -Verbose
    $Computers = Get-ADComputer -Filter * -SearchBase $SearchBase -Properties LastLogonDate
    $Count = 1
    $Results = ForEach ($Computer in $Computers) {
        Write-Progress -Id 0 -Activity "Searching Computers for BitLocker" -Status "$Count of $($Computers.Count)" -PercentComplete (($Count / $Computers.Count) * 100)
        New-Object PSObject -Property @{
            ComputerName         = $Computer.Name
            LastLogonDate        = $Computer.LastLogonDate 
            BitLockerPasswordSet = Get-ADObject -Filter "objectClass -eq 'msFVE-RecoveryInformation'" -SearchBase $Computer.distinguishedName -Properties msFVE-RecoveryPassword, whenCreated | Sort-Object whenCreated -Descending | Select-Object -First 1 | Select-Object -ExpandProperty whenCreated
        }
        $Count ++
    }
    Write-Progress -Id 0 -Activity " " -Status " " -Completed

    Write-Verbose "Building the report..." -Verbose
    $Results | Select-Object ComputerName, LastLogonDate, BitLockerPasswordSet | Sort-Object ComputerName | Export-Csv $ReportPath -NoTypeInformation
    Write-Verbose "Report saved at: $ReportPath" -Verbose
}

#----------------------------------------------------------------------------------------
# Copy-ADGroupMembership
#----------------------------------------------------------------------------------------

function Copy-ADGroupMembership {

    <#
        .SYNOPSIS
        Copy users from one AD group to another
        .DESCRIPTION
        This command will copy all members from one Active Directory group to another
        .EXAMPLE
        Copy-ADGroupMembership -SourceGroup Group01 -Destination Group02
    #>

    param (
        [Parameter(Position = 0, Mandatory = $true)]
        $SourceGroup,
        [Parameter(Position = 1, Mandatory = $true)]
        $DestinationGroup
    )
    Get-ADGroupMember -Identity $SourceGroup | ForEach-Object { Add-ADGroupMember -Identity $DestinationGroup -Members $_.distinguishedName }
}


#----------------------------------------------------------------------------------------
# Get-InactiveUser
#----------------------------------------------------------------------------------------

function Get-InactiveUsers {

    <#
        .SYNOPSIS
        Returns users who are inactive for a specified period of time.
        
        .DESCRIPTION
        This command will give you a list of all users that never logged in or didn't log in for a long time.
        You can search the whole domain or just specific OUs using the SearchBase parameter.
        You can use the -IncludeDisabled switch to include users who are disabled in AD.
        
        .EXAMPLE
        Get-InactiveUsers -MonthsSinceLastLogin 6
        
        .EXAMPLE
        Get-InactiveUsers -MonthsSinceLastLogin 6 -SearchBase "DC=domain,DC=local"
        
        .EXAMPLE
        Get-InactiveUsers -MonthsSinceLastLogin 6 -IncludeDisabled
        
    #>

    param (
        [Parameter(Position = 0, Mandatory = $true)]
        [int64]$MonthsSinceLastLogin,
        [Parameter()]
        [string]$SearchBase = (Get-ADDomain).DistinguishedName,
        [Parameter()]
        [switch]$IncludeDisabled
    )

    if ($IncludeDisabled.IsPresent) {
        $Users = Get-ADUser -Filter * -SearchBase $SearchBase -Properties LastLogonTimestamp
    }
    else {
        $Users = Get-ADUser -Filter { Enabled -eq $true } -SearchBase $SearchBase -Properties LastLogonTimestamp
    }
    
    $CutOffDate = (Get-Date).AddMonths(-$MonthsSinceLastLogin)

    foreach ($u in $Users) {
        $LastLogon = $null
        if ($u.LastLogonTimestamp) {
            $LastLogon = [DateTime]::FromFileTime($u.LastLogonTimestamp)
        }
        
        if ($null -eq $LastLogon) {
            Write-Output "$($u.Name) has never logged in!"
        }
        elseif ($LastLogon -le $CutOffDate) {
            Write-Output "$($u.Name) hasn't logged in since $($LastLogon)"
        }
    }
}

#----------------------------------------------------------------------------------------
# TO BE CONTINUED
#----------------------------------------------------------------------------------------
