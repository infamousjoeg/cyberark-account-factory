##########################################
### IMPORT PS MODULES
Import-Module psPAS
Import-Module CredentialRetriever
Import-Module ActiveDirectory

##########################################
### RECEIVE USER INPUT

Write-Host "`r`n===============================" -ForegroundColor Yellow
Write-Host "CyberArk Account Factory" -ForegroundColor Yellow
Write-Host "===============================`r`n" -ForegroundColor Yellow

# DO: Keep asking for local or AD
# UNTIL: L or A is chosen
do { $acctScope = Read-Host "Create a [L]ocal User or [A]ctive Directory User? " }
while ( $acctScope -notlike "L" -and $acctScope -notlike "A")

# Ask for Configuration ID from CMDB of Application
$cmdbConfigId = Read-Host "Enter the CMDB Configuration Id"

##########################################
### VARIABLES

$baseURI = "https://pvwa.192.168.3.102.xip.io"
$acctUsername = "Svc_${cmdbConfigId}_Dev"

##########################################
### RANDOMIZE & SECURE ACCOUNT PASSWORD
Add-Type -AssemblyName System.Web
$acctSecurePassword = ConvertTo-SecureString ([System.Web.Security.Membership]::GeneratePassword(20,10)) -AsPlainText -Force

##########################################
### CREATE LOCAL OR AD USER

switch($acctScope)
{
    # Case 1: Local User selected
    l {
        $acctAddress = (Get-NetIPAddress -InterfaceIndex 12 -AddressFamily IPv4).IPv4Address
        $acctLogonTo = $env:COMPUTERNAME
        
        try {
            New-LocalUser $acctUsername -Password $acctSecurePassword `
                -FullName $acctUsername -Description "Service Account for ${cmdbConfigId}" `
                -ErrorAction Stop | Out-Null

            Write-Output "`r`nAccount created successfully in local Users group."

            Add-LocalGroupMember -Group "Administrators" -Member $acctUsername -ErrorAction Stop

            Write-Output "`r`nAccount added to local Administrators group successfully."
        } catch {
            Write-Output "`r`nThere was an error creating the local user account. $($PSItem.ToString())"
            Write-Host -NoNewLine "`r`nPress any key to continue..." -ForegroundColor Cyan
            $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
            Exit
        }
    }
    # Case 2: Active Directory User selected
    a {
        $acctAddress = "cyberarkdemo.com"
        
        # Creation of new AD User -- Be sure to update the Path argument for where you keep
        #   your Service Accounts in AD. Typically, a Group Policy Object (GPO) is set to the
        #   Service Accounts Organizational Unit (OU) to prevent interactive logons.
        try {            
            New-ADUser -Name $acctUsername -AccountPassword $acctSecurePassword -ChangePasswordAtLogon $false `
                -Description "Service Account for ${cmdbConfigId}" -DisplayName $acctUsername `
                -Enabled $true -SamAccountName $acctUsername -UserPrincipalName "${acctUsername}@cyberarkdemo.com" `
                -Path "OU=Service Accounts,OU=CyberArk,DC=cyberarkdemo,DC=com" -ErrorAction Stop

            Write-Output "`r`nAccount created successfully in Active Directory."
        } catch {
            Write-Output "`r`nThere was an error creating the Active Directory user account. $($PSItem.ToString())"
            Write-Host -NoNewLine "`r`nPress any key to continue..." -ForegroundColor Cyan
            $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
            Exit
        }
    }
    default {
        # do nothing
    }
}

##########################################
### GET API CREDENTIALS FROM AIM CCP

# Activate TLS 1.2 Protocol for Communication
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Get Credential Object from EPV using AIM CCP
$response = Get-CCPCredential -AppId Account-Factory -Object CyberArk-REST-Acct-Factory-SvcAcct `
    -URL $baseURI

# Declare secure username & password and add to PSCredential object
$secureUsername = $response.UserName
$securePassword = ConvertTo-SecureString $response.Content -AsPlainText -Force
$apiCredentials = New-Object System.Management.Automation.PSCredential($secureUsername, $securePassword)

##########################################
### LOGIN TO CYBERARK WEB SERVICES

# Use try...catch to properly deal with exceptions (this is used at every stage going forward)
try {
    # Establish session connection to CyberArk Web Services & receive Authorization Token
    $token = New-PASSession -Credential $apiCredentials -BaseURI $baseURI  -ErrorAction Stop

    Write-Output "`r`nSecurely logged into CyberArk Web Services using ${secureUsername}."
} catch {
    Write-Output "`r`n[ ERROR ] Could not login to CyberArk Web Services. $($PSItem.ToString())"
    Write-Host -NoNewLine "`r`nPress any key to continue..." -ForegroundColor Cyan
    $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
    Exit
}

##########################################
### ONBOARD ACCOUNT TO EPV

try {
    # Case 1: Local User selected - onboard to WinServerLocal PlatformId
    if ($acctScope -like "l") {
        $acctResponse = ($token | Add-PASAccount -BaseURI $baseURI -name "OTFL-${acctAddress}-${cmdbConfigId}-SvcAcct" `
            -address $acctAddress -userName $acctUsername -platformId "WinServerLocal" `
            -SafeName "D-${cmdbConfigId}-ACCTS" -secret $acctSecurePassword -automaticManagementEnabled $true `
            -platformAccountProperties @{ "LogonDomain"="${acctLogonTo}"; }  -ErrorAction Stop)

        $acctAccountId = $acctResponse.id

        Write-Output "`r`nAutomatically onboarded ${acctUsername} successfully."
    
    # Case 2: Active Directory User selected - onboard to WinDomain PlatformId
    } else {
        $acctResponse = ($token | Add-PASAccount -BaseURI $baseURI -name "OTFL-${acctAddress}-${cmdbConfigId}-SvcAcct" `
            -address $acctAddress -userName $acctUsername -platformId "WinDomain" `
            -SafeName "D-${cmdbConfigId}-ACCTS" -secret $acctSecurePassword -automaticManagementEnabled $true `
            -ErrorAction Stop)

        $acctAccountId = $acctResponse.id

        Write-Output "`r`nAutomatically onboarded ${acctUsername} successfully."
    }
} catch {
    Write-Output "`r`n[ ERROR ] Could not onboard account to EPV. $($PSItem.ToString())"
    Write-Host -NoNewLine "`r`nPress any key to continue..." -ForegroundColor Cyan
    $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
    Exit
}

##########################################
### VERIFY ACCOUNT ONBOARDED

try {
    # If we get a non-error response, we were successful! (Piping to Out-Null blocks the output)
    $token | Get-PASAccount -id $acctAccountId -ErrorAction Stop | Out-Null

    Write-Output "`r`nSuccessfully verified ${acctUsername} using Account Id ${acctAccountId}."
} catch {
    Write-Output "`r`n[ ERROR ] Could not successfully verify account. $($PSItem.ToString())"
    Write-Host -NoNewLine "`r`nPress any key to continue..." -ForegroundColor Cyan
    $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
    Exit
}

##########################################
### LOGOFF CYBERARK WEB SERVICES

try {
    # Again, we're looking for a non-error response while piping out to NULL
    $token | Close-PASSession -ErrorAction Stop | Out-Null

    Write-Output "`r`nLogged off CyberArk Web Services."
} catch {
    Write-Output "`r`n[ ERROR ] Could not logoff CyberArk Web Services - auto-logoff will `
        occur in 20 minutes. $($PSItem.ToString())"
    Exit
}

Write-Host "`r`nScript complete!" -ForegroundColor Green
Write-Host -NoNewLine "`r`nPress any key to continue..." -ForegroundColor Cyan
$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')