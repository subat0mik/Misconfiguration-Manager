<#
.SYNOPSIS
Collect information from an SMS Provider and remote site systems to identify the issues described in Misconfiguration Manager

.DESCRIPTION
Author: Chris Thompson (@_Mayyhem)
Version: 1.0

Requirements:
  - Run on an SMS Provider or target one using the -SMSProvider parameter
  - Any SCCM Security Role (e.g., Read-only Analyst or higher)
  - Use the -Verbose option to display the results of checks as they occur

Recommended to improve accuracy and reduce false positives:
  - Local Administrators group privileges on site systems
  - RPC and SMB connectivity to site systems

.PARAMETER SMSProvider
Specify a remote SMS Provider to run the script against.

.PARAMETER Timeout
Increase or decrease the connection timeout for remote site system checks (default: 5 seconds)

.PARAMETER Verbose
Enable verbose logging of script execution events and display check results as they occur.

.EXAMPLE
.\MisconfigurationManager.ps1 -Help
# Display help text

.EXAMPLE
.\MisconfigurationManager.ps1
# Collect information from a local SMS Provider and print only the final results after analysis.

.EXAMPLE
.\MisconfigurationManager.ps1 -SMSProvider <SMS_PROVIDER> -Timeout 2 -Verbose
# Collect information from a remote SMS Provider, give up on failed connections after 2 seconds, and print results as they occur.

.LINK
https://misconfigurationmanager.com

#>

[CmdletBinding()]
param(
    [switch]$Help,
    [string]$SMSProvider,
    [int]$Timeout = 5
)

if ($Help) {
    Get-Help $MyInvocation.MyCommand.Path
    exit
}

if (-not $SMSProvider) {
    $SMSProvider = $env:COMPUTERNAME
}

# Save settings
$originalVerbosePreference = $VerbosePreference
$originalWarningPreference = $WarningPreference


# Determine if the host is the console or ISE
if ($Host.Name -eq 'ConsoleHost') {
    # For the standard console, we use ConsoleColor enum values
    $originalVerboseColor = $Host.PrivateData.VerboseForegroundColor
    $originalVerboseBackgroundColor = $Host.PrivateData.VerboseBackgroundColor
    $originalWarningColor = $Host.PrivateData.WarningForegroundColor
    $originalWarningBackgroundColor = $Host.PrivateData.WarningBackgroundColor
    # Set the foreground colors and set the background colors to match the console's background
    $Host.PrivateData.VerboseForegroundColor = 'Cyan'
    $Host.PrivateData.WarningForegroundColor = 'DarkYellow'
    $Host.PrivateData.VerboseBackgroundColor = $Host.UI.RawUI.BackgroundColor
    $Host.PrivateData.WarningBackgroundColor = $Host.UI.RawUI.BackgroundColor
} elseif ($Host.Name -eq 'Windows PowerShell ISE Host') {
    # For ISE, we use System.Windows.Media.Color values
    $originalVerboseColor = $psISE.Options.VerboseForegroundColor
    $originalWarningColor = $psISE.Options.WarningForegroundColor
    $psISE.Options.VerboseForegroundColor = [System.Windows.Media.Colors]::Cyan
    $psISE.Options.WarningForegroundColor = [System.Windows.Media.Colors]::DarkOrange
}



# Set output preferences
if ($VerbosePreference) {
    $VerbosePreference = 'Continue'
    $WarningPreference = 'Continue'
}
else {
    $VerbosePreference = 'SilentlyContinue'
    $WarningPreference = 'SilentlyContinue'    
}

# Display help text
if ($Help) {
    Get-Help $MyInvocation.MyCommand.Path
    exit
}

function Check-AccountIsLocalAdmin {
    param (
        [Parameter(Mandatory = $true)]
        [string]$AccountName,
        [Parameter(Mandatory = $true)]
        [string]$ComputerName
    )

    Write-Verbose "    Checking local Administrators group on $ComputerName for account: $AccountName"

    try {
        $scriptBlock = {
            param($AccountName, $ComputerName)
            Get-WmiObject Win32_GroupUser -ComputerName $ComputerName | 
            Where-Object { $_.GroupComponent -like '*"Administrators"' } |
            Where-Object { $_.PartComponent -like "*`"$using:AccountName`"*" } |
            ForEach-Object { $_.PartComponent } |
            ForEach-Object { $_.Split('=')[2].Trim('"') }
        }

        $matchingAdminAccounts = Run-Script -ScriptBlock $scriptBlock -ArgumentList $AccountName, $ComputerName -TimeoutSeconds $Timeout

        # Check succeeded and found a matching account in local Administrators group
        if ($matchingAdminAccounts) {
            return $true
        }

        # Check timed out
        elseif ($matchingAdminAccounts -like "*timed out*") {
            return "Check for local Administrators group members timed out after $Timeout seconds"
        } 

        # Check succeeded but no matches
        else {
            return $false
        }
    }
    catch {
        return "Failed to check local Administrators group members: $($_.ToString())"
    }
}

function Check-IssueStatus {
    param (
        [string]$Issue,
        [bool]$LikelyCondition,
        [bool]$PreventingCondition,
        [string]$LikelyMessage,
        [string]$FailedCheckMessage,
        [string]$PreventingMessage,
        [string]$RolePrefix,
        [ref]$System
    )

    if ($System.Value.IssuesToCheck -contains $Issue) {

        $message = 
        if ($PreventingCondition) { 
            $PreventingMessage
            $System.Value.IssuesToCheck = $System.Value.IssuesToCheck | Where-Object { $_ -ne $Issue }
        }
        elseif ($LikelyCondition) {
            $LikelyMessage
        } 
        else { 
            $FailedCheckMessage
        }
        $System.Value.Output += "$RolePrefix    $message`n"
    }
}

# Function converted to string to load in scriptblock to reduce connection timeouts
$getRegistrySubkeyValueFunction = @'
    function Get-RegistrySubkeyValue {
        param (
            [string]$ComputerName,
            [string]$Hive,
            [string]$SubKeyPath,
            [string]$ValueName
        )

        # Define the registry hive, subkey, and value name you want to read
        $registryHive = if ($Hive) { $Hive } else { [Microsoft.Win32.RegistryHive]::LocalMachine }

        try {
            # Open the remote registry key
            $remoteRegistry = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey($registryHive, $ComputerName)
            $subKey = $remoteRegistry.OpenSubKey($SubKeyPath)

            # Read the value
            if ($subKey -ne $null) {
                $value = $subKey.GetValue($ValueName)
                return $value
            } else {
                return "Subkey $SubKeyPath not found on $ComputerName"
            }
        } catch {
            return "Failed to read registry on ${ComputerName}: $_"
        } finally {
            if ($subKey -ne $null) {
                $subKey.Close()
            }
            if ($remoteRegistry -ne $null) {
                $remoteRegistry.Close()
            }
        }
    }
'@


function Get-SiteDatabaseEPA {
    param (
        [Parameter(Mandatory = $true)]
        [string]$ComputerName
    )

    # Get the list of all namespaces under 'root\Microsoft\SqlServer'
    $serverNamespaceRoot = "root\Microsoft\SqlServer"

    $scriptBlock = {
        param($computerName, $namespaceRoot)
        Get-WmiObject -ComputerName $computerName -Namespace $namespaceRoot -Class "__NAMESPACE"
    }

    $namespaces = Run-Script -ScriptBlock $scriptBlock -ArgumentList $ComputerName, $serverNamespaceRoot -TimeoutSeconds $Timeout -ErrorAction SilentlyContinue

    # Filter out the namespaces that match the pattern 'ComputerManagementXX'
    $cmNamespaces = $namespaces | Where-Object { $_.Name -match "^ComputerManagement\d+$" }

    if ($cmNamespaces) {
        # Iterate over each namespace and perform the query
        foreach ($namespace in $cmNamespaces) {

            $fullNamespace = "$serverNamespaceRoot\$($namespace.Name)"

            # Query the WMI object for Extended Protection setting
            $wmiQuery = "SELECT * FROM ServerSettingsExtendedProtection"

            # Execute the WMI query
            try {
                $extendedProtectionSettings = Get-WmiObject -ComputerName $ComputerName -Namespace $fullNamespace -Query $wmiQuery
                return $extendedProtectionSettings.ExtendedProtection
            }
            catch {
                return "Failed to check EPA requirements: $($_.ToString())"
            }
        }
    }
    else {
        return "Check for EPA requirements timed out after $Timeout seconds"
    }
}

function Get-SiteHierarchy {
    param (
        [string]$Namespace,
        [string]$ParentSiteCode = $null,
        [string]$SMSProvider
    )

    # Initialize output variable, a list of sites in the hierarchy
    $siteHierarchy = @()

    # Query the top level site first
    $filter = if ($ParentSiteCode) { "ParentSiteCode = '$ParentSiteCode'" } else { "ParentSiteCode = ''" }
    Write-Verbose "Querying $($Namespace).SMS_SCI_SiteDefinition for the list of sites with parent: $ParentSiteCode"

    $scriptBlock = { 
        param($Namespace, $Filter, $SMSProvider)
        return Get-WmiObject -Namespace $Namespace -Class SMS_SCI_SiteDefinition -Filter $Filter -ComputerName $SMSProvider
    }

    $sites = Run-Script -ScriptBlock $scriptBlock -ArgumentList $Namespace, $filter, $SMSProvider -TimeoutSeconds $Timeout
        
    # Exit loop if job times out or isn't completed
    if ($sites) {
        if ($sites -like "*timed out*") {
            Write-Warning "Query timed out: $ParentSiteCode doesn't have any child sites or the site database is offline"
            return
        }
        elseif ($sites[0].ToString() -like "*PSRemotingJob") {
            Write-Warning "The timeout is too short for jobs to finish"
            return
        }
    }

    foreach ($site in $sites) {
        
        Write-Verbose ("Gathering data for site: {0} ({1})" -f $site.SiteName, $site.SiteCode)

        $currentSite = @{
            "AutomaticClientPush"      = $null
            "ClearClientInstalledFlag" = $null
            "ClientPushAccounts"       = @()
            "ClientPushTargets"        = $null
            "FallbackToNTLM"           = $null
            "ParentSiteCode"           = $site.ParentSiteCode
            "SiteCode"                 = $site.SiteCode
            "SiteName"                 = $site.SiteName
            "SiteServerName"           = $site.SiteServerName
            "SiteSystems"              = @()
            "Type"                     = $site.SiteType
            "TypeDepth"                = $null
            "TypeName"                 = $null
        }

        # Get the hierarchy level
        $currentSite = Get-SiteType -Site $([ref]$currentSite)
        Write-Verbose ("{0} is a {1}" -f $currentSite.SiteName, $currentSite.TypeName)

        # Indent based on the hierarchy level
        $indent = " " * ($currentSite.TypeDepth * 4)

        # Query other site system roles
        Get-SiteSystems -Namespace $Namespace -Site $([ref]$currentSite) -Indent ($Indent + "   ") -SMSProvider $SMSProvider

        # Get client push installation settings for primary sites
        if ($currentSite.Type -eq 2) {
            Get-SitePushSettings -Namespace $namespace -Site $currentSite -ComputerName $SMSProvider
        }
        
        # Add the site to the list of sites
        $siteHierarchy += $currentSite

        # Recursive call for child sites excluding secondary sites
        Get-SiteHierarchy -Namespace $Namespace -ParentSiteCode $site.SiteCode -SMSProvider $SMSProvider
    }
    return $siteHierarchy
}

function Get-SiteNamespace {
    param (
        [string]$SMSProvider
    )

    # Query WMI to get all SMS namespaces
    Write-Verbose "Looking for site namespace in root\SMS on $SMSProvider"
    try {
        $namespaces = Get-WmiObject -Namespace "root\SMS" -Class "__NAMESPACE" -ComputerName $SMSProvider -ErrorAction Stop
    } 
    
    catch {
        Write-Warning "Could not find root\SMS namespace. Is $SMSProvider an SMS Provider?"
        exit
    }

    $foundNamespace = $null

    foreach ($ns in $namespaces) {
        # Check if the namespace is like SMS_<SiteCode>
        if ($ns.Name -match '^site_') {
            $foundNamespace = "root\SMS\" + $ns.Name
            break
        }
    }
    Write-Verbose "Found $foundNamespace on $SMSProvider"
    return $foundNamespace
}

function Get-SitePushSettings {
    param (
        [string]$ComputerName,
        [string]$Namespace,
        $Site
    )

    Write-Verbose "Querying client push installation settings for $($Site.SiteCode)"

    $queryAutomaticClientPush = "SELECT PropertyName, Value, Value1 FROM SMS_SCI_SCProperty WHERE SiteCode='$($Site.SiteCode)' AND ItemType='SMS_DISCOVERY_DATA_MANAGER' AND PropertyName='SETTINGS'"
    try {
        $result = Get-WmiObject -Namespace $Namespace -Query $queryAutomaticClientPush -ComputerName $ComputerName
        if ($result) {
            if ($result.Value1 -eq "Active") {
                Write-Warning "    Automatic site-wide client push installation is enabled"
                $Site.AutomaticClientPush = $true
            }
            elseif ($result.Value1 -eq "INACTIVE") {
                Write-Verbose "    Automatic site-wide client push installation is not enabled"
                $Site.AutomaticClientPush = $false
            }
            else {
                Write-Warning "    Check for automatic site-wide client push installation settings failed"
            }
        }
    }
    catch {
        Write-Warning "    An error occurred while querying client push settings for site $($siteCode.SiteCode): $($_.Exception.Message)" -ErrorAction 'Continue'
    }


    $queryFallbackToNTLM = "SELECT PropertyName, Value, Value1 FROM SMS_SCI_SCProperty WHERE SiteCode='$($Site.SiteCode)' AND ItemType='SMS_DISCOVERY_DATA_MANAGER' AND PropertyName='ENABLEKERBEROSCHECK'"
    try {
        $result = Get-WmiObject -Namespace $Namespace -Query $queryFallbackToNTLM -ComputerName $ComputerName
        if ($result) {
            if ($result.Value -eq 3) {
                Write-Warning "    Fallback to NTLM is enabled"
                $Site.FallbackToNTLM = $true
            }
            elseif ($result.Value -eq 2) {
                Write-Verbose "    Fallback to NTLM is not enabled"
                $Site.FallbackToNTLM = $false
            }
            else {
                Write-Warning "    Check for fallback to NTLM setting failed"
            }
        }
    }
    catch {
        Write-Warning "    An error occurred while querying client push settings for site $($siteCode.SiteCode): $($_.Exception.Message)" -ErrorAction 'Continue'
    }

    if ($Site.AutomaticClientPush -and $Site.FallbackToNTLM) {
        $queryClientPushTargets = "SELECT PropertyName, Value, Value1 FROM SMS_SCI_SCProperty WHERE SiteCode='$($Site.SiteCode)' AND ItemType='SMS_DISCOVERY_DATA_MANAGER' AND PropertyName='FILTERS'"
        try {
            $result = Get-WmiObject -Namespace $Namespace -Query $queryClientPushTargets -ComputerName $ComputerName
            if ($result) {
                Write-Warning "    Install client software on the following computers:"
                $Site.ClientPushTargets = 
                switch ($result.Value) {
                    0 { "        Workstations and Servers (including domain controllers)" }
                    1 { "        Servers only (including domain controllers)" }
                    2 { "        Workstations and Servers (excluding domain controllers)" }
                    3 { "        Servers only (excluding domain controllers)" }
                    4 { "        Workstations and domain controllers only (excluding other servers)" }
                    5 { "        Domain controllers only" }
                    6 { "        Workstations only" }
                    7 { "        No computers" }
                }
                Write-Warning $Site.ClientPushTargets
            }
            else {
                Write-Warning "    Check for client push targets failed"
            }

            $queryAccounts = "SELECT Values FROM SMS_SCI_SCPropertyList WHERE PropertyListName='Reserved2'"
            $accounts = Get-WmiObject -Namespace $Namespace -Query $queryAccounts -ComputerName $ComputerName
            if ($accounts.Values) {
                foreach ($value in $accounts.Values) {
                    Write-Warning "    Discovered client push installation account: $value"
                    $Site.ClientPushAccounts += $value
                }
            }
            else {
                Write-Warning "    No client push installation accounts were configured, but the server may still use its machine account"
                
            }

            # Always add the site server computer account to client installation accounts
            $Site.ClientPushAccounts += "$($Site.SiteServerName.Split('.')[0])$"

            $queryTask = "SELECT * FROM SMS_SCI_SQLTask WHERE ItemName='Clear Undiscovered Clients'"
            $task = Get-WmiObject -Namespace $Namespace -Query $queryTask -ComputerName $ComputerName
            if ($task.Enabled -eq $true) {
                Write-Warning "    The client installed flag is automatically cleared on inactive clients after $($task.DeleteOlderThan) days, resulting in automatic client push for reinstallation"
                $Site.ClearClientInstalledFlag = $true
            }
            elseif ($task.Enabled -eq $false) {
                Write-Verbose "    The client installed flag is not automatically cleared on inactive clients, preventing automatic reinstallation"
                $Site.ClearClientInstalledFlag = $false
            }
            else {
                Write-Verbose "    Check for clear client installed flag failed"
            }
        }
        catch {
            Write-Warning "    An error occurred while querying client push settings for site $($siteCode.SiteCode): $($_.Exception.Message)" -ErrorAction 'Continue'
        }
    }
}

function Get-SiteSystems {
    param (
        [string]$Namespace,
        [ref]$Site,
        [string]$SMSProvider
    )

    # Query SMS_SCI_SysResUse class for site system roles
    Write-Verbose "Querying the list of systems in $($Site.Value.SiteCode)"
    $siteSystemRoles = Get-WmiObject -Namespace $Namespace -Class SMS_SCI_SysResUse -Filter "SiteCode = '$($Site.Value.SiteCode)'" -ComputerName $SMSProvider

    # Group roles by NetworkOSPath
    $siteSystems = $siteSystemRoles | Group-Object -Property NetworkOSPath

    foreach ($siteSystem in $siteSystems) {

        $siteSystemName = $siteSystem.Name.TrimStart('\')
        Write-Verbose "Collecting data for $siteSystemName"
        $isRemote = $siteSystemName -ne $Site.Value.SiteServerName

        $currentSiteSystem = @{
            # Check whether the role is on a remote server (not the site server), making NTLM relay possible
            "Name"               = $siteSystemName
            "EPARequired"        = $null
            "IsRemote"           = $isRemote
            "IssuesToCheck"      = @()
            "Output"             = $null
            "SiteCode"           = $Site.Value.SiteCode
            "SiteSystemRoles"    = @()
            "SMBSigningRequired" = $null
            "WebClientStatus"    = $null
        }

        foreach ($role in $siteSystem.Group) {                       
            $currentSiteSystem.SiteSystemRoles += $role.RoleName
            Write-Verbose "    $($role.RoleName)"
        }

        # Check SMB signing requirements for TAKEOVER-2, TAKEOVER-4, TAKEOVER-6, TAKEOVER-7, and ELEVATE-1
        Write-Verbose "    Collecting SMB signing requirements"
        $currentSiteSystem.SMBSigningRequired = Get-SMBSigningRequirement -ComputerName $currentSiteSystem.Name

        if ($currentSiteSystem.IsRemote) {

            foreach ($role in $siteSystem.Group) {   

                if ($role.RoleName -eq "SMS SQL Server" -and $Site.Type -ne 1) {
                    $currentSiteSystem.IssuesToCheck += "TAKEOVER-1", "TAKEOVER-2"

                    # TAKEOVER-2
                    Print-SMBSigningStatus -CurrentSiteSystem $currentSiteSystem -Issue "TAKEOVER-2"

                    # TAKEOVER-1
                    Write-Verbose "    Collecting EPA requirements"
                    $currentSiteSystem.EPARequired = Get-SiteDatabaseEPA -ComputerName $currentSiteSystem.Name

                    if ($currentSiteSystem.EPARequired -eq 2) {
                        Write-Verbose "        EPA required: True" 
                    }
                    elseif ($currentSiteSystem.EPARequired -lt 2) {
                        Write-Warning "        EPA required: False (TAKEOVER-1 likely!)" 
                    }
                    else { 
                        Write-Warning "        $($currentSiteSystem.EPARequired) (check TAKEOVER-1 manually)"
                    }
                }
                
                elseif ($role.RoleName -eq "SMS Provider") { 
                    $currentSiteSystem.IssuesToCheck += "TAKEOVER-5", "TAKEOVER-6"

                    # TAKEOVER-5 cannot be prevented on the relay target because AdminService does not support EPA
                    
                    # TAKEOVER-6
                    if ($currentSiteSystem.SMBSigningRequired -eq 1) {
                        $currentSiteSystem.IssuesToCheck = $currentSiteSystem.IssuesToCheck | Where-Object { $_ -ne "TAKEOVER-6" }
                    }
                    Print-SMBSigningStatus -CurrentSiteSystem $currentSiteSystem -Issue "TAKEOVER-6"
                }

                # Add ELEVATE-1 if no TAKEOVER techniques are present
                elseif ($currentSiteSystem.IssuesToCheck -notcontains "ELEVATE-1" -and ($currentSiteSystem.IssuesToCheck -match '^TAKEOVER.*').Count -eq 0) {
                    $currentSiteSystem.IssuesToCheck += "ELEVATE-1"
                    Print-SMBSigningStatus -CurrentSiteSystem $currentSiteSystem -Issue "ELEVATE-1"
                }
            }

            # This is a site server
        }
        else {

            # Don't add TAKEOVERs to secondary site servers
            if ($Site.Value.Type -ne 1) {

                # TAKEOVER-3 is applicable if AD CS is in use (check manually)
                $currentSiteSystem.IssuesToCheck += "TAKEOVER-3"

                # TAKEOVER-7 is applicable to sites with passive site servers
                if ($currentSiteSystem.Name -ne $Site.Value.SiteServerName) {
                    $currentSiteSystem.IssuesToCheck += "TAKEOVER-7"
                    Write-Verbose "    This system is a passive site server"
                    Print-SMBSigningStatus -CurrentSiteSystem $currentSiteSystem -Issue "TAKEOVER-7"
                } 
                
                # Print the SMB signing status even if no attack techniques are detected
                else {
                    if ($currentSiteSystem.SMBSigningRequired -eq 1) {
                        Write-Verbose "        SMB signing required: True"
                    }
                    elseif ($currentSiteSystem.SMBSigningRequired -eq 0) {
                        Write-Warning "        SMB signing required: False"
                    }
                    else {
                        Write-Warning "        SMB signing required: $($CurrentSiteSystem.SMBSigningRequired)"
                    }
                }

                # TAKEOVER-8 is applicable if WebClient is running on the site server
                $currentSiteSystem.IssuesToCheck += "TAKEOVER-8"
                Write-Verbose "    Collecting WebClient service status"
                $currentSiteSystem.WebClientStatus = Get-WebClientService -ComputerName $siteSystemName

                if ($currentSiteSystem.WebClientStatus -eq "Not installed") {
                    Write-Verbose "        WebClient: Not installed, preventing TAKEOVER-8"
                }
                elseif ($currentSiteSystem.WebClientStatus -eq "Running") {
                    Write-Warning "        WebClient: Running (TAKEOVER-8 likely!)"
                }
                elseif ($currentSiteSystem.WebClientStatus -eq "Installed") {
                    Write-Warning "        WebClient: Installed (TAKEOVER-8 possible if it ever starts!)"
                }
                else {
                    Write-Warning "        WebClient check failed, validate TAKEOVER-8 manually"
                }
            }

            # Add ELEVATE-1 to secondary site servers
            else {
                $currentSiteSystem.IssuesToCheck += "ELEVATE-1"
                Print-SMBSigningStatus -CurrentSiteSystem $currentSiteSystem -Issue "ELEVATE-1"
            }
            
            # Get site server computer account name from CAS, which should be processed first
            if ($Site.Value.Type -eq 4) { 
                $Global:casComputerAccount = "$($Site.Value.SiteServerName.Split('.')[0])$"
            }
            
            # TAKEOVER-4 Check whether the CAS computer account is a local admin on primary site servers
            elseif ($Site.Value.Type -eq 2 -and $Global:casComputerAccount) {
                $currentSiteSystem.IssuesToCheck += "TAKEOVER-4"
                $isLocalAdmin = Check-AccountIsLocalAdmin -AccountName $casComputerAccount -ComputerName $currentSiteSystem.Name
                if ($casComputerAccount -eq $isLocalAdmin) {
                    Write-Warning "        $casComputerAccount is a local admin on $currentSiteSystem.Name (TAKEOVER-4 possible)"
                    Print-SMBSigningStatus -CurrentSiteSystem $currentSiteSystem -Issue "TAKEOVER-4"
                }
                elseif ($isLocalAdmin -contains "Failed") {
                    Write-Warning "        Failed to check whether $casComputerAccount is a local admin on $($currentSiteSystem.Name) (check TAKEOVER-4 manually)"
                    Print-SMBSigningStatus -CurrentSiteSystem $currentSiteSystem -Issue "TAKEOVER-4"
                }
                else {
                    Write-Verbose "        $casComputerAccount is not a local admin on $($currentSiteSystem.Name)"
                }
            }
        }

        # Add the current site system to the site
        $Site.Value.SiteSystems += $currentSiteSystem
    }
}

function Get-SiteType {
    param (
        [Parameter(Mandatory = $true)]
        [ref]$Site
    )

    if ($Site.Value.Type -eq 1) {
        $Site.Value.TypeName = "secondary site"
        $Site.Value.TypeDepth = 3
    }
    elseif ($Site.Value.Type -eq 2) {
        $Site.Value.TypeName = "primary site"
        $Site.Value.TypeDepth = 2
    }
    elseif ($Site.Value.Type -eq 4) {
        $Site.Value.TypeName = "central administration site"
        $Site.Value.TypeDepth = 1
    }
    return $Site.Value
}

function Get-SMBSigningRequirement {
    param (
        [Parameter(Mandatory = $true)]
        [string]$ComputerName
    )

    $subKeyPath = "System\CurrentControlSet\Services\LanManServer\Parameters\"
    $valueName = "RequireSecuritySignature"
    
    $scriptBlock = {
        param($functionString, $computerName, $subKeyPath, $valueName)

        # Create the function in this scope
        Invoke-Expression $functionString

        $requireSecuritySignature = Get-RegistrySubkeyValue -ComputerName $computerName -SubKeyPath $subKeyPath -ValueName $valueName
        return $requireSecuritySignature
    }

    # Run on timer to reduce wait time when the network path can't be found
    try {
        $requireSecuritySignature = Run-Script -ScriptBlock $scriptBlock -ArgumentList $getRegistrySubkeyValueFunction, $ComputerName, $subKeyPath, $valueName -TimeoutSeconds $Timeout
        if ($requireSecuritySignature -like "*timed out*") {
            return "Check for SMB signing requirements timed out after $Timeout seconds"
        }
        return $requireSecuritySignature
    }
    catch {
        return "Failed to check SMB signing requirements: $($_.ToString())"
    }
}

function Get-WebClientService {
    param (
        [Parameter(Mandatory = $true)]
        [string]$ComputerName
    )

    try {
        # Check if the remote computer is accessible within 3 seconds
        $ping = Test-Connection -ComputerName $ComputerName -Count 1 -Quiet
        if ($ping) {
            $service = Get-Service -Name WebClient -ComputerName $ComputerName -ErrorAction Stop
            return $service.Status
        }
        else {
            return "Failed to connect to $ComputerName to check for WebClient"
        }
    }
    catch {
        return "Failed to connect or an unexpected error occurred while checking for WebClient"
    }
}

function Print-SiteStructure {
    param (
        [Parameter(Mandatory = $true)]
        $Site,
        [string]$Indent = "",
        [array]$AllSites
    )

    try {
        # Determine if there are any child sites for this site
        $childSites = $AllSites | Where-Object { $_.ParentSiteCode -eq $Site.SiteCode }
        $hasChildSites = $childSites.Count -gt 0

        # Display the current site details
        $siteDetails = "Site Code: $($Site.SiteCode), Name: $($Site.SiteName), Site Server: $($Site.SiteServerName)"
        if ($Site.ParentSiteCode) {
            $siteDetails += ", Reporting to: $($Site.ParentSiteCode)"
        }

        # Link site to parent in tree and add space between items
        $siteIndent = if ($Site.ParentSiteCode -and $hasChildSites) { $Indent.Substring(0, $Indent.Length - 4) + "├───" }
        elseif ($Site.ParentSiteCode) { $Indent.Substring(0, $Indent.Length - 4) + "└───" }
        else { $Indent }

        $afterDetailsSpace =
        # This site has child sites
        if ($hasChildSites) {
            " │   " * $Site.TypeDepth
        }
        # This is a standalone primary site
        elseif ($Indent.Length -eq 0) {
            " │   "
        }
        # This is a descendent site
        else {
            $Indent.Substring(0, $Indent.Length - 4) + "     │" 
        }

        Write-Host "$siteIndent$siteDetails`n$afterDetailsSpace"
    
        # Print client push settings for primary sites
        if ($Site.Type -eq 2) {
            $message = $null
            if ($Site.AutomaticClientPush -eq $true) {
                $message = "$Indent ├───Automatic site-wide client push installation is enabled`n"

                # Print relevant settings if automatic push is enabled
                if ($Site.FallbackToNTLM -eq 3) {
                    $message += "$Indent │       Fallback to NTLM is enabled (ELEVATE-2 and ELEVATE-3 likely!)`n"
                } 
                elseif ($Site.FallbackToNTLM -eq 2) {
                    $message += "$Indent │       Fallback to NTLM is not enabled`n"
                } 
                else {
                    $message += "$Indent │       Check for fallback to NTLM setting failed`n"
                }

                $message += "$Indent │       Install client software on the following computers:`n"
                $message += "$Indent │    $($Site.ClientPushTargets)`n"
                $message += "$Indent │       Discovered client push installation accounts:`n"
                if ($Site.ClientPushAccounts.Count -gt 0) {
                    foreach ($value in $Site.ClientPushAccounts) {
                        $message += "$Indent │           $value`n"
                    }
                } 
                else {
                    $message += "$Indent │           No client push installation accounts were configured, but the server may still use its machine account`n"
                }

                if ($Site.ClearInstalledFlag -eq $true) {
                    $message += "$Indent │       The client installed flag is automatically cleared on inactive clients after $($task.DeleteOlderThan) days, resulting in automatic client push for reinstallation"
                } 
                else {
                    $message += "$Indent │       The client installed flag is not automatically cleared on inactive clients, preventing automatic reinstallation"
                }
            } 
            elseif ($Site.AutomaticClientPush -eq $false) {
                $message += "$Indent ├───Automatic site-wide client push installation is not enabled"
            } 
            else {
                $message += "$Indent ├───Check for automatic site-wide client push installation settings failed"
            }
            Write-Host $message
            Write-Host "$Indent │"
        }

        # Get primary site server object
        $primarySiteServer = $Site.SiteSystems | Where-Object { $_.Name.TrimStart('\') -eq $Site.SiteServerName }

        # Display site systems
        $siteSystemCount = $Site.SiteSystems.Count

        foreach ($system in $Site.SiteSystems) {

            # Remove ELEVATE-1 if any TAKEOVER is present
            if ($system.IssuesToCheck -contains "ELEVATE-1" -and ($currentSiteSystem.IssuesToCheck -match '^TAKEOVER.*').Count -gt 0) {
                $system.IssuesToCheck = $system.IssuesToCheck | Where-Object { $_ -ne "ELEVATE-1" }
            }

            # Do not continue tree structure if on the last system in the site
            $siteSystemCount--
            $isLastSystem = $siteSystemCount -eq 0

            if ($isLastSystem -and -not $hasChildSites) { 
                # This is a standalone primary site    
                if ($Indent.Length -eq 0) {
                    $systemPrefix = " └───"
                }
                # This is a descendent site
                else {
                    $systemPrefix = $Indent.Substring(0, $Indent.Length - 4) + "     └───"
                }
            }
            # This site has child sites
            else {
                $systemPrefix = "$Indent ├───"
            }

            $remoteText = if ($system.IsRemote) { " (Remote: True)" } else { "" }
            $system.Output = "$systemPrefix$($system.Name)$remoteText`n"

            # Do not continue tree structure if on the last role in the site
            $roleCount = $system.SiteSystemRoles.Count
            foreach ($role in $system.SiteSystemRoles) {
                $roleCount--

                if ($isLastSystem -and -not $hasChildSites) {
                    # This is a standalone primary site 
                    if ($Indent.Length -eq 0) {
                        $rolePrefix = "        "
                    }
                    # This is a descendent site
                    else {
                        $rolePrefix = $Indent.Substring(0, $Indent.Length - 4) + "            "
                    }
                } 
                else {
                    $rolePrefix = "$Indent │     "
                }

                $system.Output += "$rolePrefix $role`n"

                # Issue details
                if ($role -eq "SMS SQL Server") {
                
                    # TAKEOVER-1
                    Check-IssueStatus -Issue "TAKEOVER-1" `
                        -FailedCheckMessage "EPA check failed, validate TAKEOVER-1 manually" `
                        -LikelyCondition ($system.EPARequired -lt 2) `
                        -LikelyMessage "EPA not required, TAKEOVER-1 likely!" `
                        -PreventingCondition ($system.EPARequired -eq 2) `
                        -PreventingMessage "EPA required, preventing TAKEOVER-1" `
                        -RolePrefix $rolePrefix `
                        -System $([ref]$system)

                    # TAKEOVER-2
                    Check-IssueStatus -Issue "TAKEOVER-2" `
                        -FailedCheckMessage "SMB signing check failed, validate TAKEOVER-2 manually" `
                        -LikelyCondition ($system.SMBSigningRequired -eq 0) `
                        -LikelyMessage "SMB signing not required, TAKEOVER-2 likely!" `
                        -PreventingCondition ($system.SMBSigningRequired -eq 1) `
                        -PreventingMessage "SMB signing required, preventing TAKEOVER-2" `
                        -RolePrefix $rolePrefix `
                        -System $([ref]$system)

                    # TAKEOVER-9 - Not yet implemented
                }

                elseif ($role -eq "SMS Site Server") {

                    # TAKEOVER-3


                    # TAKEOVER-4
                    Check-IssueStatus -Issue "TAKEOVER-4" `
                        -FailedCheckMessage "SMB signing check failed, validate TAKEOVER-4 manually" `
                        -LikelyCondition ($system.SMBSigningRequired -eq 0) `
                        -LikelyMessage "SMB signing not required, TAKEOVER-4 likely!" `
                        -PreventingCondition ($system.SMBSigningRequired -eq 1) `
                        -PreventingMessage "SMB signing required, preventing TAKEOVER-4" `
                        -RolePrefix $rolePrefix `
                        -System $([ref]$system)

                    # TAKEOVER-7 check on both active and passive site servers
                    if ($system.IssuesToCheck -contains "TAKEOVER-7" -and $primarySiteServer.IssuesToCheck -notcontains "TAKEOVER-7") {
                        $primarySiteServer.IssuesToCheck += "TAKEOVER-7"
                    }

                    # Active site server
                    Check-IssueStatus -Issue "TAKEOVER-7" `
                        -FailedCheckMessage "SMB signing check failed, validate TAKEOVER-7 manually" `
                        -LikelyCondition ($primarySiteServer.SMBSigningRequired -eq 0) `
                        -LikelyMessage "SMB signing not required, TAKEOVER-7 likely!" `
                        -PreventingCondition ($primarySiteServer.SMBSigningRequired -eq 1) `
                        -PreventingMessage "SMB signing required, preventing TAKEOVER-7" `
                        -RolePrefix $rolePrefix `
                        -System $([ref]$primarySiteServer)

                    # Passive site servers
                    Check-IssueStatus -Issue "TAKEOVER-7" `
                        -FailedCheckMessage "SMB signing check failed, validate TAKEOVER-7 manually" `
                        -LikelyCondition ($system.SMBSigningRequired -eq 0) `
                        -LikelyMessage "SMB signing not required, TAKEOVER-7 likely!" `
                        -PreventingCondition ($system.SMBSigningRequired -eq 1) `
                        -PreventingMessage "SMB signing required, preventing TAKEOVER-7" `
                        -RolePrefix $rolePrefix `
                        -System $([ref]$system)
                
                    # TAKEOVER-8
                    if ($system.IssuesToCheck -contains "TAKEOVER-8") {
                        $message = 
                        if ($system.WebClientStatus -eq "Not installed") {
                            "WebClient not installed, preventing TAKEOVER-8"
                            $system.IssuesToCheck = $system.IssuesToCheck | Where-Object { $_ -ne "TAKEOVER-8" }
                        } 
                        elseif ($system.WebClientStatus -eq "Running") {
                            "WebClient running, TAKEOVER-8 likely!"
                        } 
                        elseif ($system.WebClientStatus -eq "Installed") {
                            "WebClient installed, TAKEOVER-8 possible if it ever starts!"
                        } 
                        else {
                            "WebClient check failed, validate TAKEOVER-8 manually"
                        }
                        $system.Output += "$rolePrefix    $message`n"
                    }
                }
            
                elseif ($role -eq "SMS Provider") {

                    # TAKEOVER-5 is not possible to completely prevent on remote SMS Providers (EPA is not supported by AdminService)

                    # TAKEOVER-6
                    Check-IssueStatus -Issue "TAKEOVER-6" `
                        -FailedCheckMessage "SMB signing check failed, validate TAKEOVER-6 manually" `
                        -LikelyCondition ($system.SMBSigningRequired -eq 0) `
                        -LikelyMessage "SMB signing not required, TAKEOVER-6 likely!" `
                        -PreventingCondition ($system.SMBSigningRequired -eq 1) `
                        -PreventingMessage "SMB signing required, preventing TAKEOVER-6" `
                        -RolePrefix $rolePrefix `
                        -System $([ref]$system)
                } 
            }
        
            # ELEVATE-1 (if no TAKEOVERs exist)
            if ($system.IssuesToCheck -contains "ELEVATE-1" -and ($system.IssuesToCheck -match '^TAKEOVER.*').Count -eq 0) {

                Check-IssueStatus -Issue "ELEVATE-1" `
                    -FailedCheckMessage "SMB signing check failed, validate ELEVATE-1 manually" `
                    -LikelyCondition ($system.SMBSigningRequired -eq 0) `
                    -LikelyMessage "SMB signing not required, ELEVATE-1 likely!" `
                    -PreventingCondition ($system.SMBSigningRequired -eq 1) `
                    -PreventingMessage "SMB signing required, preventing ELEVATE-1" `
                    -RolePrefix $rolePrefix `
                    -System $([ref]$system)
            }

            # Create some space between sites
            if ($roleCount -eq 0) {
                $system.Output += "$rolePrefix"
            }

            # Add possible issues to header for system
            $issueText = if ($system.IssuesToCheck.Count -gt 0) { " (Possible Issues: $($system.IssuesToCheck -join ', '))" }
            $systemOutputLines = $system.Output -split "`n"
            $systemOutputLines[0] += $issueText
            $systemOutput = $systemOutputLines -join "`n" # Match the line ending style used in split

            Write-Host $systemOutput
        }

        # Process child sites
        $childSiteCount = $childSites.Count
        foreach ($childSite in $childSites) {
            $childSiteCount--
            $newIndent = if ($childSiteCount -eq 0 -and -not ($AllSites | Where-Object { $_.ParentSiteCode -eq $childSite.SiteCode }).Count) { "$Indent     " } else { "$Indent │   " }
            Print-SiteStructure -Site $childSite -Indent $newIndent -AllSites $AllSites
        }
    }

    catch {
        Write-Error "Encountered an unexpected error at line $($_.InvocationInfo.ScriptLineNumber): $($_.Exception.Message)"
    }

}

function Print-SMBSigningStatus {
    param(
        $CurrentSiteSystem,
        [string]$Issue
    )
    if ($CurrentSiteSystem.SMBSigningRequired -eq 1) {
        Write-Verbose "        SMB signing required: True"
    }
    elseif ($CurrentSiteSystem.SMBSigningRequired -eq 0) {
        Write-Warning "        SMB signing required: False ($($Issue) likely!)"
    } 
    else {
        Write-Warning "        SMB signing required: $($CurrentSiteSystem.SMBSigningRequired) (check $($Issue) manually)"
    }
}


function Run-Script {
    param (
        [Parameter(Mandatory = $true)]
        [scriptblock]$ScriptBlock,

        [Parameter(Mandatory = $false)]
        [array]$ArgumentList,

        [Parameter(Mandatory = $false)]
        [int]$TimeoutSeconds
    )

    try {
        # Start the script block as a job with the arguments
        $job = Start-Job -ScriptBlock $ScriptBlock -ArgumentList $ArgumentList

        # Wait for the job to finish with the specified timeout
        if ($TimeoutSeconds) {
            $finished = Wait-Job -Job $job -Timeout $TimeoutSeconds
            if (-not $finished) {
                throw
            }
        } 
        else {
            Wait-Job -Job $job
        }

        # Get the result from the job
        $result = Receive-Job -Job $job
        Remove-Job -Job $job
        return $result
    } 
    catch {
        return "The operation timed out after $TimeoutSeconds seconds:`n`t$ScriptBlock"
    }
}

# Main
if ($VerbosePreference -eq "SilentlyContinue") {
    Write-Host "`nCollecting data... this may take a while. Add -Verbose option to show details as they are collected..."
}

# Catch and log unexpected execution error messages
try {
    # Start the hierarchy output from the CAS
    $namespace = Get-SiteNamespace -SMSProvider $SMSProvider
    $Global:casComputerAccount = $null
    $sites = @()
    $sites = Get-SiteHierarchy -Namespace $namespace -SMSProvider $SMSProvider

    if ($sites) {
        # Begin output
        Write-Host "`nHierarchy Tree:`n"

        # Start with top-level site
        $topLevelSites = $sites | Where-Object { -not $_.ParentSiteCode }  

        foreach ($site in $topLevelSites) {
            Print-SiteStructure -Site $site -AllSites $sites
        }
    }
    else {
        Write-Warning "No sites were found. Add -Verbose option to debug"
    }
} 

catch {
    Write-Error "Encountered an unexpected error at line $($_.InvocationInfo.ScriptLineNumber): $($_.Exception.Message)"
} 

finally {
    # Set preferences back to original values
    $VerbosePreference = $originalVerbosePreference
    $WarningPreference = $originalWarningPreference

    if ($Host.Name -eq 'ConsoleHost') {
        # For the standard console, we use ConsoleColor enum values
        $Host.PrivateData.VerboseForegroundColor = $originalVerboseColor
        $Host.PrivateData.WarningForegroundColor = $originalWarningColor
        $Host.PrivateData.VerboseBackgroundColor = $originalVerboseBackgroundColor
        $Host.PrivateData.WarningBackgroundColor = $originalWarningBackgroundColor
    } elseif ($Host.Name -eq 'Windows PowerShell ISE Host') {
        # For ISE, we use System.Windows.Media.Color values
        $psISE.Options.VerboseForegroundColor = $originalVerboseColor
        $psISE.Options.WarningForegroundColor = $originalWarningColor
    }
}