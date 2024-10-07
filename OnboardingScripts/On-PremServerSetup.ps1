# Import the Active Directory module
Import-Module ActiveDirectory

# Define the source file paths
$sourceFilePathCSV = "CreateUserFromCSV.ps1"
$sourceFilePathXML = "CreateUserScheduledTask.xml"

# Define the destination directory
$destinationDirectory = "C:\OnboardingScripts"

# Define the destination file paths
$destinationFilePathXML = Join-Path -Path $destinationDirectory -ChildPath $sourceFilePathXML

# Define the path for the log file
$logFilePath = Join-Path -Path $destinationDirectory -ChildPath "OnboardingServerSetupLog.txt"

# Check if the log file path exists
if (!(Test-Path -Path $logFilePath)) {
    # Create the log file if it does not exist
    New-Item -ItemType File -Path $logFilePath -Force
    Write-Output "Created log file: $logFilePath"
} else {
    # Print a message if the log file already exists
    Write-Output "Log file already exists: $logFilePath"
}

# Write an empty line (carriage return) to the log file
Add-Content -Path $logFilePath -Value "`r`n"

# Start the transcript and append to the existing log file
Start-Transcript -Path $logFilePath -Append -Force

try {

    # Function to get the domain details
    function Get-DomainDetails {
        $currentDomain = Get-ADDomain
        return @{
            DomainName = $currentDomain.DNSRoot
            DomainDN   = $currentDomain.DistinguishedName
        }
    }

    # Function to get the SID for a given domain\user
    function Get-SIDFromDomainUser {
        param (
            [string]$domainUser
        )
        $domainDetails = Get-DomainDetails
        $domain, $userName = $domainUser -split '\\', 2
        if (-not $domain -or -not $userName) {
            $domain = $domainDetails.DomainName
            $userName = $domainUser
        }
        $user = Get-ADUser -Identity $userName -Server $domain
        return $user.SID.Value
    }

    # Get domain details
    $domainDetails = Get-DomainDetails

    # Check if the "Security Groups Sync" OU exists, if not, create it
    $securityGroupsSyncOU = "OU=Security Groups Sync,$($domainDetails.DomainDN)"
    if (-not (Get-ADOrganizationalUnit -Filter { DistinguishedName -eq $securityGroupsSyncOU } -ErrorAction SilentlyContinue)) {
        New-ADOrganizationalUnit -Name "Security Groups Sync" -Path $($domainDetails.DomainDN)
        Write-Output "OU 'Security Groups Sync' created."
    }

    # Check if the "Service Accounts" OU exists, if not, create it
    $serviceAccountsOU = "OU=Service Accounts,$($domainDetails.DomainDN)"
    if (-not (Get-ADOrganizationalUnit -Filter { DistinguishedName -eq $serviceAccountsOU } -ErrorAction SilentlyContinue)) {
        New-ADOrganizationalUnit -Name "Service Accounts" -Path $($domainDetails.DomainDN)
        Write-Output "OU 'Service Accounts' created."
    }

    # Create the new service account if it does not exist
    $serviceAccountName = "sa.onboarding"
    $serviceAccountUPN = "$serviceAccountName@$($domainDetails.DomainName)"

    # Check if the service account already exists
    $serviceAccount = Get-ADUser -Filter { UserPrincipalName -eq $serviceAccountUPN } -ErrorAction SilentlyContinue
    if ($serviceAccount) {
        Write-Output "Service account '$serviceAccountName' already exists."
        $newServiceAccountPassword = Read-Host -Prompt "Enter the password for the existing service account 'sa.onboarding'" -AsSecureString
        $UnsecurePassword = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($newServiceAccountPassword))

        # Ensure that the password is not null or empty before proceeding
        if ([string]::IsNullOrWhiteSpace($UnsecurePassword)) {
            Write-Host "The password cannot be null or empty."
            exit
        }
    } else {
        $newServiceAccountPassword = Read-Host -Prompt "Enter the password for the new service account 'sa.onboarding'" -AsSecureString
        # Convert the secure string password to plain text
        $UnsecurePassword = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($newServiceAccountPassword))

        # Ensure that the password is not null or empty before proceeding
        if ([string]::IsNullOrWhiteSpace($UnsecurePassword)) {
            Write-Host "The password cannot be null or empty."
            exit
        }
        New-ADUser -SamAccountName $serviceAccountName -UserPrincipalName $serviceAccountUPN -Name $serviceAccountName -GivenName "sa" -Surname "onboarding" -Enabled $true -DisplayName "Onboarding Service Account" -Path $serviceAccountsOU -AccountPassword $newServiceAccountPassword -PassThru | Out-Null
        Add-ADGroupMember -Identity "Domain Admins" -Members $serviceAccountName | Out-Null
        Write-Output "Service account '$serviceAccountName' created and added to the Domain Admins group."
    }

    # Declare an array of paths to create
    $paths = @(
        "C:\OnboardingScripts",
        "C:\OnboardingScripts\Logs",
        "C:\OnboardingScripts\Offboarding Complete",
        "C:\OnboardingScripts\Offboarding Staging",
        "C:\OnboardingScripts\Onboarding Complete",
        "C:\OnboardingScripts\Onboarding Complete\Output",
        "C:\OnboardingScripts\Onboarding Staging"
    )

    # Loop over the paths
    foreach ($path in $paths) {
        # Check if the path already exists
        if (!(Test-Path -Path $path)) {
            # Create the directory if it does not exist
            New-Item -ItemType Directory -Path $path
            Write-Output "Created directory: $path"
        } else {
            # Print a message if the directory already exists
            Write-Output "Directory already exists: $path"
        }
    }

    # Load the XML file
    [xml]$xml = Get-Content -Path $destinationFilePathXML

    # Define the XML namespace
    $ns = New-Object Xml.XmlNamespaceManager $xml.NameTable
    $ns.AddNamespace('ns', 'http://schemas.microsoft.com/windows/2004/02/mit/task')

    # Set the author to the account that's running the script
    $newAuthor = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name

    # Update the Author field
    $authorNode = $xml.SelectSingleNode('//ns:Author', $ns)
    $authorNode.InnerText = $newAuthor

    # Get the SID for the new author
    $authorSID = Get-SIDFromDomainUser -domainUser $newAuthor

    # Update the UserId field with the SID of the new author
    $userIdNode = $xml.SelectSingleNode('//ns:UserId', $ns)
    $userIdNode.InnerText = $authorSID

    # Update the LogonType to ensure the task runs whether the user is logged in or not
    $principalsNode = $xml.SelectSingleNode('//ns:Principals', $ns)
    foreach ($principalNode in $principalsNode.SelectNodes('ns:Principal', $ns)) {
        $logonTypeNode = $principalNode.SelectSingleNode('ns:LogonType', $ns)
        if ($logonTypeNode -ne $null) {
            $logonTypeNode.InnerText = 'Password'
        }
    }

    # Save the modified XML, overwriting the original file
    $xml.Save($destinationFilePathXML)

    # Define the name of the scheduled task
    $taskName = "Onboarding Create User"

    # Check if the scheduled task already exists
    try {
        $existingTask = Get-ScheduledTask -TaskName $taskName -ErrorAction Stop
        Write-Host "Scheduled task '$taskName' already exists. Skipping creation."
    } catch {
        Write-Host "Scheduled task '$taskName' does not exist. Proceeding with creation."

        # Load the XML file
        [xml]$xml = Get-Content -Path $destinationFilePathXML

        # Save the modified XML, overwriting the original file
        $xml.Save($destinationFilePathXML)

        # Register the scheduled task using the plain text password
        Register-ScheduledTask -Xml (Get-Content $destinationFilePathXML -Raw) -TaskName $taskName -User $serviceAccountUPN -Password $UnsecurePassword | Out-Null
        Write-Host "Scheduled task '$taskName' created to run whether the user is logged in or not."
    }

    # Function to check if the On-Premises Data Gateway is already installed
    function Is-DataGatewayInstalled {
        $gatewayPath = "C:\Program Files\On-premises data gateway\EnterpriseGatewayConfigurator.exe"
        return Test-Path -Path $gatewayPath
    }

    # Function to download the latest version of the On-Premises Data Gateway
    function Download-OnPremisesDataGateway {
        # Define the destination file path for the data gateway installer
        $destinationFilePathGateway = Join-Path -Path $destinationDirectory -ChildPath "GatewayInstall.exe"

        # Check if the On-Premises Data Gateway is already installed
        if (Is-DataGatewayInstalled) {
            Write-Output "The On-Premises Data Gateway is already installed."
            return
        }

        # Check if the installer has already been downloaded
        if (Test-Path -Path $destinationFilePathGateway) {
            Write-Output "The On-Premises Data Gateway installer has already been downloaded."
            return
        }

        # Define the URL of the On-Premises Data Gateway download page
        $downloadPageUrl = "https://www.microsoft.com/en-us/download/details.aspx?id=53127"

        # Use Invoke-WebRequest to fetch the download page content
        $response = Invoke-WebRequest -Uri $downloadPageUrl -UseBasicParsing

        # Use a regex pattern to find the download link from the page content
        $downloadLinkPattern = 'https://download\.microsoft\.com/download/.+?/GatewayInstall\.exe'
        $matches = [regex]::Matches($response.Content, $downloadLinkPattern)

        # Check if a match was found
        if ($matches.Count -gt 0) {
            # Use the first match as the download URL
            $downloadUrl = $matches[0].Value

            # Download the file
            Invoke-WebRequest -Uri $downloadUrl -OutFile $destinationFilePathGateway -UseBasicParsing

            # Output the status to the console
            Write-Output "Downloaded the On-Premises Data Gateway installer to $destinationFilePathGateway"
        } else {
            Write-Output "Could not find the download link on the page."
        }
    }

    # Call the function to download the On-Premises Data Gateway
    Download-OnPremisesDataGateway

    # Define the command to run the installer silently
    $installCommand = "$destinationFilePathGateway /quiet /install"

    # Check if the On-Premises Data Gateway is not installed and the installer has been downloaded
    if (-not (Is-DataGatewayInstalled) -and (Test-Path -Path $destinationFilePathGateway)) {
        # Run the installer
        Invoke-Expression -Command $installCommand
    }
}
catch {
    # Handle any exceptions that occur within the try block
    Write-Host "An error occurred: $_"
}
finally {
    # This block runs regardless of whether an error occurred
    Stop-Transcript
}