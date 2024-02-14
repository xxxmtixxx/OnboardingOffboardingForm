# Show an example of the domain and explain what the user should input
Write-Host ""
Write-Host "Enter the domain part of the 'sa.onboarding' service account email address."
Write-Host "Example: If the full email is `sa.onboarding@yourdomain.com`, you should enter `yourdomain.com`."

# Prompt the user for the domain part of the email
Write-Host ""
$domainPart = Read-Host "Please enter the domain part of the email"

# Construct the full email address by combining the static part with the user-provided domain part
$serviceAccountUPN = "sa.onboarding@$domainPart"

# Display the constructed email address for confirmation
Write-Host "The service account email address is: $serviceAccountUPN"

# Import the required module for Azure AD
Install-Module MSOnline
Import-Module MSOnline

# Connect to Azure AD
Connect-MsolService

# Check if the service account already exists
$serviceAccount = Get-MsolUser -UserPrincipalName $serviceAccountUPN -ErrorAction SilentlyContinue
if ($serviceAccount) {
    Write-Output "Service account '$serviceAccountUPN' already exists."
} else {
    $newServiceAccountPassword = Read-Host -Prompt "Enter the password for the new service account $serviceAccountUPN" -AsSecureString
    
    # Convert the secure string password to plain text
    $UnsecurePassword = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($newServiceAccountPassword))

    # Create the new user
    New-MsolUser -UserPrincipalName $serviceAccountUPN -DisplayName "Onboarding Service Account" -Password $UnsecurePassword -ForceChangePassword $false | Out-Null

    # Add the user to the Global Admins role
    Add-MsolRoleMember -RoleName "Company Administrator" -RoleMemberEmailAddress $serviceAccountUPN | Out-Null

    Write-Output "Service account '$serviceAccountUPN' created and added to the Global Admins role."
}
