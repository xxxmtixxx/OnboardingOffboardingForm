# Get the domain
$domain = (Get-ADDomain).DNSRoot

### Modify These Variables ###
$externalDomain = '' # Specify the external domain name. Ex: yourdomain.com
$homeDrive = 'U:' # Specify Home Drive Letter. Ex: U:
$homeDirectory = '' # Specify the shared Home Drive path. Ex: \\server\Users
$securityGroupOU = 'Security Groups', 'Security Groups Sync' # Specify the Security Group OUs - Seperate with commas Ex: 'Security Groups', 'Security Groups Sync'
$domainUsersOU = 'Domain Users' # Specify the Domain Users OU
$csvFilePath = 'C:\OnboardingScripts\Onboarding Staging' # Specify the CSV path. Ex: C:\OnboardingScripts\Onboarding Staging
$destinationPath = 'C:\OnboardingScripts\Onboarding Complete' # Specify the destination path. Ex: C:\OnboardingScripts\Onboarding Complete
$logPath = 'C:\OnboardingScripts\Logs' # Specify the log path. Ex: C:\OnboardingScripts\Logs
##############################

# Static Domain Variables
$dctl = "DC=$($domain.Split('.')[0]),DC=$($domain.Split('.')[1])"
$dc = "$($domain.Split('.')[0])"
$dc = $dc.ToUpper() # Convert to uppercase
$sgous = @()
foreach ($ou in $securityGroupOU) {
    $sgous += "OU=$ou,$dctl"
}
$duou = "OU=$domainUsersOU,$dctl"
$userData = @()

# Import the Active Directory module
Import-Module ActiveDirectory

# Add a .NET type to generate random passwords
Add-Type -AssemblyName System.Web

# Get all CSV files in the directory
$csvFiles = Get-ChildItem -Path $csvFilePath -Filter '*.csv' 

if ($csvFiles -eq $null) {
    Write-Output "INFO: No CSV files found in the directory."
    exit
}

# Loop over each CSV file
foreach ($csvFile in $csvFiles){
    $filename = $csvFile.name
    $fileprefix = "$($filename.Split('.')[0])"
    $logfile = "$fileprefix.log"
    $logFullPath = "$logPath\$logfile"
    $systemLog = "$logPath\SystemLog.log"
    $noManager = $false
    $warning = $false

    # Check if corresponding log file exists
    if (-Not (Test-Path $logFullPath)) {
        # Start the transcript
        Start-Transcript -Path $logFullPath -Append

        # Import CSV data
        $data = Import-Csv -Path $csvFile.FullName

        # Get all the groups in the OUs
        $groups = foreach ($sgou in $sgous) {
            Get-ADGroup -Filter * -Properties Description -SearchBase $sgou
        }

        # Create an empty array to hold the results
        $results = @()

        # Iterate over the groups
        foreach ($group in $groups) {
            # Add the group names and descriptions to the results
            $results += New-Object PSObject -Property @{
                'GroupName' = "$dc\$($group.Name)"
                'Description' = $group.Description
            }
        }

        foreach ($row in $data) {
            $firstname = $row.firstname
            $middleInitial = $row.middleInitial
            $lastname = $row.lastname
            $jobtitle = $row.jobtitle
            $department = $row.department
            $office = $row.office
            $mobilePhone = $row.mobilePhone
            $officePhone = $row.officePhone
            $manager = $row.manager | ConvertFrom-Json
            $mappeddrives = $row.mappeddrives | ConvertFrom-Json
            $applications = $row.applications | ConvertFrom-Json
            $licenses = $row.licenses | ConvertFrom-Json

            # Generate a random password
            $initialPassword = "Temp!" + [System.Web.Security.Membership]::GeneratePassword(6, 0)  # 6 characters long with 0 non-alphanumeric characters
            $securePassword = ConvertTo-SecureString -AsPlainText $initialPassword -Force

            # Create a new Active Directory user
            try {
                $samAccountName = "$($firstname[0])$lastname"
                $errorOccurred = ("ERROR: {0} profile setup FAILED to complete" -f "$firstname $lastname")

                # Find the manager in AD
                $managerAccount = Get-ADUser -Filter "DisplayName -eq '$($manager.DisplayName)'" | Select-Object -First 1

                # Check if the user already exists in AD
                $existingUser = Get-ADUser -Filter "SamAccountName -eq '$samAccountName'" | Select-Object -First 1

                if ($existingUser -ne $null) {
                    Write-Output ("ERROR: {0} already exists in AD" -f $samAccountName)
                    Write-Output $errorOccurred
                    Stop-Transcript
                    continue
                }

                # If the user does not exist, then create the new user
                if ($managerAccount -ne $null) {
                    # If the manager exists, create the user with the manager
                    $newUser = New-ADUser `
                                -Name "$firstname $lastname" `
                                -DisplayName "$firstname $lastname" `
                                -GivenName $firstname `
                                -Initials "$($middleInitial[0])" `
                                -Surname $lastname `
                                -UserPrincipalName "$samAccountName@$externalDomain" `
                                -EmailAddress "$samAccountName@$externalDomain" `
                                -SamAccountName $samAccountName `
                                -Title $jobtitle `
                                -Department $department `
                                -Office $office `
                                -OfficePhone $officePhone `
                                -MobilePhone $mobilePhone `
                                -Manager $managerAccount.SamAccountName `
                                -Enabled $true `
                                -PassThru `
                                -Path $duou `
                                -AccountPassword $securePassword -ChangePasswordAtLogon $true
                } else {
                    # If the manager doesn't exist, create the user without the manager
                    $warning = $true
                    $noManager = $true
                    $newUser = New-ADUser `
                                -Name "$firstname $lastname" `
                                -DisplayName "$firstname $lastname" `
                                -GivenName $firstname `
                                -Initials "$($middleInitial[0])" `
                                -Surname $lastname `
                                -UserPrincipalName "$samAccountName@$externalDomain" `
                                -EmailAddress "$samAccountName@$externalDomain" `
                                -SamAccountName $samAccountName `
                                -Title $jobtitle `
                                -Department $department `
                                -Office $office `
                                -OfficePhone $officePhone `
                                -MobilePhone $mobilePhone `
                                -Enabled $true `
                                -PassThru `
                                -Path $duou `
                                -AccountPassword $securePassword -ChangePasswordAtLogon $true
                    }
            } catch {
                do {
                    if ($_.Exception.Message -like "*The password does not meet the length, complexity, or history requirement of the domain.*") {
                        # Generate new random password
                        $newPassword = GeneratePassword
                        try {
                            # Update the user's password     
                            Set-ADUser -Identity $samAccountName -ChangePasswordAtLogon $false -PasswordNeverExpires $true -AccountPassword (ConvertTo-SecureString -AsPlainText $newPassword -Force) 
                            Write-Output ("PASSWORD UPDATE: Previous random password wasn't complex enough. New password is {0}" -f $newPassword)

                            # Re-enable the user account
                            Set-ADUser -Identity $samAccountName -Enabled $true
                            break
                        } catch {
                            if ($_.Exception.Message -notlike "*The password does not meet the length, complexity, or history requirement of the domain.*") {
                                throw $_
                            }
                        }
                    } else {
                        throw $_
                    }
                } while ($true)
            }
            # Check if the user was created successfully
            $createdUser = Get-ADUser -Filter "SamAccountName -eq '$($samAccountName)'" | Select-Object -First 1

            if ($createdUser -eq $null) {
                Write-Output "ERROR: $($samAccountName) not created in AD."
                Write-Output $errorOccurred
                Stop-Transcript
                continue
            } else {
                if ($noManager) {
                    # Print out the user's details
                    Write-Output ("WARNING: Created {0} ({1}) with no manager and the password is {2}" -f "$firstname $lastname", $newUser.UserPrincipalName, $initialPassword)
                    $noManager = $false
                } else {
                    # Print out the user's details
                    Write-Output ("SUCCESS: Created {0} ({1}) with manager set to {2} and the password is {3}" -f "$firstname $lastname", $newUser.UserPrincipalName, $($manager.DisplayName), $initialPassword)
                }
            }

            # Initialize an array to store the group names
            $userGroups = @()

            # Get the user's licenses
            $userLicensesDescription = $licenses.value

            # Iterate over the licenses and add the user to the corresponding security groups
            foreach ($license in $userLicensesDescription) {
                $matchingLicense = $results | Where-Object { $_.Description -eq $license }

                if ($matchingLicense) {
                    # Add the newly created user to the corresponding security group
                    $strippedLicenseGroupName = $matchingLicense.GroupName.Split('\')[1]
                    try {
                        Add-ADGroupMember -Identity $strippedLicenseGroupName -Members $samAccountName
                        Write-Output ("SUCCESS: Added {0} to security group {1} for license {2}" -f "$firstname $lastname", $matchingLicense.GroupName, $license)
                        # Add the group name to the array
                        $userGroups += $strippedLicenseGroupName
                    }
                    catch {
                        Write-Output ("WARNING: Failed to add {0} to security group {1} for license {2}" -f "$firstname $lastname", $matchingLicense.GroupName, $license)
                        $warning = $true
                    }
                } else {
                    Write-Output ("WARNING: No matching Security Group found for license: $license")
                    $warning = $true
                }
            }

            # Get the user's applications
            $userApplicationsDescription = $applications.value

            # Iterate over the applications and add the user to the corresponding security groups
            foreach ($application in $userApplicationsDescription) {
                $matchingApplication = $results | Where-Object { $_.Description -eq $application }

                if ($matchingApplication) {
                    # Add the newly created user to the corresponding security group
                    $strippedAppGroupName = $matchingApplication.GroupName.Split('\')[1]
                    try {
                        Add-ADGroupMember -Identity $strippedAppGroupName -Members $samAccountName
                        Write-Output ("SUCCESS: Added {0} to security group {1} for application {2}" -f "$firstname $lastname", $matchingApplication.GroupName, $application)
                        # Add the group name to the array
                        $userGroups += $strippedAppGroupName
                    }
                    catch {
                        Write-Output ("WARNING: Failed to add {0} to security group {1} for application {2}" -f $samAccountName, $matchingApplication.GroupName, $application)
                        $warning = $true
                    }
                } else {
                    Write-Output ("WARNING: No matching Security Group found for application: $application")
                    $warning = $true
                }
            }

            # Get the user's mapped drives
            $userMappedDrivesDescription = $mappeddrives.value

            # Extract the first letter of $homeDrive
            $homeDriveLetter = $homeDrive.Substring(0,1)

            # Iterate over the mapped drives and add the user to the corresponding security groups
            foreach ($drive in $userMappedDrivesDescription) {
                # Skip if the drive is the HomeDrive
                if ($drive[0] -ne $homeDriveLetter) {
                    $matchingGroup = $results | Where-Object { $_.Description -eq $drive }
                    if ($matchingGroup) {
                        # Add the newly created user to the corresponding security group
                        $strippedMDGroupName = $matchingGroup.GroupName.Split('\')[1]
                        try {
                            Add-ADGroupMember -Identity $strippedMDGroupName -Members $samAccountName
                            Write-Output ("SUCCESS: Added {0} to security group {1} for drive {2}" -f "$firstname $lastname", $matchingGroup.GroupName, $drive)
                            # Add the group name to the array
                            $userGroups += $strippedMDGroupName
                        } catch {
                            Write-Output ("WARNING: Failed to add {0} to security group {1} for drive {2}" -f $samAccountName, $matchingGroup.GroupName, $drive)
                            $warning = $true
                        }
                    } else {
                        Write-Output ("WARNING: No matching Security Group found for $drive")
                        $warning = $true
                    }
                }

                # Check if the first mapped drive letter matches $homeDrive  
                if ($drive[0] -eq $homeDriveLetter) {
                    # Check if Home directory already exists
                    if (-not (Test-Path -Path "$homeDirectory\$samAccountName")) {
                        # Create Home directory
                        New-Item -path $homeDirectory -Name $samAccountName -Type Directory | Out-Null
                        Write-Output ("SUCCESS: Home directory {0}\{1} created for {2}" -f $homeDirectory, $samAccountName, "$firstname $lastname")

                        # Set permissions on user folders
                        $permissions = $samAccountName
                        $acl = Get-Acl $homeDirectory\$permissions
                        $AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("$permissions","FullControl","ContainerInherit,ObjectInherit","None","Allow")
                        $acl.SetAccessRule($AccessRule)
                        $acl | Set-Acl $homeDirectory\$permissions
                        Write-Output ("SUCCESS: Granted {0} permissions to the home directory" -f "$firstname $lastname")

                        # Set Home directory in AD
                        $setUser = Set-ADUser -Identity $newUser `
                        -HomeDirectory $homeDirectory\$permissions `
                        -HomeDrive $homeDrive
                        Write-Output ("SUCCESS: Added home directory and {0} drive to {1} in AD" -f $homeDrive, "$firstname $lastname")
                    } else {
                        Write-Output ("WARNING: Home directory {0}\{1} already exists" -f $homeDirectory, "$firstname $lastname")
                        Write-Output ("WARNING: No permissions set on home directory" -f $homeDirectory, "$firstname $lastname")
                        $warning = $true
                    }
                }
            }

            # After all the operations, write the group names to a text file
            $userGroups -join ', ' | Out-File -FilePath "$destinationPath\Output\$($firstname)$($lastname)Groups.txt"

            $userData += New-Object PSObject -Property ([ordered]@{
                'Username' = $samAccountName
                'Password' = $initialPassword
            })

            # Create the formatted string
            $formattedData = "Username: $($userData.Username)<br>Password: $($userData.Password)"

            # Write the formatted string to a text file
            Add-Content -Path "$destinationPath\Output\$($firstname)$($lastname)Output.txt" -Value $formattedData

            Write-Output ("SUCCESS: Output file written")

            
            # Move the CSV file to the Completed folder
            Move-Item -Path $csvFile.FullName -Destination $destinationPath

            # Verify that the file was moved
            if (Test-Path -Path "$destinationPath\$($csvFile.Name)") {
                # Set the flag to true since at least one CSV file was processed
                $csvProcessed = $true
                if ($warning) {
                    Write-Output ("WARNING: {0} profile setup completed with WARNINGS" -f "$firstname $lastname")
                    Stop-Transcript
                    $warning = $false
                    } else {
                    Write-Output ("SUCCESS: {0} profile setup completed SUCCESSFULLY" -f "$firstname $lastname")
                    Stop-Transcript
                    $warning = $false
                    }
            } else {
                Write-Output ("ERROR: CSV FAILED to move")
                Write-Output $errorOccurred
                Stop-Transcript
            }
        }
    } else {
        Start-Transcript -Path $logFullPath -Append
        Write-Output ("ERROR: Log file {0} already exists. Checking next CSV." -f $logFullPath)
        Stop-Transcript
    }
}

# Check if any CSV files were processed before running Start-ADSyncSyncCycle
if ($csvProcessed) {
    Start-Transcript -Path $systemLog -Append
    Write-Output ("SUCCESS: CSV files processed. Starting Entra Connect Delta Sync.")
    Start-ADSyncSyncCycle -PolicyType Delta | Out-Null
    $csvProcessed = $false
    $warning = $false
    Stop-Transcript
} else {
    Start-Transcript -Path $systemLog -Append
    Write-Output ("WARNING: No CSV files were processed. Skipping Entra Connect Delta Sync.")
    Stop-Transcript
}