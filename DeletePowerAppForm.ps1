# Import the required module
Import-Module -Name Microsoft.PowerApps.Administration.PowerShell

# Connect to Power Apps
Add-PowerAppsAccount

# Get the apps
Get-AdminPowerApp

# Delete the app
Remove-AdminPowerApp -AppName '' -EnvironmentName ''