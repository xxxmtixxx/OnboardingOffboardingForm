# Show examples and prompt for source site URL
Write-Host ""
Write-Host "Enter the source site URL."
Write-Host "Example: https://domain.sharepoint.com/sites/OnboardingOffboardingHub"
$sourceSiteURL = Read-Host "Please enter the source site URL"

# Show examples and prompt for destination tenant URL
Write-Host ""
Write-Host "Enter the destination tenant URL."
Write-Host "Example: https://domain.sharepoint.com"
$destinationTenantURL = Read-Host "Please enter the destination tenant URL"

# Display the entered URLs for confirmation
Write-Host ""
Write-Host "Source Site URL: $sourceSiteURL"
Write-Host "Destination Tenant URL: $destinationTenantURL"

Install-Module -Name PnP.PowerShell -RequiredVersion 1.12.0 -Scope CurrentUser -AllowClobber
Import-Module PnP.PowerShell

# Extract tenant name and site title from the source URL
$tenantName = $destinationTenantURL -replace 'https://', '' -replace '.sharepoint.com', ''
$adminUrl = "https://$tenantName-admin.sharepoint.com"
$sourceUri = New-Object System.Uri($sourceSiteURL)
$sourceSiteSubDomain = $sourceUri.Segments[-1].TrimEnd('/')
$sourceSiteTitle = "Onboarding & Offboarding Hub"

# Set new site URL and title for the destination tenant
$destinationSiteURL = "$destinationTenantURL/sites/$sourceSiteSubDomain"
$destinationSiteTitle = $sourceSiteTitle
$destinationSiteSubDomain = $sourceSiteSubDomain

# Connect to Source SharePoint
Write-Host "Connecting to Source SharePoint"
Connect-PnPOnline -Url $sourceSiteURL -Interactive

# Define or retrieve the source list names
$sourceListNames = @("Onboarding Form", "Onboarding Completed")

# Initialize arrays to store source list details
$sourceListsDetails = @()

# Retrieve details for each source list
foreach ($sourceListName in $sourceListNames) {
    $sourceList = Get-PnPList -Identity $sourceListName -Includes BaseTemplate, Fields
    if ($null -eq $sourceList) {
        Write-Host "Source list '$sourceListName' not found. Skipping..."
        continue
    }
    $sourceListsDetails += @{
        Name = $sourceListName
        List = $sourceList
        Fields = $sourceList.Fields
        BaseTemplate = $sourceList.BaseTemplate
    }
}

# Connect to Destination SharePoint Admin
Write-Host "Connecting to Destination SharePoint"
Connect-PnPOnline -Url $adminUrl -Interactive

# Get the email of the current user
$currentContext = Get-PnPContext
$currentContext.Load($currentContext.Web.CurrentUser)
$currentContext.ExecuteQuery()
$currentEmail = $currentContext.Web.CurrentUser.Email

# Create a new Team Site at the destination
New-PnPSite -Type TeamSite -Title $destinationSiteTitle -Alias $destinationSiteSubDomain
# Create a new Communication Site at the destination
#New-PnPSite -Type CommunicationSite -Title $destinationSiteTitle -Url $destinationSiteURL -Owner $currentEmail -Lcid 1033

# Connect to the newly created Team Site
Write-Host "Connecting to Newly Created SharePoint Site"
Connect-PnPOnline -Url $destinationSiteURL -Interactive

# Process each source list and create corresponding lists in the destination
foreach ($sourceListDetail in $sourceListsDetails) {
    $destinationListName = $sourceListDetail.Name
    $sourceFields = $sourceListDetail.Fields
    $sourceBaseTemplate = $sourceListDetail.BaseTemplate

    # Create the destination list
    $destinationList = New-PnPList -Title $destinationListName -Template $sourceBaseTemplate

    # Collect new field names
    $newFieldNames = @()
    $specialFields = @("Author", "Editor")

    # Create the destination list fields and collect their names
    foreach ($field in $sourceFields) {
        $fieldXml = $field.SchemaXml
        $result = Add-PnPFieldFromXml -List $destinationList -FieldXml $fieldXml -ErrorAction SilentlyContinue

        if ($result) {
            # Add field name to the collection
            $newFieldNames += $field.InternalName
        }
    }

    # Add special fields to the collection if they are not already included
    foreach ($specialField in $specialFields) {
        if (-not ($newFieldNames -contains $specialField)) {
            $newFieldNames += $specialField
        }
    }

    # Define the desired order of fields
    $desiredFieldOrder = if ($sourceListName -eq "Onboarding Form") {
        @(
            "EmployeeID",
            "FirstName",
            "MiddleInitial",
            "LastName",
            "StartDate",
            "Manager_x002f_Approver",
            "ManagerComments",
            "ApprovalStatus",
            "OfficeLocation",
            "Department",
            "EmployeeTitle",
            "MobileNumber",
            "Ext_x002f_Number",
            "SelectPhoneMAC",
            "AvailableMachineList",
            "SecurityGroups",
            "Author",
            "Editor"
        )
    } else {
        @(
            "EmployeeID",
            "FirstName",
            "MiddleInitial",
            "LastName",
            "StartDate",
            "Manager_x002f_Approver",
            "ManagerComments",
            "ApprovalStatus",
            "OfficeLocation",
            "Department",
            "EmployeeTitle",
            "MobileNumber",
            "Ext_x002f_Number",
            "SelectPhoneMAC",
            "AvailableMachineList",
            "SecurityGroups",
            "Author",
            "Editor"
        )
    }

    # Reorder the field names as per the desired order
    $reorderedFieldNames = $desiredFieldOrder | Where-Object { $newFieldNames -contains $_ }

    # Get the default view of the destination list
    $defaultView = Get-PnPView -List $destinationList -Identity "All Items"

    # Combine current view fields with reordered field names
    # Exclude 'LinkTitle' (Title) from the view
    $updatedViewFields = ($defaultView.ViewFields | Where-Object { $_ -ne "LinkTitle" }) + $reorderedFieldNames

    # Update the view with the updated fields
    Set-PnPView -List $destinationList -Identity $defaultView.Id -Fields $updatedViewFields | Out-Null

    Write-Host "List '$sourceListName' copied and fields reordered successfully!"
}

# Retrieve the siteId, listId, and list URL for both lists
$destinationWeb = Get-PnPWeb
$siteId = "$destinationTenantURL$($destinationWeb.ServerRelativeUrl)"
foreach ($sourceListName in $sourceListNames) {
    $list = Get-PnPList -Identity $sourceListName
    $listId = $list.Id
    $listURL = "$destinationTenantURL$($list.DefaultViewUrl)"

    # Output the retrieved information
    Write-Host "List Name: $sourceListName"
    Write-Host "Site ID: $siteId"
    Write-Host "List ID: $listId"
    Write-Host "List URL: $listURL"
}

# Retrieve Quick Launch navigation nodes
$quickLaunchNodes = Get-PnPNavigationNode -Location QuickLaunch

# Define the titles of default links to remove
$defaultLinksToRemove = @("Home", "Documents", "Pages", "Recent", "Site contents")

# Remove the default links
foreach ($link in $defaultLinksToRemove) {
    $nodeToRemove = $quickLaunchNodes | Where-Object { $_.Title -eq $link }
    if ($nodeToRemove) {
        Remove-PnPNavigationNode -Identity $nodeToRemove.Id -Force
    }
}

# Add the new list links to the Quick Launch
foreach ($sourceListName in $sourceListNames) {
    $listURL = "$destinationTenantURL/sites/$sourceSiteSubDomain/Lists/$sourceListName/AllItems.aspx"
    if (-not ($quickLaunchNodes.Title -contains $sourceListName)) {
        Add-PnPNavigationNode -Title $sourceListName -Url $listURL -Location QuickLaunch | Out-Null
    } else {
        Write-Host "The link '$sourceListName' already exists in the Quick Launch."
    }
}