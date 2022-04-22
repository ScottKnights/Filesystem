#Requires -Version 5
#Requires -Modules ActiveDirectory
<#
    .SYNOPSIS
	Protect one or more folders with read only -R and modify -M domain local groups
    .DESCRIPTION
	Protect one or more folders with read only -R and modify -M domain local groups

	This reflects the IGDLA group naming convention we use.
	Resource groups are named as closely as possible to the resource they secure and have a 2 letter prefix indicating their usage.
	Folder permissions resource groups have the name FL-<PATH>-Permission, where permission is M (Modify), R (Read), T (Traverse - dont use this!)
	As group names cannot contain \ characters, they are replaced with !.
	Examples would be to create the following groups to protect the folder N:\Data\HR
		FL-N!Data!HR-M - Modify
		FL-N!Data!HR-R - Read only
	These groups can then be populated with the required role groups containing your users.

	Folder paths can be supplied as an array at the command line or in a file.
	If the folder paths don't exist they will be created as long as they don't contain illegal characters <>:"/\|?*
	-M and -R Groups will be created based on the folder names if they don't already exist:
		The path prefix will be replaced by the Group prefix. The prefixes used will depend on your naming convention.
		Any \ characters will be replaced by !
		Other characters not allowed in group names will have the following substitutions - Feel free to modify these to suit your preferences!
			[ replaced by (
			] replaced by )
			; replaced by _
			, replaced by _
			= replaced by -
			+ replaced by -
	If the resultant group names are longer than 64 characters, they will be shortened to 64 by replacing the middle of the group name with the specified centre string.
		Ideally don't do this! Overly long group names indicate that you are using excessively long folder names, and/or applying permissions at a very deep level.
	If -traverse is specified, a third group with read only permissions to the folder only will be created.
		This is something else you should avoid if possible and is only provided for terrible file systems where subfolders are less restricted than the parent.

	Inheritance will be disabled and the following permissions will be applied:
		administrators - Full Control
		SYSTEM - Full Control
		-R group - Read only to folder and contents
		-M group - Modify the contents of the folder, but not the folder itself
		-T group - Read only to the folder only. Only created if -traverse switch is specified. Don't do it!
	Existing permissions will be removed, so users in the specified groups won't have access until they have logged off and back on.

	A well laid out file system should:
		Only apply permissions at the top few levels of folders. Don't apply permissions at more than two or three levels deep.
		Have short but descriptive folder names.
		Applied permissions only get more restrictive. Subfolders have less users accessing than the parent, who are a subset of the users that can access the parent.

	Example:
		\Data 			- Root folder. All staff have read access
		\Data\Common		- Common area. All staff have modify access
		\Data\HR		- HR folder. HR Team have modify access. HR Team are a subset of all staff.
		\Data\HR\HR Managers	- Only HR Managers have access. HR Managers are a subset of the HR team.
		\Data\HR\Policies	- HR Managers have modify access, HR Team have read access.

	A file system designed like this would have no need for long group names or traverse groups.

	Example badly designed file system:
		\Data\HR\Timesheets	- All staff need access here to submit timesheets

	Users need access to the timesheets folder, but must not access anything else inside HR. The subfolder is less restrictive than the parent. This requires a traverse group on HR.
	This should indicate that the timesheets folder is in the wrong place, so the better option is to move it outside of HR rather than use a traverse group.

	Although the function can be controlled by passing in parameters, the best option is to modify the default values of most of the parameters to reflect the environment instead
	of passing them all in each time. You then just need to pass in the folder name(s).

	Add the function to a profile on the file or management server to make it always available. Profiles are scripts that will run whenever you start a powershell host.
		$profile.AllUsersAllHosts is the profile for everyone on the server and all powershell hosts.
			Create the file (default C:\Windows\System32\WindowsPowerShell\v1.0\profile.ps1) if it doesn't exist and either:
			* Copy/paste the function into it.
			* Use Import-Module to import this module into the profile.

	Other profiles and their default values are:
		$profile.AllUsersCurrentHost - C:\Windows\System32\WindowsPowerShell\v1.0\Microsoft.PowerShell_profile.ps1
		$profile.CurrentUserAllHosts - C:\Users\<USERNAME>\Documents\WindowsPowerShell\profile.ps1
		$profile.CurrentUserCurrentHost - C:\Users\<USERNAME>\Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1

	The function needs to be run either as an administrator or as a user with the following delegated rights:
		Ability to create folders on the file server and apply permissions
		Ability to create groups in the specified OU

    .PARAMETER paths
	String Array. Comma seperated list of paths to secure. If more than one path though, probably best to use a file.

    .PARAMETER pathfile
	String. Path to file containing a list of folders to secure.

    .PARAMETER noconfirm
	Switch. Will not ask for confirmation of created group names if specified.

    .PARAMETER groupou
	String. DN of the OU in which the groups will be created.

    .PARAMETER pathprefix
	String. Prefix of the path you want to replace. Could be a local path or a UNC.

    .PARAMETER groupprefix
	String. Prefix of the groups that will be created.

    .PARAMETER centstring
	String. String used to replace the removed characters from groups >64 characters in length. Again, you really don't want to have to use this.

    .PARAMETER traverse
	Switch. Create a traverse group if specified. Something else you shoudn't use!

    .INPUTS

    .OUTPUTS

    .NOTES
	Scott Knights
	V 1.20220422.1
		Initial Release

    .EXAMPLE
	protect-folder -paths "E:\Data\Data\Company Data\HR" -noconfirm -pathprefix "E:\Data\Data\" -groupprefix "FL-N!" -groupou "OU=FileServer,OU=Org,DC=Domain,DC=com"
		Create the folder "E:\Data\Data\Company Data\HR" if it doesn't already exist
		Create the following two groups (if they don't already exist) in the OU "OU=FileServer,OU=Org,DC=Domain,DC=com" without asking for confirmation:
			FL-N!Company Data!HR-M
			FL-N!Company Data!HR-R
		Apply permissions to the folder

    .EXAMPLE
	protect-folder -paths "\\SERVER\Share\Company Data\HR\My really secure documents that are buried deep in the filesystem" -pathprefix "\\SERVER\Share\" -groupprefix "FL-N!" -centstring "###"
		Create the folder "\\SERVER\Share\Company Data\HR\My really secure documents that are buried deep in the filesystem" if it doesn't already exist
		Create the following two groups in the default OU if they don't already exist after asking for confirmation:
			FL-N!Company Data!HR!My really###uried deep in the filesystem-M
			FL-N!Company Data!HR!My really###uried deep in the filesystem-R
		Apply permissions to the folder

    .EXAMPLE
	protect-folder -pathfile ".\mylistofpaths.txt" -noconfirm
		Create all the required groups to secure all the paths in file ".\mylistofpaths.txt" using the default values assigned to the other parameters.
		Don't ask for confirmation when creating groups.
#>

# Modify the default values to reflect your environment.
function protect-folder {
	param (
		[Parameter()]
		[String[]] $paths,

		[Parameter()]
		[String] $pathfile,

		[Parameter()]
		[String] $groupou="OU=Filesystem Security,OU=Groups,OU=Corp,DC=Domain,DC=com",

		[Parameter()]
		[String] $pathprefix="E:\Data\Data\",

		[Parameter()]
		[String] $groupprefix="FL-",

		[Parameter()]
		[String] $centstring="..",

		[Parameter()]
		[Switch] $traverse,

		[Parameter()]
		[switch] $noconfirm

	)

	# Maximum group name length
	$maxlength=64

	# Get the list of paths from a file
	if ($pathfile) {
		$paths=get-content $pathfile
	}

	foreach ($path in $paths) {

		write-output "Processing path: $path"

		if (-not $path) {
			write-output "No path specified."
			continue
		}

		# Test if the path starts with the path prefix
		if ($path -notlike $pathprefix+"*") {
			write-output "$path does not start with the prefix $pathprefix."
			continue
		}

		# Test if the path contains invalid characters
		try {
			[System.IO.FileInfo]$Path|out-null
		} catch {
			write-output "Path $path contains invalid characters."
			continue
		}

		# Strip the path prefix
		$shortpath=$path.Substring($pathprefix.length)

		# Prepend the group prefix to set the write group name and replace \ with !
		$mgroup=$groupprefix+$shortpath.replace("\","!")+"-M"

		# Replace any illegal characters in group name
		$mgroup=$mgroup.replace("[","(").replace("]",")").replace(";","_").replace(",","_").replace("=","-").replace("+","-")

		# check if the group name would be too long, shorten if it is.
		$length=$mgroup.length
		if ($length -gt $maxlength) {
			$reduce=($length-$maxlength+$centstring.length)/2
			$newgroup=($mgroup.substring(0,$length/2-$reduce))+$centstring+($mgroup.substring($length/2+$reduce))
			# Check if you are happy with the shortened group name
			write-output "Group name is longer than $maxlength characters. Shortening."
			$mgroup=$newgroup
		}

		# Set the read group name based on the M group name
		$rgroup=$mgroup.substring(0,$mgroup.length-1)+"R"
		# Set the traverse group name based on the M group name. please don't do this!
		if ($traverse) {
			$tgroup=$mgroup.substring(0,$mgroup.length-1)+"T"
		}

		# Check for confirmation
		if (-not $noconfirm) {
			write-output "The following groups will be created if they don't exist and permissions applied to the folder. Do you want to proceed?"
			write-output $mgroup
			write-output $rgroup
			if ($traverse) {
				write-output $tgroup
			}
			choice /c yn
			$response=$LASTEXITCODE
			if ($response -eq 2) {
				continue
			}
		}

		# Try to create the folder if it doesn't already exist
		if (-NOT (test-path -literalpath $path)) {
			write-output "$path does not exist. Attempting to create it."
			try {
				New-Item -Path $path -ItemType "directory"|out-null
			} catch {
				write-output "Unable to create $path."
				continue
			}
		}

		# Try to create the groups if they don't already exist
		write-output "Creating groups..."
		try {
			if (-not(Get-ADGroup -Filter {SamAccountName -eq $mgroup})) {
				New-ADGroup -Name $mgroup -SamAccountName $mgroup -GroupCategory Security -GroupScope Domainlocal -DisplayName $mgroup -Path $groupou
			}
			if (-not(Get-ADGroup -Filter {SamAccountName -eq $rgroup})) {
				New-ADGroup -Name $rgroup -SamAccountName $rgroup -GroupCategory Security -GroupScope Domainlocal -DisplayName $rgroup -Path $groupou
			}
			if ($traverse) {
				if (-not(Get-ADGroup -Filter {SamAccountName -eq $tgroup})) {
					New-ADGroup -Name $tgroup -SamAccountName $tgroup -GroupCategory Security -GroupScope Domainlocal -DisplayName $tgroup -Path $groupou
				}
			}
		} catch {
			write-output "Failed to create groups for $path"
		}
		# Try to set the permissions on the path
		write-output "Setting Permissions..."
		try {
			$msid=(get-adgroup $mgroup).sid.value
			$rsid=(get-adgroup $rgroup).sid.value
			$acl = Get-Acl $path
			if ($traverse) {
				$tsid=(get-adgroup $tgroup).sid.value
				$sddl="O:BAG:DUD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICIIO;0x1301bf;;;$msid)(A;;0x1201bf;;;$msid)(A;OICI;0x1200a9;;;$rsid)(A;;0x1200a9;;;$tsid)"
			} else {
				$sddl="O:BAG:DUD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICIIO;0x1301bf;;;$msid)(A;;0x1201bf;;;$msid)(A;OICI;0x1200a9;;;$rsid)"
			}
			$acl.SetSecurityDescriptorSddlForm($sddl)
			Set-Acl -Path $path -AclObject $acl
		} catch {
			write-output "Failed to set permissions on $path"
		}
	}
}
