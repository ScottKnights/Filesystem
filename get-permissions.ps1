#Requires -Version 5
#Requires -Modules ActiveDirectory
<#
    .SYNOPSIS
	Report on permissions, showing files/folders with specific identity object types
    .DESCRIPTION
	Create a CSV file of permissions on each path inside the selected root path.
		Import into Excel and filter to see how good/bad your permissions are!
	Depth parameter allows you to select how deep to analyse the folder structure. Depth of 0 will only report on the top level.
		Depth defaults to 9999. Hopefully, nobody has a deeper file structure than this!
	The maxrows parameter sets the maximum number of rows per report file. Default is 1048575, which is the maximum rows in an excel sheet.
		If maxrows is exceeded, a new report file will be created with a numerical suffix (eg FolderPermissions.csv, FolderPermissions1.csv, FolderPermissions2.csv, etc)
	Can select patterns of identities to include or exclude from the report.
		Default is include everything (Include pattern is "*", no excludepatterns).
	Report permissions for the selected object types by specifying the required switches.
		If no object type switches are specified, all types will be reported on.
		Object types are:
			Domain User
			Domain Group
			Domain Computer
			Local User
			Local Group
			Builtin User
			Builtin Group
			CREATOR OWNER
			Unresolvable SID
			NT AUTHORITY
			Managed Service Accounts
			Group Managed Service Accounts
			Everyone
			No Permission (user running script has no access)
	Can also specify whether to report only on Allow or Deny permissions.
	Default is only to report on non inherited permissions. To report on all permissions use the inherited switch.
	There is a switch to report domain group scope, but this may make the report take longer to run.
	By default will only report on folders. There is a file switch to also report on file permissions, but this can lead to huge reports and extremely long run time.
	Will report if your OS supports long file paths and whether it is enabled.
		If there is no long file path support, paths >260 characters will be logged as identity type "Path too long".
	If there are any local users or groups granted permissions, the report will be generated much quicker if run from the server where these local objects exist.
		The script will try to get them from another machine, but this is slow and may fail due to network & permissions issues or if the machine is off.
		If it cannot identify whether an identity is a group or user it will report the identity type as "Local User/Group".
	Any identity type it cannot identify will be reported as "Unknown". If you get any unknowns, please report them so I can add them to the script.

    .PARAMETER rootfolder
	Mandatory string. Root folder of folder structure you want to get permissions from.
    .PARAMETER reportfile
	String. Output report file. Defaults to .\FolderPermissions.csv.
    .PARAMETER overwritereportfile
	Switch. Overwrite the report file if it already exists.
    .PARAMETER includepatterns
	String array. Comma seperated list of identity patterns to include in the report. Default of "*" to include everything.
    .PARAMETER excludepatterns
	String array. Comma seperated list of identity patterns to exclude from the report. Nothing excluded by default.
    .PARAMETER creatorowner
	Switch. Report files/folders that have CREATOR OWNER with permissions.
    .PARAMETER ntauthority
	Switch. Report files/folders that have an NT AUTHORITY account with permissions.
    .PARAMETER localuser
	Switch. Report files/folders that have a local user with permissions.
    .PARAMETER localgroup
	Switch. Report files/folders that have a local group with permissions.
    .PARAMETER domainuser
	Switch. Report files/folders that have a domain user with permissions.
    .PARAMETER domaingroup
	Switch. Report files/folders that have a domain group with permissions.
    .PARAMETER domaincomputer
	Switch. Report files/folders that have a domain computer with permissions.
    .PARAMETER domaingmsa
	Switch. Report files/folders that have a domain group managed service account with permissions.
    .PARAMETER domainmsa
	Switch. Report files/folders that have a domain managed service account with permissions.
    .PARAMETER builtinuser
	Switch. Report files/folders that have a builtin user with permissions.
    .PARAMETER builtingroup
	Switch. Report files/folders that have a builtin group with permissions.
    .PARAMETER sid
	Switch. Report files/folders that have an unresolvable SID with permissions.
    .PARAMETER everyone
	Switch. Report files/folders that have the everyone group with permissions.
    .PARAMETER nopermission
	Switch. Report files/folders that the user running the script has no permission to access.
    .PARAMETER files
	Switch. Generate report of files as well as folders. Can lead to a very large report and take a very long time to run.
    .PARAMETER allowonly
	Switch. Only report on allow permissions. Skip reporting deny ACLs.
    .PARAMETER inherited
	Switch. Report on inherited permissions. Default is only non inherited permissions.
    .PARAMETER denyonly
	Switch. Only report on deny permissions. Skip reporting allow ACLs.
    .PARAMETER reportscope
	Switch. Report scope of domain groups. Report may take a bit longer to run as it queries AD for each domain group.
    .PARAMETER depth
	Integer. Controls how deep to analyse the folder structure. Default 9999.
    .PARAMETER maxrows
	Integer. Maximum number of rows per report file.



    .INPUTS

    .OUTPUTS

    .NOTES
	Scott Knights
	V 1.20220316.1
		Initial Release
	V 1.20220318.1
		Added #Requires -RunAsAdministrator
		Fixed No access ACLs not being reported due to issue with groupscope
	V 1.20220322.1
		Fixed issue with MSA/GMSA reporting
	V 1.20220404.1
		Added some extra error trapping and removed #Requires -RunAsAdministrator
		Fix comment typos
		Use literalpath with get-acl
		Move variable declarations to top of script
		Change error path arrays to arraylists
	V 1.20220616.1
		Added depth parameter instead of using recurse
	V 1.20220804.1
		Fixed rootfolder parameter in examples
	V 2.20220819.1
		Rewrite to cope with large file systems.
		Uses self recursion to walk the file structure instead of getting all paths into an array at the start of the script.
		Runs faster and uses less memory, downside is there is no progress bar as we don't know how many paths there are.
		Added maxrows parameter to create multiple report files for large filesystems as Excel can only cope with 1048576 rows.
		Only show non inherited permissions by default. Use inherited parameter to show all permissions.
		V1 may still be preferred for small filesystems.
	TODO:
		Add a GUI front end?
    .EXAMPLE
	get-permissions -rootfolder "d:\data" -maxrows 50000 -inherited
	Report all identity types and all identities for d:\data and subfolders to default report file ".\FolderPermissions.csv"
	Report files have a maximum of 50000 rows
	Include inherited permissions

    .EXAMPLE
	get-permissions -rootfolder "d:\data" -reportfile ".\myreport.csv" -overwritereportfile -files -reportscope
	Report all identity types and all identities for d:\data, subfolders and files to report file ".\myreport.csv"
	Overwrite the report file if it already exists.
	Report group scope for domain groups

    .EXAMPLE
	get-permissions -rootfolder "d:\data" -domainuser -sid -denyonly -excludepatterns "*sam*","*max*"
	Report deny permissions for identity types domain users and unresolved SIDs for d:\data and subfolders
	Dont report on any identities containing "sam" or "max" in their samaccountnames.

    .EXAMPLE
	get-permissions -rootfolder "d:\data" -domaingroup -includepatterns "*FL-*" -allowonly
	Report allow permissions for domain groups with "FL-" in their name for d:\data and subfolders

    .EXAMPLE
	get-permissions -rootfolder "d:\home" -sid -depth 1
	Report unresolved SIDs for only the top level of folders in D:\home.
#>

# ============================================================================
#region Parameters
# ============================================================================
Param(
    [Parameter(Mandatory=$true,Position=0)]
    [String]$rootfolder,

    [Parameter()]
    [String]$reportfile=".\FolderPermissions.csv",

    [Parameter()]
    [String[]]$includepatterns="*",

    [Parameter()]
    [String[]]$excludepatterns,

    [Parameter()]
    [switch]$overwritereportfile,

    [Parameter()]
    [switch]$files,

    [Parameter()]
    [switch]$sid,

    [Parameter()]
    [switch]$creatorowner,

    [Parameter()]
    [switch]$ntauthority,

    [Parameter()]
    [switch]$localuser,

    [Parameter()]
    [switch]$localgroup,

    [Parameter()]
    [switch]$domainuser,

    [Parameter()]
    [switch]$domaingroup,

    [Parameter()]
    [switch]$domaincomputer,

    [Parameter()]
    [switch]$domaingmsa,

    [Parameter()]
    [switch]$domainmsa,

    [Parameter()]
    [switch]$builtinuser,

    [Parameter()]
    [switch]$everyone,

    [Parameter()]
    [switch]$nopermission,

    [Parameter()]
    [switch]$builtingroup,

    [Parameter()]
    [switch]$allowonly,

    [Parameter()]
    [switch]$inherited,

    [Parameter()]
    [switch]$denyonly,

    [Parameter()]
    [switch]$reportscope,

    [Parameter()]
    [int]$depth=9999,

    [Parameter()]
    [int]$maxrows=1048575
)
#endregion Parameters

# ============================================================================
#region Functions
# ============================================================================
# Check if the report file already exists. Delete it if $overwritereportfile is selected.
function test-outfile {
	param (
		[string]$outfile
	)

	if (test-path -literalpath $outfile) {
		if ($overwritereportfile) {
			try {
				remove-item -literalpath $outfile -force -erroraction stop
			} catch {
				write-output "Unable to delete existing report file $outfile. Exiting."
				exit
			}
		} else {
			write-output "The report file $outfile already exists. Move or rename. Exiting."
			exit
		}
	}
}


# Write an ACL entry to the report file
function write-reportfile {
	param (
		[string]$pathname="NA",
		[string]$pathtype="NA",
		[string]$owner="NA",
		[string]$identity="NA",
		[string]$permissions="NA",
		[string]$inherited="NA",
		[string]$accesstype="NA",
		[string]$identitytype="NA",
		[string]$groupscope=$null
	)

	# Create a new report file with suffix if number of rows in the report equals maxrows parameter
	if ($script:numrows -eq $maxrows) {
		$script:suffix++
		$script:outfile=$reportfile.Substring(0, $reportfile.lastIndexOf('.'))+"$script:suffix."+$reportfile.substring(($reportfile.Substring(0, $reportfile.lastIndexOf('.')).length)+1)
		test-outfile $outfile
		$script:numrows=0
	}

	$Properties = [ordered]@{'Path Name'=$pathname;'Path Type'=$pathtype;'Owner'=$owner;'Identity'=$identity;'Permissions'=$permissions;'Inherited'=$inherited;'Access Type'=$accesstype;'Identity Type'=$identitytype}
	if ($groupscope) {
		$properties.'Group Scope'=$groupscope
	}
	try {
		New-Object -TypeName PSObject -Property $Properties|Export-Csv -path $outfile -NoTypeInformation -append
		$script:numrows++
	} catch {
		write-output "Unable to write to the report file."
	}
}

# Get permissions for the passed path and identify the identity type of each permission
function get-permission {
	param (
		[string]$path
	)

	[System.Security.AccessControl.FileSystemSecurity]$Acl=$null
	[string]$identitytype=$null
	[string]$identityname=$null
	[boolean]$includes=$false
	[string]$sam=$null
	[string]$acctype=$null
	[string]$localname=$null
	[string]$localcomp=$null
	[string]$localname=$null
	[string]$replacestring=$null

	# Get the ACL.
	try {
		$Acl=Get-Acl -literalpath $path -erroraction stop
	} catch {
		# Test if the path is still valid. If not, it usually means it has been changed/moved/deleted since enumeration so skip it
		if ((test-path -literalpath $path) -and $nopermission) {
			# Path still valid but cannot access it, so log it as NO PERMISSION if reporting on this
			write-reportfile -pathname $path -pathtype $pathtype -identity $curruser -permissions "NONE" -identitytype "NO PERMISSION" -groupscope $groupscope
		}
		continue
	}

	# For each identity with permission, identify the identity type, check if the identity type is selected for reporting and set the $identitytype variable
	foreach ($Access in $acl.Access) {

		# Skip if permission is inherited and not reporting inherited permissions
		if (-not $inherited -and $Access.IsInherited -eq "TRUE") {
			continue
		}

		# Skip ACL if it is Allow and denyonly is selected
		if ($Access.AccessControlType -eq "Allow" -and $denyonly) {
			continue
		# Skip ACL if it is Deny and allowonly is selected
		} elseif ($Access.AccessControlType -eq "Deny" -and $allowonly) {
			continue
		}


		$identitytype=$null
		$identityname=$Access.IdentityReference

		# Check if the identity name is included in the includes patterns
		$includes=$false
		foreach ($includepattern in $includepatterns) {
			if ($identityname -like $includepattern) {
				$Includes=$true
				Break
			}
		}

		# Check if the identity name is included in the excludes patterns. Exclude trumps include.
		foreach ($excludepattern in $excludepatterns) {
			if ($identityname -like $excludepattern) {
				$includes=$false
				break
			}
		}

		# If the ACL identity is either in excludes patterns or not in includes patterns, Skip this ACL
		if (-not $includes) {
			continue
		}

		if ($reportscope) {
			$groupscope="NA"
		} else {
			$groupscope=$null
		}

		# Get identity if domain user/group/machine/MSA/GMSA
		if ($identityname -like "$domain*") {
			$sam=$identityname.replace("$domain\","")
			$acctype=(Get-ADObject -Filter {(SamAccountName -eq $sam)}).objectclass
			if ($acctype -eq "user") {
				if ($domainuser) {
					$identitytype="Domain User"
				}
			} elseif ($acctype -eq "group") {
				if ($domaingroup) {
					$identitytype="Domain Group"
					# Get group scope if reportscope switch is true
					if ($reportscope) {
						$groupscope=(get-adgroup $sam).groupscope
					}
				}
			} elseif ($acctype -eq "computer") {
				if ($domaincomputer) {
					$identitytype="Domain Computer"
				}
			} elseif ($acctype -eq "msDS-GroupManagedServiceAccount") {
				if ($domaingmsa) {
					$identitytype="Domain GMSA"
				}
			} elseif ($acctype -eq "msDS-ManagedServiceAccount") {
				if ($domainmsa) {
					$identitytype="Domain MSA"
				}
			}
		# Get identity if it is a BUILTIN user/group
		} elseif ($identityname -like "BUILTIN*") {
			$localname=$identityname.replace("BUILTIN\","")
			if (get-localuser $localname -ErrorAction SilentlyContinue) {
				if ($builtinuser) {
					$identitytype="BUILTIN User"
				}
			} else {
				if ($builtingroup) {
					$identitytype="BUILTIN Group"
				}
			}
		# Check if identity is a local user/group on the machine the script is running on
		} elseif ($identityname -like "$computer*") {
			$localname=$identityname.replace("$computer\","")
			if (get-localuser $localname -ErrorAction SilentlyContinue) {
				if ($localuser) {
					$identitytype="Local User"
				}
			} else {
				if ($localgroup) {
					$identitytype="Local Group"
				}
			}
		# Check if identity is CREATOR OWNER
		} elseif ($identityname -eq "CREATOR OWNER") {
			if ($creatorowner) {
				$identitytype="CREATOR OWNER"
			}
		# Check if identity is an NT AUTHORITY account
		} elseif ($identityname -like "NT AUTHORITY*") {
			if ($ntauthority) {
				$identitytype="NT AUTHORITY"
			}
		# Check if identity is a local user/group on a different machine - Slow and may fail
		} elseif ($identityname -like "*\*") {
			$localcomp=$identityname.split("\")[0]
			$localname=$identityname.split("\")[1]
			$replacestring=("WinNT://$domain/$localcomp/").tolower()
			$compname=[ADSI]"WinNT://$localcomp"
			# Try get the list of local users from the remote machine
			$ErrorActionPreference = "SilentlyContinue"
			[string[]]$users=@()
			$users = ($compname.psbase.children | where-object {$_.SchemaClassName -match "user"}).path.tolower().replace($rstring,"")
			$ErrorActionPreference = "Continue"
			if ($users.contains($localname.tolower())) {
				if ($localuser) {
					$identitytype="Local User"
				}
			} else {
				# Try get the list of local groups from the remote machine
				$ErrorActionPreference = "SilentlyContinue"
				[string[]]$groups=@()
				$groups = ($compname.psbase.children | where-object {$_.SchemaClassName -match "group"}).path.tolower().replace($rstring,"")
				$ErrorActionPreference = "Continue"
				if ($groups.contains($localname.tolower())) {
					if ($localgroup) {
						$identitytype="Local Group"
					}
				} else {
				# Unable to ascertain whether the identity is a group or user
					if ($localuser -or $localgroup) {
						$identitytype="Local User/Group"
					}
				}
			}
		# Check if the identity is an unresolvable SID
		} elseif ($identityname -like "S-*") {
			if ($sid) {
				$identitytype="Unresolvable SID"
			}
		# Check if the identity is Everyone
		} elseif ($identityname -eq "everyone") {
			if ($everyone) {
				$identitytype="Everyone"
			}
		# Give up, no idea what the identity type is. Always report on this.
		} else {
			$identitytype="Unknown"
		}
		# Type will only have a value if the identity type was identified and is being reported on, or is unknown. If it has a value, write its details to the report
		if ($identitytype) {
			write-reportfile -pathname $path -pathtype $pathtype -owner $acl.owner -identity $Access.IdentityReference -permissions $Access.FileSystemRights -inherited $Access.IsInherited -accesstype $Access.AccessControlType -identitytype $identitytype -groupscope $groupscope
		}
	}
}

# Recurse through each folder and pass each path to the get-permission function. Self recursive function
Function Get-Folder {
	param (
		[string]$parent
	)

	# Path arrays
	[array]$subpaths=@()
	[string]$pathtype=$null
	[string]$groupscope=$null

	# Error path arraylists
	$longpaths=New-Object -TypeName 'System.Collections.ArrayList'
	$noaccesspaths=New-Object -TypeName 'System.Collections.ArrayList'
	$errpaths=New-Object -TypeName 'System.Collections.ArrayList'

	$script:level++

	# Get subfolders and files (if files is selected)
	try {
		if ($files) {
			$subpaths=(get-childitem -literalPath $parent -Force -ErrorVariable Err -ErrorAction SilentlyContinue).fullname
		} else {
			$subpaths=(get-childitem -Directory -literalPath $parent -Force -ErrorVariable Err -ErrorAction SilentlyContinue ).fullname
		}
	} catch {
		return
	}

	if ($err.count -gt 0) {
		foreach ($e in $err) {
			if ($e.exception -like "*Could not find a part of the path *") {
				$null=($longpaths.add($e.targetobject))
			} elseif ($e.exception -like "*Access to the path *") {
				$null=($noaccesspaths.add($e.targetobject))
			} else {
				# Anything that isn't long path or access denied
				$null=($errpaths.add($e.targetobject))
			}
		}
	}

	foreach ($subpath in $subpaths) {
		# If the files switch is specified test if the path is a file. If not, then assume it is a folder.
		$pathtype="Folder"
		if ($files) {
			if ((get-item -literalpath $subpath -force) -is [System.IO.FileInfo]) {
				$pathtype="File"
			}
		}

		$groupscope=$null
		if ($reportscope) {
			$groupscope="NA"
		}

		# Path was too long to report on. Either the OS does not support long paths, or it isn't enabled.
		if ($longpaths.count -gt 0) {
			if ($longpaths.contains($path)) {
				write-reportfile -pathname $path -pathtype $pathtype -identitytype "Path Too Long" -groupscope $groupscope
				continue
			}
		}
		# If reporting on no permission and the path is in the error paths variable, write its details to the report.
		if ($noaccesspaths.count -gt 0 -and $nopermission) {
			if ($noaccesspaths.contains($path)) {
				write-reportfile -pathname $path -pathtype $pathtype -identity $curruser -permissions "NONE" -identitytype "NO PERMISSION" -groupscope $groupscope
				continue
			}
		}

		Get-Permission $subpath

		# If the path type is a folder, call this function again to recurse through it
		if ($pathtype -eq "Folder") {
			if ($script:level -lt $depth) {
				Get-Folder $subpath
				$script:level--
			}
		}
	}
}

#endregion Functions

# ============================================================================
#region Variables
# ============================================================================

# Declare and strongly type all variables

# Get domain, computer and current user names from system variables
[string]$domain=$env:userdomain
[string]$computer=$env:computername
[string]$curruser="$domain\$env:username"

# Long path enabled check
[int32]$buildnumber=$null
[string]$regkey=$null
[string]$regval=$null
[boolean]$lpe=$false

[string]$pathtype="Folder"

# Keep track of number of rows written to report to create new report if maxrows exceeded
[int32]$script:numrows=0
[int32]$script:suffix=0
[string]$script:outfile=$reportfile

# Folder level. Compared to depth parameter to control level of folder recursion
[int32]$script:level=0

#endregion Variables


# ============================================================================
#region Execute
# ============================================================================
Set-StrictMode -version 3.0

# Check if the specified root folder exists.
if (-not (test-path -literalpath $rootfolder)) {
	"The root folder $rootfolder does not exist or is not accessible. Exiting."
	return
}

test-outfile $outfile

# Check if windows version supports long file paths and if it is enabled. Supported in Server 2019 and Windows 10 1607 or later.
$buildnumber=(Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name CurrentBuildnumber).currentbuildnumber
if ($buildnumber -ge 14393) {
	$regkey="HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem"
	$regval="LongPathsEnabled"
	$lpe=$false
	if ((get-itemproperty -path $regkey).PSObject.Properties.Name -contains $regval) {
		if ((get-itemproperty -path $regkey -name $regval).$regval -eq 1) {
			$lpe=$true
		}
	}
	if ($lpe) {
		write-output "Your OS supports longfilepaths (>260 characters) and it is enabled."
	} else {
		write-output "Your OS supports longfilepaths (>260 characters) but it is not enabled."
		write-output "Set HKLM\SYSTEM\CurrentControlSet\Control\FileSystem REG_DWORD LongPathsEnabled = 1 and restart to enable."
	}
} else {
	write-output "Your OS does not support long file paths (>260 characters)."
}

# If no identity types are specified, report on them all
if (($nopermission,$everyone,$sid,$creatorowner,$ntauthority,$localuser,$localgroup,$domainuser,$domaingroup,$domaincomputer,$domaingmsa,$domainmsa,$builtingroup,$builtinuser -eq $false).Count -eq 14) {
	$nopermission=$everyone=$sid=$creatorowner=$ntauthority=$localuser=$localgroup=$domainuser=$domaingroup=$domaincomputer=$domaingmsa=$domainmsa=$builtingroup=$builtinuser=$true
}


Get-Permission $rootfolder
if ($depth -gt 0) {
	Get-Folder $rootfolder
}

#endregion Execute
