#Requires -Version 5
#Requires -Modules ActiveDirectory
#Requires -RunAsAdministrator
<#
    .SYNOPSIS
	Report on permissions, showing files/folders with specific identity object types
    .DESCRIPTION
	Create a CSV file of permissions on each path inside the selected root path.
		Import into Excel and filter to see how good/bad your permissions are!
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
    .PARAMETER denyonly
	Switch. Only report on deny permissions. Skip reporting allow ACLs.
    .PARAMETER reportscope
	Switch. Report scope of domain groups. Report may take a bit longer to run as it queries AD for each domain group.
    .PARAMETER logerrors
	Switch. Writes some error logging for development troubleshooting.

    .INPUTS

    .OUTPUTS

    .NOTES
	Scott Knights
	V 1.20220316.1
		Initial Release
	V 1.20220318.1
		Added #Requires -RunAsAdministrator
		Fixed No access ACLs not being reported due to issue with groupscope

	TODO:
		Add a GUI front end?
    .EXAMPLE
	get-permissions -rootpath "d:\data"
	Report all identity types and all indentities for d:\data and subfolders to default report file ".\FolderPermissions.csv"

    .EXAMPLE
	get-permissions -rootpath "d:\data" -reportfile ".\myreport.csv" -overwritereportfile -files -reportscope
	Report all identity types and all indentities for d:\data, subfolders and files to report file ".\myreport.csv"
	Overwrite the report file if it already exists.
	Report group scope for domain groups

    .EXAMPLE
	get-permissions -rootpath "d:\data" -domainuser -sid -denyonly -excludepatterns "*sam*","*max*"
	Report deny permissions for identity types domain users and unresolved SIDs for d:\data and subfolders
	Dont report on any identities containing "sam" or "max" in their samaccountnames.

    .EXAMPLE
	get-permissions -rootpath "d:\data" -domaingroup -includepatterns "*FL-*" -allowonly
	Report allow permissions for domain groups with "FL-" in their name for d:\data and subfolders
#>

# ============================================================================
#region Parameters
# ============================================================================
Param(
    [Parameter(Mandatory=$true,Position=0)]
    [String] $rootfolder,

    [Parameter()]
    [String] $reportfile=".\FolderPermissions.csv",

    [Parameter()]
    [String[]] $includepatterns="*",

    [Parameter()]
    [String[]] $excludepatterns,

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
    [switch]$logerrors,

    [Parameter()]
    [switch]$allowonly,

    [Parameter()]
    [switch]$denyonly,

    [Parameter()]
    [switch]$reportscope

)
#endregion Parameters

# ============================================================================
#region Functions
# ============================================================================
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

	$Properties = [ordered]@{'Path Name'=$pathname;'Path Type'=$pathtype;'Owner'=$owner;'Identity'=$identity;'Permissions'=$permissions;'Inherited'=$inherited;'Access Type'=$accesstype;'Identity Type'=$identitytype}
	if ($groupscope) {
		$properties.'Group Scope'=$groupscope
	}
	New-Object -TypeName PSObject -Property $Properties|Export-Csv -path $reportfile -NoTypeInformation -append
}
#endregion Functions

# ============================================================================
#region Execute
# ============================================================================
Set-StrictMode -version 3.0

# Check if the specified root folder exists.
if (-not (test-path -literalpath $rootfolder)) {
	"The root folder $rootfolder does not exist or is not accessible. Exiting."
	return
}

# Check if the report file already exists. Delete it if $overwritereportfile is selected.
if (test-path $reportfile) {
	if ($overwritereportfile) {
		remove-item -literalpath $reportfile -force
	} else {
		"The report file $reportfile already exists. Move or rename. Exiting."
		return
	}
}

# Check if windows version supports long file paths and if it is enabled. Supported in Server 2019 and Windows 10 1607 or later.
[int]$buildnumber=(Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name CurrentBuildnumber).currentbuildnumber
if ($buildnumber -ge 14393) {
	[string]$regkey="HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem"
	[string]$regval="LongPathsEnabled"
	[boolean]$lpe=$false
	if ((get-itemproperty -path $regkey).PSObject.Properties.Name -contains $regval) {
		if ((get-itemproperty -path $regkey -name $regval).$regval -eq 1) {
			[boolean]$lpe=$true
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

# Get domain, computer and current user names from system variables
[string]$domain=$env:userdomain
[string]$computer=$env:computername
[string]$curruser="$domain\$env:username"

# If no identity types are specified, report on them all
if (($nopermission,$everyone,$sid,$creatorowner,$ntauthority,$localuser,$localgroup,$domainuser,$domaingroup,$domaincomputer,$domaingmsa,$domainmsa,$builtingroup,$builtinuser -eq $false).Count -eq 14) {
	$nopermission=$everyone=$sid=$creatorowner=$ntauthority=$localuser=$localgroup=$domainuser=$domaingroup=$domaincomputer=$domaingmsa=$domainmsa=$builtingroup=$builtinuser=$true
}

# Init progress bar
[nullable[double]]$secondsRemaining = $null
[int32]$counter=0
[DateTime]$start=get-date
[TimeSpan]$secondsElapsed = (Get-Date) - $start

[int32]$percentComplete=0
[Hashtable]$progressParameters = @{
       	Activity = "Enumerating paths."
        Status = "Please wait..."
        CurrentOperation = ""
}
Write-Progress @progressParameters

[array]$paths=$rootfolder
[array]$subpaths=@()
# Get subfolders and files (if files is selected)
if ($files) {
	$subpaths=(get-childitem -literalPath $rootfolder -Recurse -Force -ErrorVariable Err -ErrorAction SilentlyContinue).fullname
} else {
	$subpaths=(get-childitem -Directory -literalPath $rootfolder -Recurse -Force -ErrorVariable Err -ErrorAction SilentlyContinue ).fullname
}

# If there are any errors, create variables containing the error paths. Currently assumes all are access is denied or path too long.
[string[]]$longpaths=@()
[string[]]$noaccesspaths=@()
[string[]]$errpaths=@()
if ($err.count -gt 0) {
	foreach ($e in $err) {
		if ($e.exception -like "*Could not find a part of the path *") {
			$longpaths+=$e.targetobject
		} elseif ($e.exception -like "*Access to the path *") {
			$noaccesspaths+=$e.targetobject
		} else {
			# Anything that isn't long path or access denied
			$errpaths+=$e.targetobject
		}
	}
	# Dump errorvariable and path variables to text files if extra logging is enabled
	if ($logerrors) {
		[string]$err|set-content -path ".\errorfile.txt" -force
		$errpaths|set-content -path ".\errpaths.txt" -force
		$longpaths|set-content -path ".\longpaths.txt" -force
		$noaccesspaths|set-content -path ".\noaccesspaths.txt" -force
	}
}

# If there are subfolders/files add them to the paths array. Count the number of paths.
if ($subpaths.count -gt 0) {
	$paths+=$subpaths
}
[int32]$numobj=$paths.count

# Process each path and get its permissions
Foreach ($path in $paths) {

	# Show Progress bar
	$counter++
	$secondsElapsed = (Get-Date)-$start
	$secondsRemaining = ($secondsElapsed.TotalSeconds / $counter) * ($numobj - $counter)
	$percentComplete=($counter / $numobj) * 100
	$progressParameters = @{
        	Activity = "Progress: $counter of $numobj $($secondsElapsed.ToString('hh\:mm\:ss'))"
	        Status = "Getting permissions"
	        CurrentOperation = "Getting permissions for "+$path
	        PercentComplete = $percentComplete
	}
	if ($secondsRemaining) {
        	$progressParameters.SecondsRemaining = $secondsRemaining
	}
	Write-Progress @progressParameters

	# If files specified test if path is a file. If not, then assume it is a folder.
	[string]$pathtype="Folder"
	if ($files) {
		if ((get-item -literalpath $path -force) -is [System.IO.FileInfo]) {
			$pathtype="File"
		}
	}

	[string]$groupscope=$null
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

	# Get the ACL. Hmmm. doesn't work with paths with square brackets.
	#[System.Security.AccessControl.FileSystemSecurity]$Acl = Get-Acl -Path $path
	# Alternate method of getting ACL that resolves square bracket problem
	[System.Security.AccessControl.FileSystemSecurity]$acl=(Get-Item -force -literalpath $path).GetAccessControl()

	# For each identity with permission, identify the identity type, check if the identity type is selected for reporting and set the $type variable
	foreach ($Access in $acl.Access) {
		# Skip ACL if it is Allow and denyonly is selected
		if ($Access.AccessControlType -eq "Allow" -and $denyonly) {
			continue
		# Skip ACL if it is Deny and allowonly is selected
		} elseif ($Access.AccessControlType -eq "Deny" -and $allowonly) {
			continue
		}


		[string]$type=$null
		[string]$identityname=$Access.IdentityReference

		# Check if the identity name is included in the includes patterns
		[boolean]$includes=$false
		foreach ($includepattern in $includepatterns) {
			if ($identityname -like $includepattern) {
				$Includes=$true
				Break
			}
		}

		# Check if the identity name is included in the excludes patterns
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

		# Get identity if domain user/group/machine/MSA/GMSA
		if ($identityname -like "$domain*") {
			[string]$sam=$identityname.replace("$domain\","")
			[string]$acctype=(Get-ADObject -Filter {(SamAccountName -eq $sam)}).objectclass
			if ($acctype -eq "user") {
				if ($domainuser) {
					$type="Domain User"
				}
			} elseif ($acctype -eq "group") {
				if ($domaingroup) {
					$type="Domain Group"
					# Get group scope if reportscope switch is true
					if ($reportscope) {
						$groupscope=(get-adgroup $sam).groupscope
					}
				}
			} elseif ($acctype -eq "computer") {
				if ($domaincomputer) {
					$type="Domain Computer"
				}
			} elseif ($acctype -eq "msDS-GroupManagedServiceAccount") {
				if ($domaincomputer) {
					$type="Domain GMSA"
				}
			} elseif ($acctype -eq "msDS-ManagedServiceAccount") {
				if ($domaincomputer) {
					$type="Domain MSA"
				}
			}
		# Get identity if it is a BUILTIN user/group
		} elseif ($identityname -like "BUILTIN*") {
			[string]$localname=$identityname.replace("BUILTIN\","")
			if (get-localuser $localname -ErrorAction SilentlyContinue) {
				if ($builtinuser) {
					$type="BUILTIN User"
				}
			} else {
				if ($builtingroup) {
					$type="BUILTIN Group"
				}
			}
		# Check if identity if a local user/group on the machine the script is running on
		} elseif ($identityname -like "$computer*") {
			[string]$localname=$identityname.replace("$computer\","")
			if (get-localuser $localname -ErrorAction SilentlyContinue) {
				if ($localuser) {
					$type="Local User"
				}
			} else {
				if ($localgroup) {
					$type="Local Group"
				}
			}
		# Check if identity is CREATOR OWNER
		} elseif ($identityname -eq "CREATOR OWNER") {
			if ($creatorowner) {
				$type="CREATOR OWNER"
			}
		# Check if identity is an NT AUTHORITY account
		} elseif ($identityname -like "NT AUTHORITY*") {
			if ($ntauthority) {
				$type="NT AUTHORITY"
			}
		# Check if identity is a local user/group on a different machine - Slow and may fail
		} elseif ($identityname -like "*\*") {
			[string]$localcomp=$identityname.split("\")[0]
			[string]$localname=$identityname.split("\")[1]
			[string]$rstring=("WinNT://$domain/$localcomp/").tolower()
			[ADSI]$compname = "WinNT://$localcomp"
			# Try get the list of local users from the remote machine
			$ErrorActionPreference = "SilentlyContinue"
			[string[]]$users=@()
			$users = ($compname.psbase.children | where-object {$_.SchemaClassName -match "user"}).path.tolower().replace($rstring,"")
			$ErrorActionPreference = "Continue"
			if ($users.contains($localname.tolower())) {
				if ($localuser) {
					$type="Local User"
				}
			} else {
				# Try get the list of local groups from the remote machine
				$ErrorActionPreference = "SilentlyContinue"
				[string[]]$groups=@()
				$groups = ($compname.psbase.children | where-object {$_.SchemaClassName -match "group"}).path.tolower().replace($rstring,"")
				$ErrorActionPreference = "Continue"
				if ($groups.contains($localname.tolower())) {
					if ($localgroup) {
						$type="Local Group"
					}
				} else {
				# Unable to ascertain whether the identity is a group or user
					if ($localuser -or $localgroup) {
						$type="Local User/Group"
					}
				}
			}
		# Check if the identity is an unresolvable SID
		} elseif ($identityname -like "S-*") {
			if ($sid) {
				$type="Unresolvable SID"
			}
		# Check if the identity is Everyone
		} elseif ($identityname -eq "everyone") {
			if ($everyone) {
				$type="Everyone"
			}
		# Give up, no idea what the identity type is. Always report on this.
		} else {
			$type="Unknown"
		}
		# Type will only have a value if the identity type was identified and is being reported on, or is unknown. If it has a value, write its details to the report
		if ($type) {
			write-reportfile -pathname $path -pathtype $pathtype -owner $acl.owner -identity $Access.IdentityReference -permissions $Access.FileSystemRights -inherited $Access.IsInherited -accesstype $Access.AccessControlType -identitytype $type -groupscope $groupscope
		}
	}
}

#endregion Execute
