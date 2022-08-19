Anything Filesystem related  
  
Get-Permissions.ps1  
Report on permissions, showing files/folders with specific identity object types.  
Create a CSV file of permissions on each path inside the selected root path.  
Lots of options for reporting on specific identity types or identities that match/don't match patterns.  
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

Protect-Folder.psm1  
A function to create AD groups to apply Modify and Read permissions to secure a folder or multiple folders.  
The groups are created using a naming convention where the groups are named after the folder.    
Can be passed a single folder path, multiple paths or a text file containing paths.  
Will create the paths if they don't already exist and they don't contain illegal characters.  
Will create the required AD groups based on the folder name if the don't already exist. Any illegal characters will be replaced.  
Group names will be shortened if they are longer than 64 characters.  
Permissions will be applied to the path using these groups.  
Can also create a permissions traverse group if you have a terrible file system.