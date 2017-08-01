# disable-SMBv1
Script that scans your AD-Computer and checks if SMBv1 is enabled, if it is it attemps to close it

I know that you could actually do this with GPO but I needed to know which computer actually ran SMBv1 and get a good listing and at that point adding the option to enable / disable was easy to implement.

First parameters are 
$computers = Get-ADComputer -Filter {(Enabled -eq $true)}
$outputPath = "C:\temp\output.csv"
$force_SMBv1_disable = $false

$computers => Filter to select the PC in your Active Directory you actually want to check
$outputPath => Sp.cify where you want the csv saved
$force_SMBv1_disable => $true is you want to actually change the set-smbserverconfiguration / RegKey of the selected computer
