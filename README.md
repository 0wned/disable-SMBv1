# disable-SMBv1

#You need to have WinRM enabled on the remote PC, I did this on our network to enable only a few IP to be able to remotly execute commands and specific users
{% highlight powershell %}
import-module ServerManager
Add-WindowsFeature RSAT-AD-Powershell
import-module activedirectory
{% endhighlight %}

Script that scans your AD-Computer and checks if SMBv1 is enabled, if it is it attemps to close it

I know that you could actually do this with GPO but I needed to know which computer actually ran SMBv1 and get a good listing and at that point adding the option to enable / disable was easy to implement.

First parameters are 

1. $computers = Get-ADComputer -Filter {(Enabled -eq $true)}
  - Filter to select the PC in your Active Directory you actually want to check
2. $outputPath = "C:\temp\output.csv"
  - Specify where you want the csv saved
3. $force_SMBv1_disable = $false
  - $true is you want to actually change the set-smbserverconfiguration / RegKey of the selected computer
