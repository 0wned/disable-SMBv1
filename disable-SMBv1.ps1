#$computers = Get-ADComputer -Filter {(Enabled -eq $true)}

#This function takes in the name of a PC and checks it's windows Version
#Returns True is version is above Windows 8 / Server 2008
#Returns False otherwise
function isNewOS($pcname){
    $tmp = (gwmi win32_operatingsystem -ComputerName $pcname).version
    
    #Operating system of window 8 and up or and servers 2012 and up
    switch -Wildcard ($tmp){
        "10*" {return $true} #windows 10 / Server 2016
        "6.3*" {return $true} #Windows 8.1 / Server 2012 R2
        "6.2*" {return $true} #Windows 8 / Server 2012
        default {return $false}
    }
}

#This function takes in the result of check_OS_version, the cim-session and the name of the PC
#If the version is above Windows 8 / Server 2008, it uses the built-in function of powershell Set-SmbServerConfiguration
#Otherwise it create / modify the registry key to disable SMBv1
function disable_SMB1($isNew, $cim, $pcname){
    if ($isNew){
        Set-SmbServerConfiguration -EnableSMB1Protocol $false -CimSession $cim -Force
		Set-SmbServerConfiguration -EnableSMB2Protocol $true -CimSession $cim -Force
    }
    else{
		#Sets RegKey SMBv1 to False
        Invoke-Command -ComputerName $pcname -ScriptBlock {
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" SMB1 -Type DWORD -Value 0 -Force}

		#Sets RegKey SMBv2 to True		
		Invoke-Command -ComputerName $pcname -ScriptBlock {
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" SMB2 -Type DWORD -Value 1 -Force}
		
    }

}

#This function generate an output from the Array that was created
function generate_output(){
#ComputerName, IPAddress, SMBv1, SMBv2, isSMBv1Disabled, Comments
	
}

$computers = Get-ADComputer -Filter {(Name -like "HGPCIT-1002") -or (Name -like "HGPCIT-1001") -or (Name -like "HGPCIT-1003")} select property IPv4Address, Name
$output = @()

foreach ($pc in $computers){

	#Setup the variables that will populate the output
		$ComputerName = $IPAddress = $SMBv1 = $SMBv2 = $isSMBv1Disabled = $Comments = ""

		$ComputerName = $pc.Name
		$IPAddress = $pc.IPv4Address

    #Short ping to make sure I dont get have to wait the full timeout length
    if (Test-Connection -ComputerName $ComputerName -BufferSize 16 -Count 1 -Quiet -ErrorAction SilentlyContinue){		

		$cim = New-CimSession -ComputerName $ComputerName

		#Newer Windows Version (advanced options)
		if isNewOS($ComputerName){
			write-host "[+] " $ComputerName " is a newer OS Version"
			$SMBv1, $SMBv2 = Get-SmbServerConfiguration -CimSession $cim | select EnableSMB1Protocol, EnableSMB2Protocol 
		}
		
		#Older Windows Version (minimal options)
		else{
			write-host "[+] " $ComputerName " is an older OS Version"

			#Try/Catch to make sure it doesnt crash if the regkey doesnt exit and set SMBv1 to true if it doesnt exist	
			#Normaly the keys dont exists.		
			try{
				$SMBv1 = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" SMB1
				$SMBv2 = Get-ItemProperty –Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" SMB2			
			}
			catch{
				$SMBv1 = $SMBv2 = $true
			}
		}

       	if ($SMBv1 -eq $true){
       		Write-Host $ComputerName "SMBv1 is Enabled... Verifying if SMB2 is also enabled..."
            
			if ($SMBv2 -eq $true){
            	Write-Host "SMBv2 is Enabled, Disabling SMBv1..."
  				try {
                	disable_SMB1(isNewOS($ComputerName), $cim)
                        
                    Write-Host -ForegroundColor Green "Successfully disabled SMBv1 on host : " $ComputerName
					$isSMBv1Disabled = $true
               	}
               	catch{
                	Write-Host -ForegroundColor Red "Unable to disable SMBv1 of host : " $ComputerName
					$Comment = "Unable to disable SMBv1"            
				}
            }
      	else{
                write-host "[-] "  $ComputerName "SMB1 is already Disabled"
				$Comment = "SMB1 is already Disabled"
        }
		$tmp = $ComputerName, $IPAddress, $SMBv1, $SMBv2, $isSMBv1Disabled, $Comments
		$output += $tmp
    }
}
