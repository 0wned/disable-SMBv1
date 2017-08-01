#Enter here the filter for the computer(s) you want to modify

#$computers = Get-ADComputer -Filter {(Enabled -eq $true)}

$computers = Get-ADComputer -Filter {(Enabled -eq $true)}
$outputPath = "C:\temp\output.csv"
$force_SMBv1_disable = $false
$output = @()

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
function disable_SMB1($pcname, $isNew){
    $cim = New-CimSession -ComputerName $pcname

    if ($force_SMBv1_disable){ 
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
}

function get_SMBv1_is_enabled($pcname, $isNew){
    $SMB=@{}
    try{
        $cim = New-CimSession -ErrorAction stop -ComputerName $pcname
    }catch{
        return $null
    }

    if ($isNew){
        $tmp = Get-SmbServerConfiguration -ErrorAction Stop -CimSession $cim | select EnableSMB1Protocol,EnableSMB2Protocol
            
        $SMB.Add("EnableSMB1Protocol", $tmp.EnableSMB1Protocol)
        $SMB.Add("EnableSMB2Protocol", $tmp.EnableSMB2Protocol)
    }
    else{
        try{
            $tmp = Invoke-Command -ErrorAction Stop -ComputerName $pcname -ScriptBlock {
            get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" SMB1}
            $SMB.Add("EnableSMB1Protocol", $tmp.SMB1)

            $tmp = Invoke-Command -ErrorAction stop  -ComputerName $pcname -ScriptBlock {
            get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" SMB2}
		    $SMB.Add("EnableSMB2Protocol", $tmp.SMB2)
            
        }
        #Try/Catch to make sure it doesnt crash if the regkey doesnt exit and set SMBv1 to true if it doesnt exist	
	    #Normaly the keys dont exists.
		catch{
            $SMB.Add("EnableSMB1Protocol", $true)
		    $SMB.Add("EnableSMB2Protocol", $true)
        }		
    }
    return $SMB
}

#This function generate an output from the Array that was created
function generate_output($ComputerName, $IPAddress, $SMB, $isSMBv1Disabled, $Comment){
    #Write-Host  $ComputerName "'" $IPAddress "'" $SMB.EnableSMB1Protocol "'" $SMB.EnableSMB2Protocol "'" $isSMBv1Disabled "'" $Comment 
    
    $output = New-Object PsObject -Property @{
        "Computer Name"      = $ComputerName.ToString()
        "IP Address"         = $IPAddress.ToString()
        "SMBv1"              = $SMB.EnableSMB1Protocol.ToString() 
        "SMBv2"              = $SMB.EnableSMB2Protocol.ToString() 
        "was_SMBv1_Disabled" = $isSMBv1Disabled.ToString()
        "Comments"           = $Comment.ToString()
    }
    return $output
}

foreach ($pc in $computers){
	#Setup the variables that will populate the output
	$ComputerName = ""
    $IPAddress = ""
    $isSMBv1Disabled = ""
    $Comment = "None"
    $SMB=@{}

    $ComputerName = $pc.Name
    #Short ping to make sure I dont get have to wait the full timeout length
    if (Test-Connection -ComputerName $ComputerName -BufferSize 16 -Count 1 -Quiet -ErrorAction SilentlyContinue){		
    	
        if (!$pc.IPv4Address -eq $null) {
            $IPAddress = $pc.IPv4Address
        }else {
            $tmp = [System.Net.Dns]::GetHostAddresses($ComputerName)
            if (!$tmp -eq $null){$IPAddress = $tmp}
            else{$IPAddress = "Couldn't retrieve the IP Address"}
        }
	    
        $isNew = isNewOS $ComputerName
        $SMB = get_SMBv1_is_enabled $ComputerName $isNew
        Write-Host -ForegroundColor Yellow "[+]" $ComputerName "OS Version is new :" $isNew

        if ($SMB -eq $null){
            write-host -foregroundcolor Red "    Error Retrieving information from $ComputerName Probably WinRM isn't enabled"
            continue
        }

       	if ($SMB.EnableSMB1Protocol -eq $true){
       		Write-Host "   "$ComputerName "SMBv1 is Enabled... Verifying if SMB2 is also enabled..."
            
			if ($SMB.EnableSMB2Protocol -eq $true){
            	Write-Host "    SMBv2 is Enabled, Disabling SMBv1..."
  				try {
                	disable_SMB1 $ComputerName $isNew
                    if(!$force_SMBv1_disable){
                        Write-Host -ForegroundColor Green "    Didnt enforce to disable SMBv1 on host : " $ComputerName
                    }else{
                        Write-Host -ForegroundColor Green "    Successfully disabled SMBv1 on host : " $ComputerName
					}
                    $isSMBv1Disabled = $true
               	}
               	catch{
                    Write-Host $_.Exception.Message
                	Write-Host -ForegroundColor Red "    Unable to disable SMBv1 of host : " $ComputerName
					$Comment = "Unable to disable SMBv1"            
				}
            }else{
                $isSMBv1Disabled = $true
                $Comment = $ComputerName + " Has SMBv1 Enabled but not SMBv2"
            }
        }
        else{
            write-host -ForegroundColor Green "[-]"$ComputerName "SMB1 is already Disabled"
            $isSMBv1Disabled = $true
		    $Comment = "SMB1 is already Disabled"
        }

        $output += generate_output $ComputerName $IPAddress $SMB $isSMBv1Disabled $Comment
        
    }
}

$output | export-csv
