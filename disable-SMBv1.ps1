#$computers = Get-ADComputer -Filter {(Enabled -eq $true)}

function check_OS_version($pcname)
{
    $tmp = (gwmi win32_operatingsystem -ComputerName $pcname).version
    
    #Operating system of window 8 and up or and servers 2012 and up
    switch -Wildcard ($tmp)
    {
        "10*" {return $true} #windows 10 / Server 2016
        "6.3*" {return $true} #Windows 8.1 / Server 2012 R2
        "6.2*" {return $true} #Windows 8 / Server 2012
        default {return $false}
    }
}

function disable_SMB1($isNew, $cim, $pcname)
{
    if ($isNew)
    {
        Set-SmbServerConfiguration -EnableSMB1Protocol $false -CimSession $cim
    }
    #If Version requires Regkey modifications
    else
    {
        Invoke-Command -ComputerName $pcname -ScriptBlock 
        {
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" SMB1 -Type DWORD -Value 0 -Force
        }
    }

}


$computers = Get-ADComputer -Filter {(Name -like "HGPCIT-1002") -or (Name -like "HGPCIT-1001") -or (Name -like "HGPCIT-1003")}
foreach ($pc in $computers){

    #Short ping to make sure I dont get have to wait the full timeout length
    if (Test-Connection -ComputerName $pc.Name -BufferSize 16 -Count 1 -Quiet -ErrorAction SilentlyContinue)
    {
        $cim = New-CimSession -ComputerName $pc.name
        $serverconfiguration = Get-SmbServerConfiguration -CimSession $cim |select EnableSMB1Protocol, EnableSMB2Protocol 

        foreach($config in $serverconfiguration)
        {
            if ($config.EnableSMB1Protocol -eq $true)
            {
                Write-Host -ForegroundColor red  "[+] " $pc.name "SMBv1 is Enabled... Verifying if SMB2 is also enabled..."
                if ($config.EnableSMB2Protocol -eq $true)
                {
                    Write-Host "     SMBv2 is Enabled, Disabling SMBv1..."
                    try
                    {
                        disable_SMB1(check_OS_version($pc.name), $cim)
                        
                        Write-Host -ForegroundColor Green "     Successfully disabled SMBv1 on host : " $pc.Name
                    }
                    catch
                    {
                        Write-Host "Unable to disable SMBv1 of host : " $pc.Name
                    }
                }
            }
            else 
            {
                write-host "[-] "  $pc.name "SMB1 is Disabled"
            }
        }
    }
}
