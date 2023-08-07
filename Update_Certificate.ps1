#*****************************************************************
#	Version: 1.0.0
#   1) Updates encryption certificate 'alwayEncr_cert'
#   2) Add certificate private keys for IIS App Pools
#
#	USAGE: 
#       - Put this file into "_GIT" folder 
#
#   NOTE:
#       - only works with admin privileges
#
#*****************************************************************
# HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\SystemCertificates\MY\Certificates
#
#

Import-Module Webadministration -erroraction 'silentlycontinue'

$CERTIFICATE_NAME = "alwayEncr_cert.pfx"
$CERTIFICATE_SUBJECT = "CN=Always Encrypted Auto Certificate1"

Function Write-Phase(){
    param(
        [string]$message
    );

    Write-host "*** ${message} ***" -ForegroundColor Green
}

Function Restart-AsAdministrator(){

    Write-Phase "Checking privileges"

    $currentUser = New-Object Security.Principal.WindowsPrincipal $([Security.Principal.WindowsIdentity]::GetCurrent())
    
    if($currentUser.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)){
        return
    }
    
    try{

        Write-Warning "Restarting script with Administrator privileges"
        
        $currentProcess = [System.Diagnostics.Process]::GetCurrentProcess()
        $newProcess = New-Object System.Diagnostics.ProcessStartInfo $currentProcess.Path;
        $newProcess.Arguments = "-file " + $script:MyInvocation.MyCommand.Path
        $newProcess.Verb = "runas"

        [System.Diagnostics.Process]::Start($newProcess)
    }
    catch{

        Write-host "Error " $MyInvocation.MyCommand.Name -ForegroundColor Red
        Write-Host ([Environment]::NewLine)
        Write-Host "$($_.Exception)" -ForegroundColor Red

        Pause
    }
    finally{
        Exit
    }
}

Function Add-PrivateKeys(){
    param(
        [string]$appPoolName,
        [string]$certificateKeyPath
    )
    
    Write-Host "Adding Private Key permissions for ${appPoolName}"
        
    try{
        $permissions = Get-Acl -Path $certificateKeyPath
    
        $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("IIS AppPool\$appPoolName", 'FullControl', 'Allow')
        $permissions.AddAccessRule($accessRule)
        Set-Acl -Path $certificateKeyPath -AclObject $permissions
    }
    catch{

        Write-host "Error " $MyInvocation.MyCommand.Name -ForegroundColor Red
        Write-Host ([Environment]::NewLine)
        Write-Host "$($_.Exception)" -ForegroundColor Red
    } 
}

Function Get-CertificateKeyPath(){
    param([string]$certificateThumbprint)

    Write-Phase "Retrieving certificate path"

    try {

        $certificateStoreLocation  = "Cert:\LocalMachine\My"
        $certificate = Get-ChildItem $certificateStoreLocation | Where-Object thumbprint -eq $certificateThumbprint
        
        if ($null -eq $certificate){
            
            $errorMessage = "Certificate with thumbprint: ${certificateThumbprint} does not exist at ${certificateStoreLocation}"
            Write-Host $errorMessage -ForegroundColor Red
            
            Pause
            Exit
        }
    
        $rsaCertificate = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($certificate)
        $rsaKeyName = $rsaCertificate.key.UniqueName

        return "${env:ALLUSERSPROFILE}\Microsoft\Crypto\RSA\MachineKeys\${rsaKeyName}"
    }
    catch {
        Write-host "Error " $MyInvocation.MyCommand.Name -ForegroundColor Red
        Write-Host ([Environment]::NewLine)
        Write-Host "$($_.Exception)" -ForegroundColor Red
    }
}

Function Get-AppPoolNameList(){

    Write-Phase "Retrieving used AppPools"

    try {
        $appPoolNameList = Get-ChildItem -Path IIS:\Sites | ForEach-Object {$_.applicationPool}

        return $appPoolNameList
    }
    catch {
        Write-host "Error " $MyInvocation.MyCommand.Name -ForegroundColor Red
        Write-Host ([Environment]::NewLine)
        Write-Host "$($_.Exception)" -ForegroundColor Red

        Pause
        Exit
    }
}

Function Import-Certificate(){

    Write-Phase "Importing certificate"

    try {
        
        $drive = Split-Path (Get-Location) -qualifier
        $filePath = "$drive\_GIT\psol-core-database\PSolCoreDatabase\Security\${CERTIFICATE_NAME}"
        
        $certPassword = "Password"
        $password = ConvertTo-SecureString $certPassword -AsPlainText -Force
        $certCredentials = New-Object System.Management.Automation.PSCredential ("username", $password)
        $certificateStoreLocation = 'Cert:\LocalMachine\My'

        $certParams = @{
            FilePath = $filePath
            CertStoreLocation = $certificateStoreLocation
            Password = $certCredentials.Password
        }
        
        Import-PfxCertificate @certParams
    }
    catch {
        Write-host "Error " $MyInvocation.MyCommand.Name -ForegroundColor Red
        Write-Host ([Environment]::NewLine)
        Write-Host "$($_.Exception)" -ForegroundColor Red

        Pause
        Exit
    }
}

#****************************************************
#****************************************************
#****************************************************

Function main(){
    
    Clear-Host

    try{
        
        Restart-AsAdministrator
        
        Import-Certificate

        $certificateThumbprint = Get-ChildItem "Cert:\LocalMachine\My" | Where-Object {$_.Subject -Match $CERTIFICATE_SUBJECT} | Select-Object Thumbprint
        $certificateKeyPath = Get-CertificateKeyPath -certificateThumbprint $certificateThumbprint.Thumbprint

        foreach($appPoolName in Get-AppPoolNameList){
        
            Add-PrivateKeys -appPoolName $appPoolName -certificateKeyPath $certificateKeyPath
        }
        
        Write-Phase "Update ended"
    }
    catch{
        Write-Host "$($_.Exception)" -ForegroundColor Red
        Write-Host ([Environment]::NewLine)
        Write-Host "*** Update failed ***" -ForegroundColor Red
    }

    Pause
}

main