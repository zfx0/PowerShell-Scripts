param (
    [Parameter(Mandatory=$false)][string]$Localhost = $ENV:COMPUTERNAME,
    [Parameter(Mandatory=$false)][string]$LogPath = "C:\Patching\Logs\Stop-ExchangePatching_$(Get-Date -Format 'yyyy-MM-dd').log"
)

#region Functions
function Start-Log {
    [CmdletBinding()]
    param (
	    [string]$FilePath
    )
    try {
        if(-Not(Test-Path $FilePath)) {
	        New-Item $FilePath -Type File -Force | Out-Null
	    }
        $global:ScriptLogFilePath = $FilePath
    } catch {
        Write-Error $_.Exception.Message
    }
}

function Write-Log {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Message,
        [Parameter(Mandatory = $false)]
        [ValidateSet(1, 2, 3)]
        [int]$LogLevel = 1
    )
    $TimeGenerated = "$(Get-Date -Format HH:mm:ss).$((Get-Date).Millisecond)+000"
    $Line = '<![LOG[{0}]LOG]!><time="{1}" date="{2}" component="{3}" context="" type="{4}" thread="" file="">'
    $LineFormat = $Message, $TimeGenerated, (Get-Date -Format MM-dd-yyyy), "$($MyInvocation.ScriptName | Split-Path -Leaf):$($MyInvocation.ScriptLineNumber)", $LogLevel
    $Line = $Line -f $LineFormat
    if($LogLevel -eq 1) {
        Write-Host $Message -ForegroundColor Green
    } elseif($LogLevel -eq 2) {
        Write-Host $Message -ForegroundColor Yellow
    } elseif($LogLevel -eq 3) {
        Write-Host $Message -ForegroundColor Red
    }
    Add-Content -Value $Line -Path $ScriptLogFilePath
}

# Load the Exchange snapin if it's no already present.
function LoadExchangeSnapin {
    if (!(Get-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn -ErrorAction:SilentlyContinue)) {
        Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn -ErrorAction:Stop
    }
}

# Check whether all component states are Active except for ForwardSyncDaemon & ProvisioningRps
function Test-PostMaintenanceComponentState {
    try {
        Write-Log -Message "Checking ServerComponent states to ensure they are all Active except for ForwardSyncDaemon and ProvisioningRps."
        $RetVal = 0
        $State = Get-ServerComponentState $ENV:COMPUTERNAME | Select-Object Component,State
        $State | ForEach-Object {
            if($_.State -eq "Inactive") {
                $RetVal++
                if(-Not($_.Component -eq "ForwardSyncDaemon") -and -Not($_.Component -eq "ProvisioningRps")) {
                    $RetVal = 0
                    Write-Error "$($_.Component) should be in an Inactive state but it is currently Active."
                }
            }
        }
        return ($RetVal -eq 2)
    } catch {
        Write-Log -Message "Failed to check the ServerComponentState." -LogLevel 3
        Write-Log -Message "$($_.Exception.Message)." -LogLevel 3
        return $false
    }
}

function Test-PostMaintenace {
    $ComponentStatus = Test-PostMaintenanceComponentState
    return ($ComponentStatus)
}
#endregion

# Configure the server as out of maintenance mode and ready to accept client connections
try {
    Write-Log -Message "Taking server out of maintenance mode."
    Set-ServerComponentState $Localhost -Component ServerWideOffline -State Active -Requester Maintenance
} catch {
    Write-Log -Message "Failed to set the ServerWideOffline component to Active." -LogLevel 3
    Write-Log -Message "$($_.Exception.Message)." -LogLevel 3
}

# Allow serve to accept Unified Messaging calls
try {
    Write-Log "Setting server to accept Unified Messaging calls."
    Set-ServerComponentState $Localhost -Component UMCallRouter -State Active -Requester Maintenance
} catch {
    Write-Log -Message "Failed to set the UMCallRouter component to Active." -LogLevel 3
    Write-Log -Message "$($_.Exception.Message)." -LogLevel 3
}

# Run the StopDagServerMaintenance script
try {
    Write-Log "Running the StopDagServerMaintenance.ps1 script."
    # Set location to the $ExScripts directory
    Set-Location $ExScripts

    # Call the StopDagServerMaintenance script
    .\StopDagServerMaintenance.ps1 -serverName $Localhost
} catch {
    Write-Log -Message "There was an issue when running the StopDagServerMaintenance.ps1 script." -LogLevel 3
    Write-Log -Message "$($_.Exception.Message)." -LogLevel 3
}

# Enable transport queues
try {
    Write-Log -Message "Enabling transport queues."
    Set-ServerComponentState $Localhost -Component HubTransport -State Active -Requester Maintenance
} catch {
    Write-Log -Message "Failed to set the HubTransport component to Active." -LogLevel 3
    Write-Log -Message "$($_.Exception.Message)." -LogLevel 3
}


# Restart MSExchangeTransport service to resume transport activity
try {
    Write-Log -Message "Restarting the MSExchangeTransport service."
    Restart-Service MSExchangeTransport
} catch {
    Write-Log -Message "Failed to restart the MSExchangeTransport service." -LogLevel 3
    Write-Log -Message "$($_.Exception.Message)." -LogLevel 3
}

# Run Test-PostMaintenance function to ensure the server is ready for production use
if(-Not(Test-PostMaintenace)) {
    Write-Log "The post-maintenance checks failed, please ensure the required component states are active." -LogLevel 3
}