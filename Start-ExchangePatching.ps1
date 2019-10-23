param (
    [Parameter(Mandatory=$false)][string]$Localhost = $ENV:COMPUTERNAME,
    [Parameter(Mandatory=$true)][string]$Target,
    [Parameter(Mandatory=$false)][string]$LogPath = "C:\Patching\Logs\Stop-ExchangePatching_$(Get-Date -Format 'yyyy-MM-dd').log"
)
$LogPath = "C:\Patching\Logs\Start-ExchangePatching_$(Get-Date -Format 'yyyy-MM-dd').log"

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

# Check whether both the Monitoring and RecoveryActionsEnabled component states are both Inactive
function Test-PreMaintenanceComponentState {
    try {
        Write-Log -Message "Checking ServerComponent states to ensure they are all Inactive except for Monitoring and RecoveryActionsEnabled."
        $RetVal = 0
        $State = Get-ServerComponentState $ENV:COMPUTERNAME | Select-Object Component,State
        $State | ForEach-Object {
            if($_.State -eq "Active") {
                $RetVal++
                if(-Not($_.Component -eq "Monitoring") -and -Not($_.Component -eq "RecoveryActionsEnabled")) {
                    $RetVal = 0
                    Write-Log -Message "$($_.Component) should be in an Inactive state but it is currently Active." -LogLevel 3
                }
            }
        }
        return ($RetVal -eq 2)
    } catch {
        Write-Log -Message "Failed to check the ServerComponentState." -LogLevel 3
        Write-Log -Message "$($_.Exception.Message)." -LogLevel 3
        return ($false)
    }
}

# Check to ensure the DatabaseCopyAutoActivationPolicy is set to Blocked
function Test-DatabaseCopyAutoActivationPolicy {
    try {
        Write-Log -Message "Checking DatabaseCopyAutoActivationPolicy to ensure it is Blocked."
        $Policy = Get-MailboxServer $ENV:COMPUTERNAME | Select-Object DatabaseCopyAutoActivationPolicy
        return ($Policy.Unstricted -eq "Blocked")
    } catch {
        Write-Log -Message "Failed to check DatabaseCopyAutoActivationPolicy." -LogLevel 3
        Write-Log -Message "$($_.Exception.Message)." -LogLevel 3
        return ($false)
    }
}

# Check to ensure the State of the local node and ensure it is set to Paused
function Test-ClusterNode {
    try {
        Write-Log -Message "Checking if ClusterNode state is set to Paused."
        $ClusterNode = Get-ClusterNode | Where-Object { $_.Name -eq $Localhost }
        Write-Log -Message "ClusterNode state: $($ClusterNode.State)"
        return ($ClusterNode.State -eq "Paused")
    } catch {
        Write-Log -Message "Failed to check the cluster node state." -LogLevel 3
        Write-Log -Message "$($_.Exception.Message)." -LogLevel 3
        return ($false)
    }
}

# Check to ensure that all transport queues have been drained
function Test-TransportQueue {
    try {
        Write-Log -Message "Checking to ensure all transport queues are empty."
        $RetVal = 0
        $Queues = Get-Queue
        $Queues | ForEach-Object {
            if($_.MessageCount -gt 0) {
                $RetVal++
            }
        }
        if($RetVal -eq 0) {
            Write-Log -Message "All transport queues are empty."
        } else {
            Write-Log -Message "1 or more transport queues are not empty."
        }
        return ($RetVal -eq 0)
    } catch {
        Write-Log -Message "Failed to check the transport queues." -LogLevel 3
        Write-Log -Message "$($_.Exception.Message)." -LogLevel 3
        return ($false)
    }
}

# Run all pre-requisite checks to ensure the server is ready for maintenance
function Test-PreMaintenance {
    $RetVal = $true
    if(-Not(Test-PreMaintenanceComponentState)) {
        Write-Log -Message "Failed PreMaintenanceComponentState check." -LogLevel 2
        $RetVal = $false
    }
    if(-Not(Test-DatabaseCopyAutoActivationPolicy)) {
        Write-Log -Message "Failed DatabaseCopyAutoActivationPolicy check." -LogLevel 2
        $RetVal = $false
    }
    if(-Not(Test-ClusterNode)) {
        Write-Log -Message "Failed ClusterNode check." -LogLevel 2
        $RetVal = $false
    }
    if(-Not(Test-TransportQueue)) {
        Write-Log -Message "Failed TransportQueue check." -LogLevel 2
        $RetVal = $false
    }
    return $RetVal
}

#endregion

Start-Log $LogPath

LoadExchangeSnapin

# Drain the HubTransport component
try {
    Write-Log -Message "Draining the transport queue."
    Set-ServerComponentState $Localhost -Component HubTransport -State Draining -Requester Maintenance
} catch {
    Write-Log -Message "Failed to set the HubTransport component to Draining." -LogLevel 3
    Write-Log -Message "$($_.Exception.Message)." -LogLevel 3
}


# Restart the MSExchangeTransport to initiate draining of the transport queues
try {
    Write-Log "Restarting the MSExchangeTransport service."
    Restart-Service MSExchangeTransport
} catch {
    Write-Log -Message "Failed to restart the MSExchangeTransport service." -LogLevel 3
    Write-Log -Message "$($_.Exception.Message)." -LogLevel 3
}

# Drain all Unified Messaging calls
try {
    Write-Log -Message "Draining all Unified Messaging calls."
    Set-ServerComponentState $Localhost -Component UMCallRouter -State Draining -Requester Maintenance
} catch {
    Write-Log -Message "Failed to set the UMCallRouter component to Draining." -LogLevel 3
    Write-Log -Message "$($_.Exception.Message)." -LogLevel 3
}

# Run the StartDagServerMaintenance script
try {
    Write-Log "Running the StartDagServerMaintenance.ps1 script."
    # Set location to the $ExScripts directory
    Set-Location $ExScripts
    # Call the StartDagServerMaintenance script
    .\StartDagServerMaintenance.ps1 -ServerName $Localhost -MoveComment "Maintenance"
} catch {
    Write-Log -Message "There was an issue when running the StartDagServerMaintenance.ps1 script." -LogLevel 3
    Write-Log -Message "$($_.Exception.Message)." -LogLevel 3
}

# Redirect messages pending delivery in local queues
try {
    Write-Log "Redirecting messages in pending delivery queue from $($Localhost) to $($Target)"
    Redirect-Message -Server $Localhost -Target $Target
} catch {
    Write-Log -Message "Failed to check the transport queues." -LogLevel 3
    Write-Log -Message "$($_.Exception.Message)." -LogLevel 3
}

# Place server into maintenance mode
try {
    Write-Log "Placing the server into maintenance mode."
    Set-ServerComponentState $Localhost -Component ServerWideOffline -State Inactive -Requester Maintenance
} catch {
    Write-Log -Message "Failed to set the ServerWideOffline component to Inactive." -LogLevel 3
    Write-Log -Message "$($_.Exception.Message)." -LogLevel 3
}

# Run Test-PreMaintenance function to ensure the server is ready for maintenance
if(-Not(Test-PreMaintenance)) {
    Write-Error "The pre-maintenance checks failed, server is not ready to be patched."
}