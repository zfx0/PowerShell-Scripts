. .\Convert-WindowsImage.ps1
# Prepare all the variables in advance (optional)
$ConvertWindowsImageParam = @{
    SourcePath          = "C:\Hyper-V\ISO\17763.379.190312-0539.rs5_release_svc_refresh_SERVER_EVAL_x64FRE_en-us.iso"
    VHDPath             = "C:\Hyper-V\Virtual Hard Disks\WSUS.vhdx"
    RemoteDesktopEnable = $True
    Passthru            = $True
    DiskLayout          = "UEFI"
    Edition    = @(
        "Windows Server 2019 Standard Evaluation" # core: Windows Server 2019 Standard Evaluation desktop: Windows Server 2019 Standard Evaluation (Desktop Experience)
    )
}
# Produce the images
$VHDx = Convert-WindowsImage @ConvertWindowsImageParam