 rem Windows auto setting

 rem input any key

echo  "input any key"
pause

 rem ���W�X�g���̊m�F
echo "registry check"

reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
reg query "HKEY_CURRENT_USER\Control Panel\Desktop"
reg query "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update"
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"


 rem �������O�C����L���ɂ���
echo "enable AutoLogin"
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "AutoAdminLogon" /t REG_DWORD /d "1" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "DefaultUserName" /t REG_SZ /d "userName" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "DefaultPassword" /t REG_SZ /d "password" /f


 rem �B���t�@�C����\������
echo "show HiddenFile"
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v Hidden /t REG_DWORD /d 1 /f


 rem �f�X�N�g�b�v�A�C�R�����\���ɂ���
echo "hide DesktopIcons"
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v HideIcons /t REG_DWORD /d 1 /f

 rem �ċN�����̕����𖳌�������
echo "disable restore"
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoSaveSettings /t REG_DWORD /d 1 /f

 rem �X�N���[���Z�[�o�[ OFF
echo "do not start the ScreenSaver"
reg add  "HKEY_CURRENT_USER\Control Panel\Desktop" /v ScreenSaveActive  /t REG_SZ /d 0 /f


 rem �f�B�X�v���C�d����؂�Ȃ�
powercfg -change -monitor-timeout-ac 0
powercfg -change -monitor-timeout-dc 0
echo "do not turn off display power"


 rem �X���[�v�𖳌��ɂ���
echo "disable sleep"
powercfg -change -standby-timeout-ac 0
powercfg -change -standby-timeout-dc 0


 rem �����X�V��؂�
echo "disable WindowsUpdate"
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /v AUOptions /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /v IncludeRecommendedUpdates /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /v EnableFeaturedSoftware /t REG_DWORD /d 0 /f

 rem power shell
 rem Stop-Service -Name "Windows Update"
 rem �R�}���h�v�����v�g
sc config wuauserv start= disabled

pause