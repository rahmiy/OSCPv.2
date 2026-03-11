@echo off
::dism.exe /online /cleanup-image /restorehealth
::sfc /scannow

del C:\Windows\temp\*.*/s/q
del C:\Windows\prefetch\*.*/s/q

net stop bits
net stop wuauserv
del C:\Windows\SoftwareDistribution\*.*/s/q
net start bits
net start wuauserv
