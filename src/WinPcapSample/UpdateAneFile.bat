::: WinPcapExtension.ane
@echo off
echo .
echo Copying WinPcapExtension.ane to this project...
echo .
copy ..\..\..\WinPcapExtension\src\WinPcapExtension\WinPcapExtension.ane ext\ /v /y
rmdir extdir\WinPcapExtension.ane /s /q
mkdir extdir\WinPcapExtension.ane
set PATH=%PATH%;C:\Program Files\Git\usr\bin
unzip -o ext/WinPcapExtension.ane -d extdir/WinPcapExtension.ane/ 

::: PacketLib.swc
echo .
echo Copying PacketLib.swc to this project ...
echo .
copy ..\..\..\PacketLib\src\PacketLib\bin\PacketLib.swc ext\ /v /y
