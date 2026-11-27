@echo off
setlocal EnableExtensions
cd /d "%~dp0"
title Generate TinyJambu dan ECDSA Keys

echo ==========================================================
echo  GENERATE KUNCI TinyJambu-128 dan ECDSA secp256r1
 echo ==========================================================
echo.
if not exist "make_keys.py" (
 echo [ERROR] make_keys.py tidak ditemukan di folder ini.
 echo Pastikan file BAT ini berada satu folder dengan make_keys.py.
 goto :fail
)

where py >nul 2>nul
if not errorlevel 1 (
  set "PYEXE=py -3"
) else (
  where python >nul 2>nul
  if errorlevel 1 (
    echo [ERROR] Python belum terpasang atau belum masuk PATH.
    echo Instal Python 3 dari https://www.python.org/downloads/windows/
    echo Saat instalasi centang 'Add python.exe to PATH'.
    goto :fail
  )
  set "PYEXE=python"
)

echo [1/3] Memeriksa Python...
%PYEXE% --version
if errorlevel 1 goto :fail

echo.
echo [2/3] Memastikan library cryptography tersedia...
%PYEXE% -c "import cryptography" >nul 2>nul
if errorlevel 1 (
  echo Library belum ada; mencoba instalasi melalui pip...
  %PYEXE% -m pip install cryptography
  if errorlevel 1 (
    echo [ERROR] Instalasi cryptography gagal. Periksa koneksi internet dan pip.
    goto :fail
  )
)

echo.
echo [3/3] Membuat kunci unik di kedua folder sketch...
%PYEXE% "make_keys.py"
if errorlevel 1 goto :fail

if not exist "TRANSMITTER_SECURE\secrets.h" goto :fail
if not exist "RECEIVER_SECURE\secrets.h" goto :fail
findstr /C:"#error" "TRANSMITTER_SECURE\secrets.h" >nul
if not errorlevel 1 goto :fail
findstr /C:"#error" "RECEIVER_SECURE\secrets.h" >nul
if not errorlevel 1 goto :fail

echo.
echo [SUKSES] Kedua file secrets.h sudah berisi kunci.
echo Sekarang buka TRANSMITTER_SECURE.ino di Arduino IDE dan klik Verify.
echo Jangan bagikan secrets.h atau screenshot berisi kunci.
echo CATATAN: Menjalankan generator lagi akan mengganti kunci;
echo upload ulang TX dan RX jika kunci dibuat ulang.
echo.
pause
exit /b 0

:fail
echo.
echo [GAGAL] Pembuatan kunci belum berhasil. Baca pesan error di atas.
echo Jika perlu bantuan, kirim teks error saja tanpa isi secrets.h.
echo.
pause
exit /b 1
