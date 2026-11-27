# Perbaikan source code ESP32 PIR Secure — TinyJAMBU + ECDSA

## File yang dipakai
- `TRANSMITTER_SECURE/TRANSMITTER_SECURE.ino`
- `RECEIVER_SECURE/RECEIVER_SECURE.ino`
- `make_keys.py`, `GENERATE_KUNCI_WINDOWS.bat` untuk pembuatan kunci **jika kunci belum dibuat**.

Kedua sketch merupakan revisi kode yang sebelumnya diunggah, dengan protokol 99 byte yang sama (TinyJAMBU-128 + ECDSA P-256), ESP-NOW, PIR GPIO16, LED GPIO19 dan GPIO18, buzzer GPIO17, LCD SDA21/SCL22, Blynk V0 sampai V5. Nilai password dan token Blynk sengaja tidak disediakan; isi di perangkat lokal. MAC address HARUS disesuaikan dengan MAC Wi-Fi STA board yang sebenarnya.

## Cara memasang tanpa merusak kunci
**Sangat penting:** Jika `secrets.h` dari generator sebelumnya sudah berhasil dibuat, **jangan menggantinya atau menjalankan generator lagi**. Salin **hanya file .ino** baru ke folder transmitter dan receiver sebelumnya. Pastikan `secrets.h` yang lama tetap ada pada masing-masing folder. Jika belum punya kunci, jalankan `GENERATE_KUNCI_WINDOWS.bat` dari folder yang berisi `make_keys.py`, lalu upload **kedua ESP32** dengan pasangan kunci hasil satu kali generate. ZIP versi ini tidak berisi `secrets.h` sehingga tidak akan menimpa kunci pengguna.

## Logika LED
- Gerakan terverifikasi: LED **merah ON**, hijau OFF; buzzer 2000/2800 Hz bergantian per 200 ms.
- Tidak ada gerakan terverifikasi: merah OFF, **hijau ON**; buzzer OFF.
- Belum ada paket valid atau komunikasi terputus lebih dari 3 s: **keduanya OFF**, buzzer OFF.
- Fungsi `aturLED()` **mematikan dua output lebih dulu**, baru menyalakan satu yang diminta, dan hanya menulis saat mode berubah.
- `LED_MERAH_ACTIVE_LOW` dan `LED_HIJAU_ACTIVE_LOW` default `false`, sesuai LED **Active-HIGH**. Bila satu LED terpasang ke 3.3V sebagai Active-LOW, ubah boolean LED terkait menjadi `true` pada board yang berbeda. **Jangan ubah kedua boolean tanpa hasil tes fisik.**

### Tes LED dari Serial Monitor receiver
Buka Serial Monitor receiver 115200 baud, pada input Serial Monitor kirim salah satu huruf:
- `R` → hanya merah ON
- `G` → hanya hijau ON
- `O` → keduanya OFF
- `A` → kembali ke pengendalian otomatis

Tes ini bisa dilakukan tanpa menunggu koneksi transmitter; ketika mode tes aktif, output LED **sengaja override** status sensor dan Blynk tetap menunjukkan status asli. Untuk deployment non-demo, ubah `ENABLE_LED_SERIAL_TEST = false`.

**Jika perintah `R` tetap menyalakan kedua LED, itu adalah masalah wiring/polaritas/ground atau pin tidak sesuai**, bukan perintah program, karena fungsi ini hanya mengaktifkan satu GPIO menurut polaritas yang dikonfigurasi. Periksa setiap LED memakai resistor 220–330 ohm ke GPIO masing-masing; konfigurasi Active-HIGH: GPIO 19 → resistor → anoda merah → katoda ke GND; GPIO 18 → resistor → anoda hijau → katoda ke GND.

## Instalasi
- Arduino IDE 2.x; board `ESP32 Dev Module`, **Arduino-ESP32 core 3.x** dengan Mbed TLS 3.x (`mbedtls/ecdsa.h` tersedia). Jika memakai core 4.x, API kripto perlu migrasi.
- Arduino libraries: `TinyJAMBU` dari https://github.com/rweather/TinyJAMBU, `Blynk`, `LiquidCrystal_I2C` yang sesuai fungsi `init()`.
- Pada receiver isi `BLYNK_AUTH_TOKEN`, `ssid`, `pass`; pada transmitter sesuaikan `HOTSPOT_SSID`; pastikan `RECEIVER_MAC` dan `TRANSMITTER_MAC` sesuai MAC STA sebenarnya.
- Jalankan Verify pada transmitter dan receiver. Jika berhasil, upload receiver dahulu lalu transmitter.

## Verifikasi keamanan dan pengukuran
- `PRINT_PER_PACKET_METRICS=1` pada kedua sketch: kirim log `CSV_TX_ROW` waktu enkripsi/sign dan `CSV_RX_ROW` waktu verify/decrypt dalam µs. Statistik rata-rata/min/max tersedia tiap 20 sampel.
- TinyJAMBU melindungi ciphertext+tag; ECDSA memverifikasi hash paket. Receiver tidak mengubah status motion dari paket gagal verifikasi.
- Tidak ada perubahan pada format paket atau kunci, sehingga kunci yang dihasilkan sebelumnya masih dapat dipakai.
- Frame ESP-NOW tidak memakai native encryption (`peer.encrypt=false`), tetapi payload TinyJAMBU terlindungi. Challenge dari receiver belum diautentikasi; ini merupakan prototipe pengujian akademik.

## Batas pengujian
Source telah diperiksa secara statis, tetapi **belum dilakukan Verify/Upload pada Arduino IDE dan belum diuji pada hardware ESP32 pengguna**. LED yang sama-sama menyala secara fisik dengan pengujian `R/G/O` menandakan perlunya pemeriksaan rangkaian. Jangan memasukkan `secrets.h` atau token Blynk ke publikasi.
