// ESP32 Receiver: ESP-NOW + TinyJAMBU-128 + ECDSA secp256r1 + Blynk
// Board: ESP32 Dev Module, Arduino-ESP32 3.x
// Library eksternal: https://github.com/rweather/TinyJAMBU
#define BLYNK_TEMPLATE_ID "TMPL6r3KDmvDO"
#define BLYNK_TEMPLATE_NAME "Sistem Monitoring Ruangan"
#define BLYNK_AUTH_TOKEN "ISI_TOKEN_BARU"

#include <Arduino.h>
#include <atomic>
#include <WiFi.h>
#include <esp_now.h>
#include <esp_mac.h>
#include <esp_random.h>
#include <Wire.h>
#include <LiquidCrystal_I2C.h>
#include <BlynkSimpleEsp32.h>
#include <TinyJAMBU.h>
#include <mbedtls/ecp.h>
#include <mbedtls/ecdsa.h>
#include <mbedtls/md.h>
#include <stddef.h>
#include "secrets.h" // Hasil python make_keys.py

char ssid[] = "PengantarKIC";
char pass[] = "ISI_PASSWORD_HOTSPOT"; // Jangan masukkan password ke repositori
// WAJIB DIGANTI: MAC Wi-Fi STA TRANSMITTER; lihat Serial Monitor TX
const uint8_t TRANSMITTER_MAC[6] = {0xB0,0x3F,0xD3,0x5C,0x2B,0xAC}; // ISI MAC TX ASLI

#define LED_MERAH 19
#define LED_HIJAU 18
#define BUZZER_PIN 17
#define SDA_LCD 21
#define SCL_LCD 22

const uint32_t ALERT_TIME = 5000;
const uint32_t TIMEOUT_KONEKSI = 3000;
const uint32_t BLYNK_RETRY_MS = 10000;
const uint32_t CHALLENGE_INTERVAL_MS = 1500;
#define PRINT_PER_PACKET_METRICS 0 // 1 = data verify/decrypt per paket
const uint32_t REPORT_EVERY_N = 20;
const uint8_t FALLBACK_CHANNEL = 1;

constexpr uint8_t PROTO_VERSION = 1;
constexpr uint8_t PKT_CHALLENGE = 0xC1;
constexpr uint8_t PKT_DATA = 0xD1;
constexpr size_t CHALLENGE_SIZE = 12;
constexpr size_t NONCE_SIZE = 12;
constexpr size_t CIPHER_SIZE = 9;

struct __attribute__((packed)) ChallengePacket {
  uint8_t version;
  uint8_t type;
  uint8_t challenge[CHALLENGE_SIZE];
};
struct __attribute__((packed)) SecurePacket {
  uint8_t version;
  uint8_t type;
  uint8_t challenge[CHALLENGE_SIZE];
  uint8_t nonce[NONCE_SIZE];
  uint8_t cipher[CIPHER_SIZE];
  uint8_t signature[64];
};
static_assert(sizeof(SecurePacket) == 99, "Layout paket berubah!");

LiquidCrystal_I2C lcd(0x27, 16, 2);
BlynkTimer timer;
portMUX_TYPE rxMux = portMUX_INITIALIZER_UNLOCKED;
SecurePacket packetPending = {};
volatile bool hasPacket = false;

mbedtls_ecp_group eccGroup;
mbedtls_ecp_point eccPublic;

// Pengukuran lokal RX. Menyimpan operasi valid untuk statistik.
struct PerfStat {
  uint64_t sum = 0;
  uint32_t minimum = UINT32_MAX, maximum = 0, count = 0;
  void add(uint32_t us) {
    sum += us; ++count;
    if (us < minimum) minimum = us;
    if (us > maximum) maximum = us;
  }
  uint32_t mean() const { return count ? (uint32_t)(sum / count) : 0; }
};
PerfStat verifyStat, decryptStat;

void printPerfRX(uint32_t accepted, uint32_t rejected) {
  if (!verifyStat.count || !decryptStat.count) return;
  Serial.println("CSV_RX_HEADER,accepted,verify_avg_us,verify_min_us,verify_max_us,decrypt_avg_us,decrypt_min_us,decrypt_max_us,rejected");
  Serial.printf("CSV_RX,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu\n",
                (unsigned long)accepted,
                (unsigned long)verifyStat.mean(), (unsigned long)verifyStat.minimum,
                (unsigned long)verifyStat.maximum, (unsigned long)decryptStat.mean(),
                (unsigned long)decryptStat.minimum, (unsigned long)decryptStat.maximum,
                (unsigned long)rejected);
}

uint8_t activeChallenge[CHALLENGE_SIZE] = {};
uint32_t latestSequence = 0;
bool sessionAccepted = false;
uint32_t lastPacketMs = 0;
uint32_t lastChallengeMs = 0;
uint32_t lastBlynkRetryMs = 0;
uint32_t alertStartMs = 0;
// Status alarm dibagikan dengan task FreeRTOS agar perubahan nada
// tidak tertunda oleh verifikasi ECDSA, TinyJAMBU, atau koneksi Blynk.
std::atomic<bool> buzzerRequested{false};
TaskHandle_t buzzerTaskHandle = nullptr;
uint32_t freqBuzzer = 0; // Dipakai jika task gagal dibuat (fallback).
uint32_t acceptedCount = 0;
uint32_t rejectedCount = 0;
int lastWifiChannel = -1;
bool everVerified = false;
bool movement = false;
bool alarmSeen = false;
bool previouslyOnline = false;

enum DisplayState { LCD_UNSET = -1, LCD_WAITING, LCD_SAFE, LCD_ALERT, LCD_OFFLINE };
void showLCD(DisplayState state);
DisplayState displayState = LCD_UNSET;

// ================================================================
// KONFIGURASI LED. Ubah ke true HANYA jika LED terpasang Active-LOW:
// - Active-HIGH: GPIO -> resistor -> anoda LED; katoda LED -> GND
// - Active-LOW : 3V3 -> resistor -> anoda LED; katoda LED -> GPIO
// Catatan: GPIO dan GND kedua LED tidak boleh digabung sembarangan.
// ================================================================
constexpr bool LED_MERAH_ACTIVE_LOW = false;
constexpr bool LED_HIJAU_ACTIVE_LOW = false;

constexpr uint8_t LED_MODE_MATI  = 0;
constexpr uint8_t LED_MODE_MERAH = 1;
constexpr uint8_t LED_MODE_HIJAU = 2;

// Mematikan kedua LED SEBELUM menyalakan satu LED; menghindari
// kondisi sementara kedua LED aktif saat status sensor berubah.
// Cache mode menjaga LED tidak berkedip akibat penulisan berulang.
void aturLED(uint8_t mode) {
  static uint8_t lastMode = 255;
  if (mode == lastMode) return;
  if (mode > LED_MODE_HIJAU) mode = LED_MODE_MATI;

  digitalWrite(LED_MERAH, LED_MERAH_ACTIVE_LOW ? HIGH : LOW);
  digitalWrite(LED_HIJAU, LED_HIJAU_ACTIVE_LOW ? HIGH : LOW);
  if (mode == LED_MODE_MERAH) {
    digitalWrite(LED_MERAH, LED_MERAH_ACTIVE_LOW ? LOW : HIGH);
  } else if (mode == LED_MODE_HIJAU) {
    digitalWrite(LED_HIJAU, LED_HIJAU_ACTIVE_LOW ? LOW : HIGH);
  }
  lastMode = mode;
}

// Diagnostik dari Serial Monitor RX (115200 baud):
// R = hanya MERAH, G = hanya HIJAU, O = keduanya MATI,
// A = kembali ke otomatis berdasarkan data PIR yang sudah diverifikasi.
// Saat tes manual, nilai status Blynk tetap mencerminkan sensor (bukan tes LED).
// Nonaktifkan pada versi produksi agar perangkat tidak bisa dikendalikan lokal.
constexpr bool ENABLE_LED_SERIAL_TEST = true;
int8_t manualLedMode = -1;  // -1 berarti otomatis

void periksaPerintahLED() {
  if (!ENABLE_LED_SERIAL_TEST) return;
  while (Serial.available() > 0) {
    char c = (char)Serial.read();
    if (c >= 'a' && c <= 'z') c -= ('a' - 'A');
    switch (c) {
      case 'R': manualLedMode = LED_MODE_MERAH; Serial.println("[LED TEST] Hanya MERAH"); break;
      case 'G': manualLedMode = LED_MODE_HIJAU; Serial.println("[LED TEST] Hanya HIJAU"); break;
      case 'O': manualLedMode = LED_MODE_MATI;  Serial.println("[LED TEST] Semua MATI"); break;
      case 'A': manualLedMode = -1; Serial.println("[LED TEST] Mode OTOMATIS"); break;
      default: break;
    }
  }
}

void onReceive(const esp_now_recv_info_t *info, const uint8_t *buf, int len) {
  if (!info || memcmp(info->src_addr, TRANSMITTER_MAC, 6) != 0) return;
  if (len != sizeof(SecurePacket)) return;
  SecurePacket packet;
  memcpy(&packet, buf, sizeof(packet));
  if (packet.version != PROTO_VERSION || packet.type != PKT_DATA) return;
  // Jangan jalankan kriptografi di callback WiFi.
  portENTER_CRITICAL(&rxMux);
  packetPending = packet;
  hasPacket = true;
  portEXIT_CRITICAL(&rxMux);
}

void showLCD(DisplayState state) {
  if (state == displayState) return;
  displayState = state;
  lcd.clear();
  if (state == LCD_WAITING) {
    lcd.setCursor(0, 0); lcd.print("MENUNGGU DATA");
    lcd.setCursor(0, 1); lcd.print("VERIFIKASI...");
  } else if (state == LCD_ALERT) {
    lcd.setCursor(0, 0); lcd.print("[ALERT] GERAKAN");
    lcd.setCursor(0, 1); lcd.print("TERDETEKSI!");
  } else if (state == LCD_SAFE) {
    lcd.setCursor(0, 0); lcd.print("[AMAN] Tidak ada");
    lcd.setCursor(0, 1); lcd.print("gerakan");
  } else if (state == LCD_OFFLINE) {
    lcd.setCursor(0, 0); lcd.print("LINK TIDAK AMAN");
    lcd.setCursor(0, 1); lcd.print("CEK TRANSMITTER");
  }
}

// Pola suara DIAMBIL dari RECEIVER_PIR(2).ino:
// 2000 Hz lalu 2800 Hz, bergantian setiap 200 ms.
// Task berprioritas sedikit lebih tinggi dari loop() supaya tetap
// memperbarui nada ketika loop() sedang memproses kriptografi.
void buzzerWorker(void *parameter) {
  uint32_t frekuensiTerakhir = 0;

  for (;;) {
    bool aktif = buzzerRequested.load(std::memory_order_relaxed);
    uint32_t frekuensi = aktif
      ? (((millis() / 200UL) % 2UL == 0) ? 2000U : 2800U)
      : 0U;

    if (frekuensi != frekuensiTerakhir) {
      ledcWriteTone(BUZZER_PIN, frekuensi);
      frekuensiTerakhir = frekuensi;
    }
    vTaskDelay(pdMS_TO_TICKS(10));
  }
}

void driveBuzzer(bool on) {
  buzzerRequested.store(on, std::memory_order_relaxed);

  // Jika task FreeRTOS tidak berhasil dibuat, tetap gunakan
  // pola asli di loop() sebagai fallback.
  if (buzzerTaskHandle == nullptr) {
    uint32_t frekuensi = on
      ? (((millis() / 200UL) % 2UL == 0) ? 2000U : 2800U)
      : 0U;
    if (frekuensi != freqBuzzer) {
      ledcWriteTone(BUZZER_PIN, frekuensi);
      freqBuzzer = frekuensi;
    }
  }
}

bool verifiedOnline() {
  return everVerified && (uint32_t)(millis() - lastPacketMs) <= TIMEOUT_KONEKSI;
}

void generateFreshChallenge() {
  esp_fill_random(activeChallenge, sizeof(activeChallenge));
  latestSequence = 0;
  sessionAccepted = false;
  Serial.println("[SECURITY] Challenge baru. Menunggu paket bertanda tangan.");
}

void sendChallenge() {
  ChallengePacket packet = {};
  packet.version = PROTO_VERSION;
  packet.type = PKT_CHALLENGE;
  memcpy(packet.challenge, activeChallenge, CHALLENGE_SIZE);
  esp_err_t err = esp_now_send(TRANSMITTER_MAC,
                               reinterpret_cast<const uint8_t *>(&packet),
                               sizeof(packet));
  if (err != ESP_OK) Serial.printf("Kirim challenge gagal: %d\n", err);
}

bool verifyECDSA(const SecurePacket &packet) {
  uint8_t digest[32];
  const mbedtls_md_info_t *md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
  if (!md || mbedtls_md(md, reinterpret_cast<const uint8_t *>(&packet),
                         offsetof(SecurePacket, signature), digest) != 0) return false;

  mbedtls_mpi r, s;
  mbedtls_mpi_init(&r);
  mbedtls_mpi_init(&s);
  int rc = mbedtls_mpi_read_binary(&r, packet.signature, 32);
  if (rc == 0) rc = mbedtls_mpi_read_binary(&s, packet.signature + 32, 32);
  if (rc == 0) rc = mbedtls_ecdsa_verify(&eccGroup, digest, sizeof(digest), &eccPublic, &r, &s);
  mbedtls_mpi_free(&r);
  mbedtls_mpi_free(&s);
  return rc == 0;
}

bool decryptAndAuthenticate(const SecurePacket &packet, uint8_t &outMotion, uint32_t &outSequence) {
  // Challenge dari RX menolak replay sesi dari sebelum restart.
  if (memcmp(packet.challenge, activeChallenge, CHALLENGE_SIZE) != 0) return false;

  const uint32_t sequence = (uint32_t(packet.nonce[8]) << 24) |
                            (uint32_t(packet.nonce[9]) << 16) |
                            (uint32_t(packet.nonce[10]) << 8) |
                            uint32_t(packet.nonce[11]);
  if (sequence == 0 || (sessionAccepted && sequence <= latestSequence)) return false;
  uint32_t t0 = micros();
  bool signatureOK = verifyECDSA(packet);
  uint32_t verifyUs = (uint32_t)(micros() - t0);
  if (!signatureOK) return false;

  uint8_t plain[1] = {};
  size_t plainLength = 0;
  t0 = micros();
  int rc = tinyjambu_128_aead_decrypt(plain, &plainLength,
                    packet.cipher, sizeof(packet.cipher),
                    reinterpret_cast<const uint8_t *>(&packet),
                    offsetof(SecurePacket, cipher),
                    packet.nonce, TINYJAMBU_KEY);
  uint32_t decryptUs = (uint32_t)(micros() - t0);
  if (rc != 0 || plainLength != 1 || plain[0] > 1) return false;
  verifyStat.add(verifyUs);
  decryptStat.add(decryptUs);
  if (PRINT_PER_PACKET_METRICS) {
    Serial.printf("CSV_RX_ROW,%lu,%lu,%lu\n", (unsigned long)sequence,
                  (unsigned long)verifyUs, (unsigned long)decryptUs);
  }
  outMotion = plain[0];
  outSequence = sequence;
  return true;
}

void publishToBlynk() {
  if (WiFi.status() != WL_CONNECTED || !Blynk.connected()) return;
  int rssi = WiFi.RSSI();
  float quality = constrain(2.0f * (rssi + 100), 0.0f, 100.0f);
  bool online = verifiedOnline();
  const char *connection = !everVerified ? "MENUNGGU VERIFIKASI" :
                             online ? "ESP-NOW SECURE" : "ESP-NOW OFFLINE";
  const char *sensor = !everVerified ? "MENUNGGU VERIFIKASI" :
                         !online ? "KONEKSI TERPUTUS" :
                         movement ? "GERAKAN TERDETEKSI" : "TIDAK ADA GERAKAN";
  Blynk.virtualWrite(V0, connection);
  Blynk.virtualWrite(V1, quality);
  Blynk.virtualWrite(V2, rssi);
  Blynk.virtualWrite(V3, (online && !movement) ? 1 : 0);
  Blynk.virtualWrite(V4, (online && movement) ? 1 : 0);
  Blynk.virtualWrite(V5, sensor);
}

void setup() {
  Serial.begin(115200);
  pinMode(LED_MERAH, OUTPUT);
  pinMode(LED_HIJAU, OUTPUT);
  aturLED(LED_MODE_MATI);
  if (!ledcAttach(BUZZER_PIN, 2000, 8)) Serial.println("PWM buzzer gagal");
  ledcWriteTone(BUZZER_PIN, 0);
  // ESP32-WROOM-32 memiliki dua core; task buzzer diberi prioritas 2
  // agar suara tetap berganti setiap 200 ms saat proses kriptografi berat.
  BaseType_t buzzerTaskOK = xTaskCreatePinnedToCore(
    buzzerWorker, "BuzzerAlarm", 3072, nullptr, 2,
    &buzzerTaskHandle, 1
  );
  if (buzzerTaskOK != pdPASS) {
    buzzerTaskHandle = nullptr;
    Serial.println("Task buzzer gagal dibuat, memakai mode loop biasa.");
  }
  Wire.begin(SDA_LCD, SCL_LCD);
  lcd.init(); lcd.backlight(); showLCD(LCD_WAITING);

  mbedtls_ecp_group_init(&eccGroup);
  mbedtls_ecp_point_init(&eccPublic);
  if (mbedtls_ecp_group_load(&eccGroup, MBEDTLS_ECP_DP_SECP256R1) != 0 ||
      mbedtls_ecp_point_read_binary(&eccGroup, &eccPublic,
                                   ECDSA_PUBLIC_KEY, 65) != 0) {
    Serial.println("Gagal load public key P-256"); while (true) delay(1000);
  }

  WiFi.mode(WIFI_STA);
  WiFi.setSleep(false);
  WiFi.setAutoReconnect(true);
  WiFi.begin(ssid, pass);
  Serial.print("Connecting hotspot");
  uint32_t started = millis();
  while (WiFi.status() != WL_CONNECTED && millis() - started < 15000) {
    Serial.print("."); delay(250);
  }
  Serial.println();
  int channel = FALLBACK_CHANNEL;
  if (WiFi.status() == WL_CONNECTED) {
    channel = WiFi.channel();
    Serial.printf("Hotspot channel: %d; IP: %s\n", channel, WiFi.localIP().toString().c_str());
  } else {
    Serial.println("Belum terhubung Wi-Fi; fallback channel 1");
    WiFi.setChannel(FALLBACK_CHANNEL);
  }
  lastWifiChannel = channel;
  Serial.printf("MAC Receiver: %s\n", WiFi.macAddress().c_str());

  if (esp_now_init() != ESP_OK) {
    Serial.println("esp_now_init gagal"); while (true) delay(1000);
  }
  esp_now_peer_info_t peer = {};
  memcpy(peer.peer_addr, TRANSMITTER_MAC, 6);
  peer.channel = 0; // Pakai channel antarmuka STA receiver saat ini.
  peer.ifidx = WIFI_IF_STA;
  peer.encrypt = false; // TinyJAMBU adalah enkripsi payload, control challenge terbuka.
  if (esp_now_add_peer(&peer) != ESP_OK) {
    Serial.println("esp_now_add_peer gagal, periksa MAC transmitter"); while (true) delay(1000);
  }
  esp_now_register_recv_cb(onReceive);
  generateFreshChallenge();
  lastChallengeMs = millis() - CHALLENGE_INTERVAL_MS;

  Blynk.config(BLYNK_AUTH_TOKEN);
  lastBlynkRetryMs = millis() - BLYNK_RETRY_MS;
  timer.setInterval(1500L, publishToBlynk);
  Serial.println("[LED TEST] Serial Monitor 115200: R=merah G=hijau O=mati A=otomatis");
  Serial.println("Receiver secure siap; menunggu paket ECDSA + TinyJAMBU valid.");
  Serial.println("CSV_RX berisi waktu verify/decrypt (mikrodetik). Blynk V0..V5 dipertahankan.");
}

void loop() {
  uint32_t now = millis();
  SecurePacket packet;
  bool got = false;
  portENTER_CRITICAL(&rxMux);
  if (hasPacket) {
    packet = packetPending;
    hasPacket = false;
    got = true;
  }
  portEXIT_CRITICAL(&rxMux);

  if (got) {
    uint8_t newMotion = 0;
    uint32_t newSequence = 0;
    if (decryptAndAuthenticate(packet, newMotion, newSequence)) {
      latestSequence = newSequence;
      sessionAccepted = true;
      lastPacketMs = millis();
      everVerified = true;
      ++acceptedCount;
      if ((acceptedCount % REPORT_EVERY_N) == 0) printPerfRX(acceptedCount, rejectedCount);
      bool newState = newMotion == 1;
      if (newState && !movement) {
        alertStartMs = millis(); alarmSeen = true;
        Serial.println("[ALERT] Gerakan; crypto valid!");
      } else if (!newState && movement) {
        Serial.println("[AMAN] Tidak ada gerakan; crypto valid!");
      }
      movement = newState;
    } else {
      ++rejectedCount;
      if (rejectedCount <= 5 || rejectedCount % 10 == 0)
        Serial.printf("[SECURITY] Ditolak (tag/signature/replay): %lu\n", (unsigned long)rejectedCount);
    }
  }

  bool online = verifiedOnline();
  if (previouslyOnline && !online) {
    generateFreshChallenge();
    movement = false;
    alarmSeen = false;
    Serial.println("[OFFLINE] Heartbeat aman hilang; challenge dirotasi.");
    lastChallengeMs = millis() - CHALLENGE_INTERVAL_MS;
  }
  previouslyOnline = online;

  if ((uint32_t)(millis() - lastChallengeMs) >= CHALLENGE_INTERVAL_MS) {
    sendChallenge();
    lastChallengeMs = millis();
  }

  // Tidak pernah meminta kedua LED ON secara bersamaan.
  periksaPerintahLED();
  uint8_t modeAuto = !online ? LED_MODE_MATI :
                      (movement ? LED_MODE_MERAH : LED_MODE_HIJAU);
  aturLED(manualLedMode >= 0 ? (uint8_t)manualLedMode : modeAuto);

  if (online) {
    driveBuzzer(movement);
    bool alert = movement || (alarmSeen && (uint32_t)(millis() - alertStartMs) < ALERT_TIME);
    showLCD(alert ? LCD_ALERT : LCD_SAFE);
  } else {
    driveBuzzer(false);
    showLCD(everVerified ? LCD_OFFLINE : LCD_WAITING);
  }

  if (WiFi.status() == WL_CONNECTED) {
    if (WiFi.channel() != lastWifiChannel) {
      Serial.printf("Channel hotspot berubah menjadi %d. Restart transmitter!\n", WiFi.channel());
      lastWifiChannel = WiFi.channel();
      generateFreshChallenge();
      lastChallengeMs = millis() - CHALLENGE_INTERVAL_MS;
      lastPacketMs = 0;
      movement = false;
    }
    if (Blynk.connected()) {
      Blynk.run();
    } else if ((uint32_t)(now - lastBlynkRetryMs) >= BLYNK_RETRY_MS) {
      lastBlynkRetryMs = now;
      Blynk.connect(500);
    }
  }
  timer.run();
}
