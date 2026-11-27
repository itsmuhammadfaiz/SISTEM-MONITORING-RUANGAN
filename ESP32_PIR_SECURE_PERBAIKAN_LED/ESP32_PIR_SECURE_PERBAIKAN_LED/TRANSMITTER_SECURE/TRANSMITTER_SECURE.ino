// ESP32 Transmitter: PIR + ESP-NOW + TinyJAMBU-128 + ECDSA P-256
// Board: ESP32 Dev Module, Arduino-ESP32 3.x
// Library eksternal: https://github.com/rweather/TinyJAMBU
#include <Arduino.h>
#include <WiFi.h>
#include <esp_now.h>
#include <esp_wifi.h>
#include <esp_err.h>
#include <esp_random.h>
#include <TinyJAMBU.h>
#include <mbedtls/ecp.h>
#include <mbedtls/ecdsa.h>
#include <mbedtls/md.h>
#include <stddef.h>
#include "secrets.h" // Hasil python make_keys.py

#define PIR_PIN 16
#define LED_MERAH 19
#define LED_HIJAU 18

// WAJIB DIGANTI: MAC WiFi STA receiver (lihat Serial Monitor receiver).
const uint8_t RECEIVER_MAC[6] = {0xB0,0x3F,0xD3,0x5B,0x13,0x94};
// Harus sama persis dengan hotspot pada receiver Blynk.
const char *HOTSPOT_SSID = "PengantarKIC"; // Sesuai kode terakhir; ubah jika SSID berubah
const uint8_t CHANNEL_MANUAL = 0; // 0: scan SSID otomatis; 1..13: manual

const uint32_t INTERVAL_KIRIM_MS = 300; // Dipertahankan dari sumber asli
#define PRINT_PER_PACKET_METRICS 0 // 1 untuk data per paket CSV di Serial Monitor
const uint32_t REPORT_EVERY_N = 20;
// Pengujian integritas: ubah menjadi 1 untuk merusak ciphertext setelah ditandatangani.
#define TEST_RUSAK_PAKET 0
const uint32_t STABILISASI_PIR_MS = 60000;

constexpr uint8_t PROTO_VERSION = 1;
constexpr uint8_t PKT_CHALLENGE = 0xC1;
constexpr uint8_t PKT_DATA = 0xD1;
constexpr size_t CHALLENGE_SIZE = 12;
constexpr size_t NONCE_SIZE = 12;
constexpr size_t CIPHER_SIZE = 9; // 1 byte PIR + TinyJAMBU tag 8 byte

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
  uint8_t signature[64]; // ECDSA P-256 raw r(32) || s(32)
};
static_assert(sizeof(SecurePacket) == 99, "Layout paket berubah!");

portMUX_TYPE rxMux = portMUX_INITIALIZER_UNLOCKED;
ChallengePacket pendingChallenge = {};
volatile bool hasChallenge = false;
uint8_t activeChallenge[CHALLENGE_SIZE] = {};
uint8_t noncePrefix[8] = {};
uint32_t sequence = 0;
bool sessionReady = false;
uint32_t lastSendMs = 0;
int lastPir = -1;

mbedtls_ecp_group eccGroup;
mbedtls_mpi eccPrivate;

// Timer kripto: ukur operasi saja, bukan waktu radio atau delay.
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
PerfStat encStat, signStat;
uint32_t signedSent = 0, sendRejected = 0;

void printPerfTX() {
  if (!encStat.count || !signStat.count) return;
  Serial.println("CSV_TX_HEADER,valid_packets,enc_avg_us,enc_min_us,enc_max_us,sign_avg_us,sign_min_us,sign_max_us,send_error");
  Serial.printf("CSV_TX,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu\n",
                (unsigned long)signedSent,
                (unsigned long)encStat.mean(), (unsigned long)encStat.minimum,
                (unsigned long)encStat.maximum, (unsigned long)signStat.mean(),
                (unsigned long)signStat.minimum, (unsigned long)signStat.maximum,
                (unsigned long)sendRejected);
}



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

int secureRng(void *, unsigned char *out, size_t size) {
  esp_fill_random(out, size);
  return 0;
}

void onReceive(const esp_now_recv_info_t *info, const uint8_t *buf, int len) {
  if (!info || memcmp(info->src_addr, RECEIVER_MAC, 6) != 0) return;
  if (len != sizeof(ChallengePacket)) return;
  ChallengePacket ctrl;
  memcpy(&ctrl, buf, sizeof(ctrl));
  if (ctrl.version != PROTO_VERSION || ctrl.type != PKT_CHALLENGE) return;
  portENTER_CRITICAL(&rxMux);
  pendingChallenge = ctrl;
  hasChallenge = true;
  portEXIT_CRITICAL(&rxMux);
}

int detectHotspotChannel() {
  int count = WiFi.scanNetworks(false, true);
  if (count <= 0) { WiFi.scanDelete(); return -1; }
  int channel = -1;
  int best = -1000;
  for (int i = 0; i < count; ++i) {
    if (WiFi.SSID(i) == HOTSPOT_SSID && WiFi.RSSI(i) > best) {
      channel = WiFi.channel(i);
      best = WiFi.RSSI(i);
    }
  }
  WiFi.scanDelete();
  return channel;
}

bool signPacket(SecurePacket &packet) {
  uint8_t digest[32];
  const mbedtls_md_info_t *md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
  if (!md || mbedtls_md(md, reinterpret_cast<const uint8_t *>(&packet),
                         offsetof(SecurePacket, signature), digest) != 0) return false;

  mbedtls_mpi r, s;
  mbedtls_mpi_init(&r);
  mbedtls_mpi_init(&s);
  int rc = mbedtls_ecdsa_sign(&eccGroup, &r, &s, &eccPrivate,
                             digest, sizeof(digest), secureRng, nullptr);
  if (rc == 0) rc = mbedtls_mpi_write_binary(&r, packet.signature, 32);
  if (rc == 0) rc = mbedtls_mpi_write_binary(&s, packet.signature + 32, 32);
  mbedtls_mpi_free(&r);
  mbedtls_mpi_free(&s);
  return rc == 0;
}

void sendEncryptedPIR(uint8_t motion) {
  if (!sessionReady) return;
  if (sequence == UINT32_MAX) {
    sessionReady = false;
    Serial.println("Sequence habis: hentikan pengiriman dan restart kedua board.");
    return;
  }
  SecurePacket packet = {};
  packet.version = PROTO_VERSION;
  packet.type = PKT_DATA;
  memcpy(packet.challenge, activeChallenge, CHALLENGE_SIZE);
  memcpy(packet.nonce, noncePrefix, 8);
  const uint32_t seq = ++sequence;
  packet.nonce[8] = uint8_t(seq >> 24);
  packet.nonce[9] = uint8_t(seq >> 16);
  packet.nonce[10] = uint8_t(seq >> 8);
  packet.nonce[11] = uint8_t(seq);

  // AAD = versi + tipe + challenge + nonce: tak disembunyikan tetapi diverifikasi.
  size_t written = 0;
  uint32_t t0 = micros();
  tinyjambu_128_aead_encrypt(packet.cipher, &written,
                            &motion, 1,
                            reinterpret_cast<const uint8_t *>(&packet),
                            offsetof(SecurePacket, cipher),
                            packet.nonce, TINYJAMBU_KEY);
  uint32_t encUs = (uint32_t)(micros() - t0);
  if (written != CIPHER_SIZE) {
    Serial.println("Gagal TinyJambu encrypt");
    return;
  }
  t0 = micros();
  bool signedOK = signPacket(packet);
  uint32_t signUs = (uint32_t)(micros() - t0);
  if (!signedOK) {
    Serial.println("Gagal ECDSA sign");
    return;
  }
  encStat.add(encUs);
  signStat.add(signUs);
  ++signedSent;
  if (PRINT_PER_PACKET_METRICS) {
    Serial.printf("CSV_TX_ROW,%lu,%lu,%lu\n", (unsigned long)seq,
                  (unsigned long)encUs, (unsigned long)signUs);
  }
  if ((signedSent % REPORT_EVERY_N) == 0) printPerfTX();
  if (TEST_RUSAK_PAKET) packet.cipher[0] ^= 0x01;
  esp_err_t rc = esp_now_send(RECEIVER_MAC,
                              reinterpret_cast<const uint8_t *>(&packet),
                              sizeof(packet));
  if (rc != ESP_OK) {
    ++sendRejected;
    Serial.printf("esp_now_send gagal: %s\n", esp_err_to_name(rc));
  }
}

void setup() {
  Serial.begin(115200);
  pinMode(PIR_PIN, INPUT);
  pinMode(LED_MERAH, OUTPUT);
  pinMode(LED_HIJAU, OUTPUT);
  aturLED(LED_MODE_MATI);

  mbedtls_ecp_group_init(&eccGroup);
  mbedtls_mpi_init(&eccPrivate);
  if (mbedtls_ecp_group_load(&eccGroup, MBEDTLS_ECP_DP_SECP256R1) != 0 ||
      mbedtls_mpi_read_binary(&eccPrivate, ECDSA_PRIVATE_KEY, 32) != 0) {
    Serial.println("Gagal load private key P-256"); while (true) delay(1000);
  }

  WiFi.mode(WIFI_STA);
  WiFi.setSleep(false);
  WiFi.disconnect();
  delay(150);
  Serial.printf("MAC Transmitter: %s\n", WiFi.macAddress().c_str());
  int channel = CHANNEL_MANUAL;
  while (channel < 1 || channel > 13) {
    channel = detectHotspotChannel();
    if (channel < 1 || channel > 13) {
      Serial.println("Hotspot tidak ditemukan; cek SSID atau channel manual.");
      delay(3000);
    }
  }
  if (esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE) != ESP_OK) {
    Serial.println("Gagal mengatur channel WiFi"); while (true) delay(1000);
  }
  Serial.printf("TX channel: %d | MAC: %s\n", channel, WiFi.macAddress().c_str());

  if (esp_now_init() != ESP_OK) {
    Serial.println("esp_now_init gagal"); while (true) delay(1000);
  }
  esp_now_peer_info_t peer = {};
  memcpy(peer.peer_addr, RECEIVER_MAC, 6);
  peer.channel = channel;
  peer.ifidx = WIFI_IF_STA;
  peer.encrypt = false; // TinyJAMBU melindungi payload. Challenge tidak terenkripsi.
  if (esp_now_add_peer(&peer) != ESP_OK) {
    Serial.println("esp_now_add_peer gagal"); while (true) delay(1000);
  }
  esp_now_register_recv_cb(onReceive);
  Serial.println("TX siap; CSV_TX berisi metrik kripto (mikrodetik).");
  Serial.println("TX siap, stabilisasi PIR selama 60 detik dan tunggu challenge...");
  delay(STABILISASI_PIR_MS);
}

void loop() {
  ChallengePacket newChallenge;
  bool received = false;
  portENTER_CRITICAL(&rxMux);
  if (hasChallenge) {
    newChallenge = pendingChallenge;
    received = true;
    hasChallenge = false;
  }
  portEXIT_CRITICAL(&rxMux);

  if (received && (!sessionReady || memcmp(newChallenge.challenge, activeChallenge, 12) != 0)) {
    memcpy(activeChallenge, newChallenge.challenge, 12);
    esp_fill_random(noncePrefix, 8);
    sequence = 0;
    sessionReady = true;
    Serial.println("Challenge RX diterima: sesi baru dimulai.");
  }
  int pir = digitalRead(PIR_PIN);
  aturLED(pir == HIGH ? LED_MODE_MERAH : LED_MODE_HIJAU);
  bool statusBerubah = (pir != lastPir);
  if (statusBerubah) {
    Serial.println(pir ? "[ALERT] Gerakan" : "[AMAN] Tidak ada gerakan");
    lastPir = pir;
  }

  uint32_t now = millis();
  // Pertahankan perilaku original: kirim saat berubah atau heartbeat 300 ms.
  if (sessionReady &&
      (statusBerubah || (uint32_t)(now - lastSendMs) >= INTERVAL_KIRIM_MS)) {
    sendEncryptedPIR(pir ? 1 : 0);
    lastSendMs = millis();
  }
  delay(5);
}
