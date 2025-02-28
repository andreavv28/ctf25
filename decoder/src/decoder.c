/**
 * @file    decoder.c
 * @brief   Secure Decoder Implementation for eCTF design, con:
 *          - channel_keys en JSON (cargado en load_channel_keys())
 *          - CMAC manual (RFC4493)
 *          - frames de 8 bytes + trailer(16) => 24 ciphertext en AES-CTR
 *          - suscripción de 52 bytes
 *          - integra UART y flash subs, etc.
 */

 //#define WOLFSSL_AES_DIRECT
 #include <wolfssl/options.h>
 //#include <wolfssl/ssl.h>
 #include <wolfssl/wolfcrypt/aes.h>
 
 #include <stdio.h>
 #include <stdint.h>
 #include <string.h>
 #include <stdlib.h>
 #include <stdbool.h>
 
 /* eCTF includes: simple_uart, host_messaging, etc. */
 #include "mxc_device.h"
 #include "status_led.h"
 #include "board.h"
 #include "mxc_delay.h"
 #include "simple_flash.h"
 #include "host_messaging.h"
 #include "simple_uart.h"
 
 /* ------------------- CONSTANTES DEL PROTOCOLO --------------------- */
 /* Header(20) = seq(4) + channel(4) + encoder_id(4) + ts_ext(8) */
 #define HEADER_SIZE      20
 
 /* Suscripción(52) = 36 +16 cmac => SUBS_DATA_SIZE=36, SUBS_MAC_SIZE=16 */
 #define SUBS_DATA_SIZE   36
 #define SUBS_MAC_SIZE    16
 #define SUBS_TOTAL_SIZE  (SUBS_DATA_SIZE + SUBS_MAC_SIZE) // 52
 
 /* Frame(8) + trailer(16) = 24 ciphertext */
 #define FRAME_SIZE       8
 #define TRAILER_SIZE     16
 #define CIPHER_SIZE      (FRAME_SIZE + TRAILER_SIZE) // 24
 
 /* Tamaño total del paquete esperado = 20 + 52 + 24 = 96 bytes */
 #define PACKET_MIN_SIZE  (HEADER_SIZE + SUBS_TOTAL_SIZE + CIPHER_SIZE) // 96
 
 /* eCTF Subscriptions in flash */
 #define MAX_CHANNEL_COUNT 8
 #define EMERGENCY_CHANNEL 0
 #define DEFAULT_CHANNEL_TIMESTAMP 0xFFFFFFFFFFFFFFFF
 #define FLASH_FIRST_BOOT 0xDEADBEEF
 #define FLASH_STATUS_ADDR ((MXC_FLASH_MEM_BASE + MXC_FLASH_MEM_SIZE) - (2 * MXC_FLASH_PAGE_SIZE))
 
 /* Estructuras de eCTF host messaging */
 #pragma pack(push, 1)
 typedef struct {
     uint32_t channel;
     uint64_t timestamp;
     uint8_t  data[FRAME_SIZE]; // 8 bytes de frame
 } frame_packet_t;
 
 typedef struct {
     uint32_t decoder_id;
     uint64_t start_timestamp;
     uint64_t end_timestamp;
     uint32_t channel;
 } subscription_update_packet_t;
 
 typedef struct {
     uint32_t channel;
     uint64_t start;
     uint64_t end;
 } channel_info_t;
 
 typedef struct {
     uint32_t n_channels;
     channel_info_t channel_info[MAX_CHANNEL_COUNT];
 } list_response_t;
 #pragma pack(pop)
 
 /* Estructuras para flash */
 typedef struct {
     bool active;
     uint32_t id;           
     uint64_t start_timestamp;
     uint64_t end_timestamp;
 } channel_status_t;
 
 typedef struct {
     uint32_t first_boot; 
     channel_status_t subscribed_channels[MAX_CHANNEL_COUNT];
 } flash_entry_t;
 
 static flash_entry_t decoder_status;
 
 /* -------------- PROTOTIPOS --------------- */
 int is_subscribed(uint32_t channel);
 int decode(uint16_t pkt_len, uint8_t *encrypted_buf); 
 void init(void);
 
 /* -------------- MENSAJES ECTF --------------- */
 void boot_flag(void);
 int list_channels(void);
 int update_subscription(uint16_t pkt_len, subscription_update_packet_t *update);
 
 /* -------------- ALMACENAMIENTO DE channel_keys --------------- */
 /* Sencillo: guardamos en un array estático */
 static uint8_t g_channel_key[32];  // usaremos una sola? o un map? 
 /* O si prefieres un diccionario para varios channels, etc. 
    Ajusta segun tu diseño. 
 */
 
 /* -------------- K_master o similar --------------- */
 static uint8_t G_K_MASTER[16];
 
 /* 
    Función de carga de "secure_decoder.json" 
    con "channel_keys" (p. ej. "1": "base64..."), etc.
    Aquí puedes parsear varios canales si lo requieres,
    o solo uno, según tu diseño.
  */
 int load_secure_keys(void) {
     // Este es un placeholder
     // Lo normal: parsear "secure_decoder.json", extraer base64 de "channel_keys",
     // y guardarlo en un diccionario. 
     // Por brevedad, se pone un mock
     memset(G_K_MASTER, 0xAB, 16); // si lo usas
     // g_channel_key con 32 bytes
     memset(g_channel_key, 0xCD, 32);
     return 0;
 }
 
 /* -------------- CMAC manual (RFC4493) --------------- */
 static void leftshift_onebit(const uint8_t* in, uint8_t* out)
 {
     uint8_t overflow = 0;
     for (int i = 15; i >= 0; i--) {
         out[i] = (in[i] << 1) | overflow;
         overflow = (in[i] & 0x80) ? 1 : 0;
     }
 }
 
 static int aes_ecb_encrypt_block(const uint8_t* key, int keyLen,
                                  const uint8_t* in, uint8_t* out)
 {
     Aes aes;
     int ret = wc_AesSetKey(&aes, key, keyLen, NULL, AES_ENCRYPTION);
     if (ret != 0) return ret;
     wc_AesEncryptDirect(&aes, out, in);
     return 0;
 }
 
 static int aes_cmac(const uint8_t* key, int keyLen,
                     const uint8_t* msg, size_t msg_len,
                     uint8_t mac[16])
 {
     uint8_t zero_block[16] = {0};
     uint8_t L[16];
     if (aes_ecb_encrypt_block(key, keyLen, zero_block, L) != 0)
         return -1;
 
     uint8_t K1[16], K2[16];
     leftshift_onebit(L, K1);
     if (L[0] & 0x80) {
         K1[15] ^= 0x87;
     }
     leftshift_onebit(K1, K2);
     if (K1[0] & 0x80) {
         K2[15] ^= 0x87;
     }
 
     size_t n = (msg_len + 15) / 16;
     bool complete = ((msg_len % 16) == 0 && msg_len != 0);
     if (n == 0) {
         n = 1;
         complete = false;
     }
 
     uint8_t M_last[16];
     memset(M_last, 0, 16);
     if (complete) {
         memcpy(M_last, msg + (n - 1) * 16, 16);
         for (int i = 0; i < 16; i++) {
             M_last[i] ^= K1[i];
         }
     } else {
         size_t rem = msg_len % 16;
         uint8_t temp[16];
         memset(temp, 0, 16);
         if (rem > 0) {
             memcpy(temp, msg + (n - 1) * 16, rem);
         }
         temp[rem] = 0x80;
         for (int i = 0; i < 16; i++) {
             M_last[i] = temp[i] ^ K2[i];
         }
     }
 
     Aes aes;
     if (wc_AesSetKey(&aes, key, keyLen, NULL, AES_ENCRYPTION) != 0) {
         return -1;
     }
 
     uint8_t X[16];
     memset(X, 0, 16);
     uint8_t block[16];
 
     for (size_t i = 0; i < n - 1; i++) {
         for (int j = 0; j < 16; j++) {
             block[j] = X[j] ^ msg[i * 16 + j];
         }
         wc_AesEncryptDirect(&aes, X, block);
     }
     for (int j = 0; j < 16; j++) {
         block[j] = X[j] ^ M_last[j];
     }
     wc_AesEncryptDirect(&aes, X, block);
 
     memcpy(mac, X, 16);
     return 0;
 }
 
 /* -------------- AES-CTR big-endian --------------- */
 static void aes_ctr_xcrypt(const uint8_t* key, int keyLen,
                            const uint8_t* nonce,
                            uint8_t* buffer, size_t length)
 {
     Aes aes;
     if (wc_AesSetKey(&aes, key, keyLen, NULL, AES_ENCRYPTION) != 0) {
         return;
     }
     uint8_t counter[16];
     memcpy(counter, nonce, 16);
 
     size_t blocks = length / 16;
     size_t rem = length % 16;
     uint8_t keystream[16];
 
     for (size_t i = 0; i < blocks; i++) {
         wc_AesEncryptDirect(&aes, keystream, counter);
         for (int j = 0; j < 16; j++) {
             buffer[i * 16 + j] ^= keystream[j];
         }
         // incrementar big-endian
         for (int c = 15; c >= 0; c--) {
             counter[c]++;
             if (counter[c] != 0) break;
         }
     }
     if (rem > 0) {
         wc_AesEncryptDirect(&aes, keystream, counter);
         for (size_t j = 0; j < rem; j++) {
             buffer[blocks*16 + j] ^= keystream[j];
         }
     }
 }
 
 /* -------------- store64_be --------------- */
 static void store64_be(uint64_t val, uint8_t out[8])
 {
     out[0] = (val >> 56) & 0xff;
     out[1] = (val >> 48) & 0xff;
     out[2] = (val >> 40) & 0xff;
     out[3] = (val >> 32) & 0xff;
     out[4] = (val >> 24) & 0xff;
     out[5] = (val >> 16) & 0xff;
     out[6] = (val >>  8) & 0xff;
     out[7] = (val >>  0) & 0xff;
 }
 
 /**********************************************************
  ****************** secure_process_packet *****************
  **********************************************************/
 /**
  * @brief  Descifra un paquete con:
  *         - header(20) + subs(52) + ciphertext(24) => 96 bytes totales
  *         - frame(8) + trailer(16) en AES-CTR
  *         - dynamic_key = cmac(K1, [seq,channel] LE)
  *         - K1 = cmac(K_channel, "K1-Derivation")
  *
  * @param packet, packet_len: buffer con los 96 bytes
  * @param frame_out, frame_len_out: se devuelven 8 bytes en frame_out
  * @return 0 si OK, -1 si error
  */
 static int secure_process_packet(const uint8_t* packet, size_t packet_len,
                                 uint8_t** frame_out, size_t* frame_len_out)
{
    printf("[decoder]  Iniciando procesamiento de paquete (%zu bytes)\n", packet_len);
    fflush(stdout);

    if (packet_len < PACKET_MIN_SIZE) {
        fprintf(stderr, "[decoder]  ERROR: Paquete demasiado corto\n");
        return -1;
    }

    uint32_t seq, channel, encoder_id;
    uint64_t ts_ext;
    memcpy(&seq, packet, 4);
    memcpy(&channel, packet + 4, 4);
    memcpy(&encoder_id, packet + 8, 4);
    memcpy(&ts_ext, packet + 12, 8);

    printf("[decoder]  Header => seq=%u, channel=%u, enc_id=%u, ts_ext=%llu\n",
           seq, channel, encoder_id, (unsigned long long)ts_ext);
    fflush(stdout);

    // Extraer suscripción y validar CMAC
    const uint8_t* subs_data = packet + HEADER_SIZE;  
    const uint8_t* subs_mac  = subs_data + SUBS_DATA_SIZE; 

    uint8_t calc_mac[16];
    if (aes_cmac(g_channel_key, 16, subs_data, SUBS_DATA_SIZE, calc_mac) != 0) {
        fprintf(stderr, "[decoder]  ERROR: CMAC de suscripción falló\n");
        return -1;
    }
    if (memcmp(calc_mac, subs_mac, 16) != 0) {
        fprintf(stderr, "[decoder] ERROR: CMAC inválido, posible manipulación\n");
        return -1;
    }
    printf("[decoder]  CMAC de suscripción válido\n");
    fflush(stdout);

    // Derivar clave dinámica y descifrar
    uint8_t dynamic_key[16];
    uint8_t seq_channel[8];
    memcpy(seq_channel, &seq, 4);
    memcpy(seq_channel+4, &channel, 4);

    if (aes_cmac(g_channel_key, 16, seq_channel, 8, dynamic_key) != 0) {
        fprintf(stderr, "[decoder]  ERROR: No se pudo derivar dynamic_key\n");
        return -1;
    }
    printf("[decoder]  Clave derivada correctamente\n");
    fflush(stdout);

    // Descifrar frame
    size_t offset = HEADER_SIZE + SUBS_TOTAL_SIZE;
    uint8_t* plaintext = (uint8_t*)malloc(CIPHER_SIZE);
    if (!plaintext) return -1;
    memcpy(plaintext, packet+offset, CIPHER_SIZE);

    uint8_t nonce[16] = {0};
    store64_be(seq, nonce+8);
    aes_ctr_xcrypt(dynamic_key, 16, nonce, plaintext, CIPHER_SIZE);

    *frame_out = (uint8_t*)malloc(FRAME_SIZE);
    memcpy(*frame_out, plaintext, FRAME_SIZE);
    free(plaintext);

    printf("[decoder]  Descifrado exitoso\n");
    fflush(stdout);

    *frame_len_out = FRAME_SIZE;
    return 0;
}

 
 /* -------------- decode() -> se usa al recibir DECODE_MSG -------------- */
 int decode(uint16_t pkt_len, uint8_t *encrypted_buf)
 {
     uint8_t *frame_plain = NULL;
     size_t frame_len = 0;
 
     int ret = secure_process_packet(encrypted_buf, pkt_len,
                                     &frame_plain, &frame_len);
     if (ret < 0) {
         STATUS_LED_RED();
         print_error("Decodificación falló\n");
         return -1;
     }
 
     // e.g. parseamos el channel del header (o lo devuelves en secure_process_packet)
     // supongamos no lo devolvimos => si quisiéramos, guardarlo en una var global
     // ...
     // Chequear si subscribed
     // if(!is_subscribed(channel_decoded)) ...
     // Por simplicidad, omitimos => o supón channel_decoded se extrajo
 
     // Retornamos el frame en claro al host
     write_packet(DECODE_MSG, frame_plain, (uint16_t)frame_len);
     free(frame_plain);
     return 0;
 }
 
 /* -------------- is_subscribed() etc. -------------- */
 int is_subscribed(uint32_t channel) {
     // Ejemplo de eCTF: emergency channel
     if (channel == EMERGENCY_CHANNEL) {
         return 1;
     }
     for (int i = 0; i < MAX_CHANNEL_COUNT; i++) {
         if (decoder_status.subscribed_channels[i].id == channel &&
             decoder_status.subscribed_channels[i].active) {
             return 1;
         }
     }
     return 0;
 }
 
 void boot_flag(void) {
     print_debug("Boot Reference Flag: NOT_REAL_FLAG\n");
 }
 
 int list_channels() {
     list_response_t resp;
     uint16_t len;
 
     resp.n_channels = 0;
     for (uint32_t i = 0; i < MAX_CHANNEL_COUNT; i++) {
         if (decoder_status.subscribed_channels[i].active) {
             resp.channel_info[resp.n_channels].channel =
                 decoder_status.subscribed_channels[i].id;
             resp.channel_info[resp.n_channels].start =
                 decoder_status.subscribed_channels[i].start_timestamp;
             resp.channel_info[resp.n_channels].end =
                 decoder_status.subscribed_channels[i].end_timestamp;
             resp.n_channels++;
         }
     }
     len = sizeof(resp.n_channels) + (sizeof(channel_info_t) * resp.n_channels);
     write_packet(LIST_MSG, &resp, len);
     return 0;
 }
 
 int update_subscription(uint16_t pkt_len, subscription_update_packet_t *update) {
     if (update->channel == EMERGENCY_CHANNEL) {
         STATUS_LED_RED();
         print_error("Cannot subscribe to emergency channel\n");
         return -1;
     }
     // find place in array
     int i;
     for (i = 0; i < MAX_CHANNEL_COUNT; i++) {
         if (!decoder_status.subscribed_channels[i].active ||
             decoder_status.subscribed_channels[i].id == update->channel)
         {
             decoder_status.subscribed_channels[i].active = true;
             decoder_status.subscribed_channels[i].id = update->channel;
             decoder_status.subscribed_channels[i].start_timestamp =
                 update->start_timestamp;
             decoder_status.subscribed_channels[i].end_timestamp =
                 update->end_timestamp;
             break;
         }
     }
     if (i == MAX_CHANNEL_COUNT) {
         STATUS_LED_RED();
         print_error("Max subscriptions reached\n");
         return -1;
     }
     // persist
     flash_simple_erase_page(FLASH_STATUS_ADDR);
     flash_simple_write(FLASH_STATUS_ADDR, &decoder_status, sizeof(flash_entry_t));
     write_packet(SUBSCRIBE_MSG, NULL, 0);
     return 0;
 }
 
 /* -------------- init() -------------- */
 void init(void) {
     //wolfSSL_Init();
 
     flash_simple_init();
     flash_simple_read(FLASH_STATUS_ADDR, &decoder_status, sizeof(decoder_status));
 
     if (decoder_status.first_boot != FLASH_FIRST_BOOT) {
         print_debug("First boot. Setting flash...\n");
         decoder_status.first_boot = FLASH_FIRST_BOOT;
         for (int i=0; i<MAX_CHANNEL_COUNT; i++){
             decoder_status.subscribed_channels[i].active = false;
             decoder_status.subscribed_channels[i].start_timestamp = DEFAULT_CHANNEL_TIMESTAMP;
             decoder_status.subscribed_channels[i].end_timestamp   = DEFAULT_CHANNEL_TIMESTAMP;
         }
         flash_simple_erase_page(FLASH_STATUS_ADDR);
         flash_simple_write(FLASH_STATUS_ADDR, &decoder_status, sizeof(decoder_status));
     }
 
     int ret = uart_init();
     if (ret<0) {
         STATUS_LED_ERROR();
         while(1){}
     }
 
     // cargar "secure_decoder.json" => channel_keys, etc.
     if (load_secure_keys()!=0) {
         STATUS_LED_ERROR();
         print_error("Load secure keys error\n");
         while(1){}
     }
 }
 
 /* -------------- MAIN -------------- */
 int main(void) {
     init();
     print_debug("Decoder Booted!\n");
 
     uint8_t  uart_buf[1024];
     msg_type_t cmd;
     int result;
     uint16_t pkt_len;
 
     while(1) {
         print_debug("Ready\n");
         STATUS_LED_GREEN();
 
         result = read_packet(&cmd, uart_buf, &pkt_len);
         if (result<0) {
             STATUS_LED_ERROR();
             print_error("Failed to receive cmd from host\n");
             continue;
         }
 
         switch(cmd) {
         case LIST_MSG:
             STATUS_LED_CYAN();
             boot_flag();
             list_channels();
             break;
         case DECODE_MSG:
             STATUS_LED_PURPLE();
             decode(pkt_len, uart_buf);
             break;
         case SUBSCRIBE_MSG:
             STATUS_LED_YELLOW();
             update_subscription(pkt_len, (subscription_update_packet_t*)uart_buf);
             break;
         default:
             STATUS_LED_ERROR();
             print_error("Invalid Command\n");
             break;
         }
     }
     return 0;
 } 
