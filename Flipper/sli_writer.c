// sli_writer.c
// Writes Magic ISO15693 SLI / SLIX-L / Special cards from a Flipper .nfc file.
//
// Three write modes:
//   Normal  — non-addressed write, then UID via 0x40/0x41
//   SaveUID — inventory only, save detected UID as canonical "special (factory) UID"
//   Special — restore factory UID, write blocks addressed (flags=0x62), set target UID
//
// Special card write sequence:
//   1. magic_write_uid(factory_uid)  — restore factory UID so blocks are writable
//   2. write_blocks_addressed()      — flags=0x62 (high rate + addressed + option)
//   3. magic_write_uid(target_uid)   — set the UID from the .nfc file
//
// UID Byte Order:
//   All UIDs in memory (detected_uid, special_uid, nfc_data.uid) are in canonical MSB-first order,
//   matching Flipper's iso15693_3_poller_inventory() return value and .nfc file format.
//   Reversal to wire order (LSB-first) is performed only during raw frame serialization.

#include "sli_writer.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <notification/notification.h>
#include <notification/notification_messages.h>

#define TAG "SLI_Writer"

/* ============================================================================
 *  ISO15693 / Magic command constants
 * ========================================================================== */

#define ISO15693_CMD_WRITE_BLOCK  0x21
#define ISO15693_CMD_READ_BLOCK   0x20
#define ISO15693_CMD_SELECT       0x25
#define ISO15693_CMD_RESET_READY  0x26

/* Gen2 magic UID commands (Proxmark: hf 15 csetuid --v2)
 *   HIGH: 02 E0 09 40 uid[7..4]
 *   LOW:  02 E0 09 41 uid[3..0] */
#define SLI_MAGIC_SET_UID_HIGH  0x40
#define SLI_MAGIC_SET_UID_LOW   0x41

/* FWT in carrier cycles — 500000 fc ≈ 37ms */
#define ISO15693_FWT_FC  500000

/* ============================================================================
 *  LED notification sequences
 * ========================================================================== */

static const NotificationSequence seq_blink_start = {
    &message_blue_255, &message_delay_50, &message_blue_0, NULL,
};
static const NotificationSequence seq_success = {
    &message_green_255, &message_delay_100, &message_green_0,
    &message_delay_50,
    &message_green_255, &message_delay_100, &message_green_0,
    NULL,
};
static const NotificationSequence seq_error = {
    &message_red_255, &message_delay_100, &message_red_0, NULL,
};

/* ============================================================================
 *  BitBuffer & Wire-Order Serialization Helpers
 * ========================================================================== */

/* All UID arguments and stored values in the application are MSB-first.
 * ISO15693 over-the-air frames require wire-order (LSB-first) bytes. */
static void append_uid_wire_order(BitBuffer* tx, const uint8_t uid_msb[8]) {
    for(size_t i = 0; i < 8; ++i) {
        bit_buffer_append_byte(tx, uid_msb[7 - i]);
    }
}

static BitBuffer* bb_alloc_from(const uint8_t* data, size_t len) {
    BitBuffer* bb = bit_buffer_alloc(len * 8);
    if(!bb) return NULL;
    bit_buffer_reset(bb);
    if(data && len) bit_buffer_append_bytes(bb, data, len);
    return bb;
}

static BitBuffer* bb_alloc_rx(size_t max_bytes) {
    BitBuffer* bb = bit_buffer_alloc(max_bytes * 8);
    if(!bb) return NULL;
    bit_buffer_set_size(bb, 0);
    return bb;
}

static bool iso_reply_ok(BitBuffer* rx) {
    if(bit_buffer_get_size_bytes(rx) < 1) return false;
    return (bit_buffer_get_byte(rx, 0) & 0x01) == 0;
}

static bool iso_send_raw(
    Iso15693_3Poller* iso,
    const uint8_t* frame,
    size_t frame_len,
    uint32_t fwt_fc)
{
    BitBuffer* tx = bb_alloc_from(frame, frame_len);
    if(!tx) return false;
    BitBuffer* rx = bb_alloc_rx(16);
    if(!rx) {
        bit_buffer_free(tx);
        return false;
    }

    Iso15693_3Error err = iso15693_3_poller_send_frame(
        iso, tx, rx, fwt_fc ? fwt_fc : ISO15693_FWT_FC);
    bool ok = (err == Iso15693_3ErrorNone) && iso_reply_ok(rx);

    if(!ok) {
        size_t rxsz = bit_buffer_get_size_bytes(rx);
        if(rxsz >= 2)
            FURI_LOG_W(TAG, "iso_send_raw: err=%d rxbytes=%u resp=[%02X %02X]",
                       (int)err, (unsigned)rxsz,
                       bit_buffer_get_byte(rx, 0), bit_buffer_get_byte(rx, 1));
        else
            FURI_LOG_W(TAG, "iso_send_raw: err=%d rxbytes=%u", (int)err, (unsigned)rxsz);
    }
    bit_buffer_free(tx);
    bit_buffer_free(rx);
    return ok;
}

/* ============================================================================
 *  Reset card to Ready state helper
 *  Observed device-specific requirement for magic tags to transition from
 *  addressed block writes back to Ready state before vendor UID commands.
 *  If expected_uid_msb is provided, verifies that the expected card is active.
 * ========================================================================== */

static bool reset_card_to_ready(Iso15693_3Poller* iso, const uint8_t expected_uid_msb[8]) {
    /* 1. Addressed Reset to Ready (0x22 0x26 <UID 8 bytes wire order>) */
    if(expected_uid_msb) {
        BitBuffer* tx = bit_buffer_alloc(10 * 8);
        if(tx) {
            bit_buffer_append_byte(tx, 0x22); /* High data rate + Addressed */
            bit_buffer_append_byte(tx, ISO15693_CMD_RESET_READY);
            append_uid_wire_order(tx, expected_uid_msb);
            BitBuffer* rx = bb_alloc_rx(4);
            if(rx) {
                iso15693_3_poller_send_frame(iso, tx, rx, ISO15693_FWT_FC);
                bit_buffer_free(rx);
            }
            bit_buffer_free(tx);
        }
        furi_delay_ms(20);
    }

    /* 2. Non-addressed Reset to Ready (0x02 0x26) */
    uint8_t frame_non_addressed[2] = {0x02, ISO15693_CMD_RESET_READY};
    iso_send_raw(iso, frame_non_addressed, sizeof(frame_non_addressed), ISO15693_FWT_FC);
    furi_delay_ms(20);

    /* 3. Run inventory to ensure card is active in field and in Ready state */
    uint8_t resync_uid_msb[8];
    for(int i = 0; i < 5; i++) {
        if(iso15693_3_poller_inventory(iso, resync_uid_msb) == Iso15693_3ErrorNone) {
            if(expected_uid_msb) {
                if(memcmp(resync_uid_msb, expected_uid_msb, 8) == 0) {
                    FURI_LOG_I(TAG, "Card reset to ready and verified UID: %02X%02X%02X%02X%02X%02X%02X%02X",
                               resync_uid_msb[0], resync_uid_msb[1], resync_uid_msb[2], resync_uid_msb[3],
                               resync_uid_msb[4], resync_uid_msb[5], resync_uid_msb[6], resync_uid_msb[7]);
                    return true;
                }
                FURI_LOG_W(TAG, "Card reset to ready: UID mismatch, retrying resync...");
            } else {
                FURI_LOG_I(TAG, "Card reset to ready, UID: %02X%02X%02X%02X%02X%02X%02X%02X",
                           resync_uid_msb[0], resync_uid_msb[1], resync_uid_msb[2], resync_uid_msb[3],
                           resync_uid_msb[4], resync_uid_msb[5], resync_uid_msb[6], resync_uid_msb[7]);
                return true;
            }
        }
        furi_delay_ms(25);
    }
    FURI_LOG_W(TAG, "Card inventory resync failed after reset_to_ready");
    return false;
}

/* ============================================================================
 *  Magic UID write (non-addressed, used for both Normal and Special modes)
 * ========================================================================== */

static WriteResult magic_write_uid(Iso15693_3Poller* iso, const uint8_t uid_msb[8]) {
    /* HIGH: sets bytes 4..7 in MSB / bytes 0..3 on wire */
    uint8_t frame_high[8] = {
        0x02, 0xE0, 0x09, SLI_MAGIC_SET_UID_HIGH,
        uid_msb[7], uid_msb[6], uid_msb[5], uid_msb[4],
    };
    /* LOW: sets bytes 0..3 in MSB / bytes 4..7 on wire */
    uint8_t frame_low[8] = {
        0x02, 0xE0, 0x09, SLI_MAGIC_SET_UID_LOW,
        uid_msb[3], uid_msb[2], uid_msb[1], uid_msb[0],
    };

    FURI_LOG_I(TAG, "magic_write_uid HIGH: %02X%02X%02X%02X",
               uid_msb[0], uid_msb[1], uid_msb[2], uid_msb[3]);
    bool ok_high = false;
    for(int i = 0; i < 5; i++) {
        if(iso_send_raw(iso, frame_high, sizeof(frame_high), 1000000)) {
            ok_high = true;
            break;
        }
        furi_delay_ms(25);
    }

    furi_delay_ms(50);

    FURI_LOG_I(TAG, "magic_write_uid LOW:  %02X%02X%02X%02X",
               uid_msb[4], uid_msb[5], uid_msb[6], uid_msb[7]);
    bool ok_low = false;
    for(int i = 0; i < 5; i++) {
        if(iso_send_raw(iso, frame_low, sizeof(frame_low), 1000000)) {
            ok_low = true;
            break;
        }
        furi_delay_ms(25);
    }

    /* Verification inventory: fail-closed readback */
    furi_delay_ms(50);
    uint8_t actual_uid_msb[8];
    bool readback_received = false;

    for(unsigned attempt = 0; attempt < 5; ++attempt) {
        Iso15693_3Error err = iso15693_3_poller_inventory(iso, actual_uid_msb);
        if(err == Iso15693_3ErrorNone) {
            readback_received = true;
            if(memcmp(actual_uid_msb, uid_msb, sizeof(actual_uid_msb)) == 0) {
                FURI_LOG_I(TAG, "Post-write UID verified: %02X%02X%02X%02X%02X%02X%02X%02X",
                           actual_uid_msb[0], actual_uid_msb[1], actual_uid_msb[2], actual_uid_msb[3],
                           actual_uid_msb[4], actual_uid_msb[5], actual_uid_msb[6], actual_uid_msb[7]);
                return WriteResultOk;
            }
            FURI_LOG_W(TAG, "UID mismatch: got %02X%02X%02X%02X%02X%02X%02X%02X expected %02X%02X%02X%02X%02X%02X%02X%02X",
                       actual_uid_msb[0], actual_uid_msb[1], actual_uid_msb[2], actual_uid_msb[3],
                       actual_uid_msb[4], actual_uid_msb[5], actual_uid_msb[6], actual_uid_msb[7],
                       uid_msb[0], uid_msb[1], uid_msb[2], uid_msb[3],
                       uid_msb[4], uid_msb[5], uid_msb[6], uid_msb[7]);
        }
        if(attempt + 1 < 5) {
            furi_delay_ms(25);
        }
    }

    if(!ok_high || !ok_low) {
        FURI_LOG_E(TAG, "SET_UID command failed (high=%d, low=%d)", ok_high, ok_low);
        return WriteResultUidCmdFailed;
    }

    if(!readback_received) {
        FURI_LOG_E(TAG, "UID readback unavailable");
        return WriteResultUidReadbackUnavailable;
    }

    FURI_LOG_E(TAG, "UID verification failed: UID mismatch");
    return WriteResultUidMismatch;
}

/* ============================================================================
 *  SELECT helper (puts card in selected state, non-fatal if no response)
 * ========================================================================== */

static void select_card(Iso15693_3Poller* iso, const uint8_t uid_msb[8]) {
    BitBuffer* tx = bit_buffer_alloc(10 * 8);
    if(!tx) return;
    bit_buffer_append_byte(tx, 0x22);  /* high rate + addressed */
    bit_buffer_append_byte(tx, ISO15693_CMD_SELECT);
    append_uid_wire_order(tx, uid_msb);

    BitBuffer* rx = bb_alloc_rx(4);
    if(rx) {
        Iso15693_3Error err = iso15693_3_poller_send_frame(iso, tx, rx, ISO15693_FWT_FC);
        FURI_LOG_I(TAG, "SELECT resp: err=%d rxbytes=%u",
                   (int)err, (unsigned)bit_buffer_get_size_bytes(rx));
        bit_buffer_free(rx);
    }
    bit_buffer_free(tx);
}

/* ============================================================================
 *  Normal block read helper (non-addressed, flags=0x02)
 * ========================================================================== */

static bool read_block(Iso15693_3Poller* iso, uint8_t block_number, uint8_t data[4]) {
    uint8_t frame[3];
    frame[0] = 0x02; /* High data rate */
    frame[1] = ISO15693_CMD_READ_BLOCK;
    frame[2] = block_number;

    BitBuffer* tx = bb_alloc_from(frame, sizeof(frame));
    if(!tx) return false;
    BitBuffer* rx = bb_alloc_rx(16);
    if(!rx) {
        bit_buffer_free(tx);
        return false;
    }

    Iso15693_3Error err = iso15693_3_poller_send_frame(iso, tx, rx, ISO15693_FWT_FC);
    bool ok = (err == Iso15693_3ErrorNone) && iso_reply_ok(rx);
    size_t rxsz = bit_buffer_get_size_bytes(rx);

    if(ok && rxsz >= 5) {
        for(size_t i = 0; i < 4; i++) {
            data[i] = bit_buffer_get_byte(rx, 1 + i);
        }
    } else {
        ok = false;
    }

    bit_buffer_free(tx);
    bit_buffer_free(rx);
    return ok;
}

/* ============================================================================
 *  Normal block write (non-addressed, flags=0x02, auto-retry with 0x42)
 * ========================================================================== */

static WriteResult write_blocks(
    Iso15693_3Poller* iso,
    const uint8_t* data,
    uint8_t block_count,
    uint8_t block_size)
{
    if(block_size == 0 || block_size > 4) block_size = 4;
    size_t blocks = (block_count > SLI_MAGIC_MAX_BLOCKS) ? SLI_MAGIC_MAX_BLOCKS : block_count;

    FURI_LOG_I(TAG, "write_blocks: %u blocks x %u bytes (non-addressed)", (unsigned)blocks, (unsigned)block_size);

    for(size_t b = 0; b < blocks; b++) {
        uint8_t wframe[7];
        wframe[0] = 0x02;
        wframe[1] = ISO15693_CMD_WRITE_BLOCK;
        wframe[2] = (uint8_t)b;
        memcpy(&wframe[3], &data[b * block_size], block_size);
        if(block_size < 4) memset(&wframe[3 + block_size], 0x00, 4 - block_size);

        bool wrote = false;
        for(int attempt = 0; attempt < 5 && !wrote; attempt++) {
            wrote = iso_send_raw(iso, wframe, sizeof(wframe), ISO15693_FWT_FC);
            if(!wrote) {
                if(wframe[0] == 0x02) {
                    FURI_LOG_W(TAG, "Block %u: retrying with Option flag (0x42)", (unsigned)b);
                    wframe[0] = 0x42;
                }
                furi_delay_ms(20);
            }
        }
        if(!wrote) {
            FURI_LOG_E(TAG, "write_blocks: block %u failed", (unsigned)b);
            return WriteResultBlockWriteFailed;
        }
        furi_delay_ms(20);
    }

    /* Strict read-back verification: read every written block back and verify */
    FURI_LOG_I(TAG, "Verifying %u written blocks...", (unsigned)blocks);
    furi_delay_ms(30);

    for(size_t b = 0; b < blocks; b++) {
        uint8_t readback[4] = {0};
        bool verified_block = false;

        for(int attempt = 0; attempt < 5; attempt++) {
            if(read_block(iso, (uint8_t)b, readback)) {
                if(memcmp(readback, &data[b * block_size], block_size) == 0) {
                    verified_block = true;
                    break;
                }
                FURI_LOG_W(
                    TAG,
                    "Block %u readback mismatch (attempt %d): [%02X %02X %02X %02X] != [%02X %02X %02X %02X]",
                    (unsigned)b,
                    attempt,
                    readback[0], readback[1], readback[2], readback[3],
                    data[b * block_size],
                    data[b * block_size + 1],
                    data[b * block_size + 2],
                    data[b * block_size + 3]);
            }
            furi_delay_ms(20);
        }

        if(!verified_block) {
            FURI_LOG_E(TAG, "Block %u readback verification failed!", (unsigned)b);
            return WriteResultBlockVerifyFailed;
        }
    }

    FURI_LOG_I(TAG, "All %u blocks verified successfully!", (unsigned)blocks);
    return WriteResultOk;
}

/* ============================================================================
 *  Special block read helper (addressed, flags=0x22)
 * ========================================================================== */

static bool read_block_addressed(
    Iso15693_3Poller* iso,
    const uint8_t uid_msb[8],
    uint8_t block_number,
    uint8_t data[4])
{
    BitBuffer* tx = bit_buffer_alloc(11 * 8);
    if(!tx) return false;
    bit_buffer_append_byte(tx, 0x22); /* High data rate + Addressed */
    bit_buffer_append_byte(tx, ISO15693_CMD_READ_BLOCK);
    append_uid_wire_order(tx, uid_msb);
    bit_buffer_append_byte(tx, block_number);

    BitBuffer* rx = bb_alloc_rx(16);
    if(!rx) {
        bit_buffer_free(tx);
        return false;
    }

    Iso15693_3Error err = iso15693_3_poller_send_frame(iso, tx, rx, ISO15693_FWT_FC);
    bool ok = (err == Iso15693_3ErrorNone) && iso_reply_ok(rx);
    size_t rxsz = bit_buffer_get_size_bytes(rx);

    if(ok && rxsz >= 5) {
        for(size_t i = 0; i < 4; i++) {
            data[i] = bit_buffer_get_byte(rx, 1 + i);
        }
    } else {
        ok = false;
    }

    bit_buffer_free(tx);
    bit_buffer_free(rx);
    return ok;
}

/* ============================================================================
 *  Special block write (addressed + option, flags=0x62)
 *  flags=0x62: high data rate(0x02) + addressed(0x20) + option(0x40)
 * ========================================================================== */

static WriteResult write_blocks_addressed(
    Iso15693_3Poller* iso,
    const uint8_t uid_msb[8],
    const uint8_t* data,
    uint8_t block_count,
    uint8_t block_size)
{
    if(block_size == 0 || block_size > 4) block_size = 4;
    size_t blocks = (block_count > SLI_MAGIC_MAX_BLOCKS) ? SLI_MAGIC_MAX_BLOCKS : block_count;

    FURI_LOG_I(TAG, "write_blocks_addressed: %u blocks (flags=0x62)", (unsigned)blocks);

    for(size_t b = 0; b < blocks; b++) {
        BitBuffer* tx = bit_buffer_alloc(15 * 8);
        if(!tx) return WriteResultBlockWriteFailed;
        bit_buffer_append_byte(tx, 0x62);
        bit_buffer_append_byte(tx, ISO15693_CMD_WRITE_BLOCK);
        append_uid_wire_order(tx, uid_msb);
        bit_buffer_append_byte(tx, (uint8_t)b);
        bit_buffer_append_bytes(tx, &data[b * block_size], block_size);
        if(block_size < 4) {
            for(size_t pad = 0; pad < (size_t)(4 - block_size); pad++) {
                bit_buffer_append_byte(tx, 0x00);
            }
        }

        BitBuffer* rx = bb_alloc_rx(16);
        if(!rx) {
            bit_buffer_free(tx);
            return WriteResultBlockWriteFailed;
        }

        /* Extended FWT for Option flag (2-phase response) */
        Iso15693_3Error err = iso15693_3_poller_send_frame(iso, tx, rx, 2000000);
        size_t rxsz = bit_buffer_get_size_bytes(rx);

        FURI_LOG_I(TAG, "  block %u: err=%d rxbytes=%u", (unsigned)b, (int)err, (unsigned)rxsz);
        if(rxsz >= 2)
            FURI_LOG_I(TAG, "  resp=[%02X %02X]",
                       bit_buffer_get_byte(rx, 0), bit_buffer_get_byte(rx, 1));

        /* Fail on explicit card error response (bit0=1 in flags byte) */
        bool card_error = (rxsz >= 1) && ((bit_buffer_get_byte(rx, 0) & 0x01) != 0);

        bit_buffer_free(tx);
        bit_buffer_free(rx);

        if(card_error) {
            FURI_LOG_E(TAG, "Block %u: card error", (unsigned)b);
            return WriteResultBlockWriteFailed;
        }

        furi_delay_ms(25);
    }

    /* Strict read-back verification: read every written block back and verify */
    FURI_LOG_I(TAG, "Verifying %u written blocks...", (unsigned)blocks);
    furi_delay_ms(30);

    for(size_t b = 0; b < blocks; b++) {
        uint8_t readback[4] = {0};
        bool verified_block = false;

        for(int attempt = 0; attempt < 5; attempt++) {
            if(read_block_addressed(iso, uid_msb, (uint8_t)b, readback)) {
                if(memcmp(readback, &data[b * block_size], block_size) == 0) {
                    verified_block = true;
                    break;
                }
                FURI_LOG_W(
                    TAG,
                    "Block %u readback mismatch (attempt %d): [%02X %02X %02X %02X] != [%02X %02X %02X %02X]",
                    (unsigned)b,
                    attempt,
                    readback[0], readback[1], readback[2], readback[3],
                    data[b * block_size],
                    data[b * block_size + 1],
                    data[b * block_size + 2],
                    data[b * block_size + 3]);
            }
            furi_delay_ms(20);
        }

        if(!verified_block) {
            FURI_LOG_E(TAG, "Block %u readback verification failed!", (unsigned)b);
            return WriteResultBlockVerifyFailed;
        }
    }

    FURI_LOG_I(TAG, "All %u blocks verified successfully!", (unsigned)blocks);
    return WriteResultOk;
}

/* ============================================================================
 *  Persistent special UID storage
 * ========================================================================== */

bool sli_writer_save_special_uid(SliWriterApp* app) {
    storage_common_mkdir(app->storage, "/ext/apps_data/sli_writer");

    File* f = storage_file_alloc(app->storage);
    bool ok = false;
    if(storage_file_open(f, SLI_SPECIAL_UID_PATH, FSAM_WRITE, FSOM_CREATE_ALWAYS)) {
        ok = (storage_file_write(f, app->special_uid, 8) == 8);
        storage_file_close(f);
    }
    storage_file_free(f);
    if(ok) FURI_LOG_I(TAG, "Special UID saved: %02X%02X%02X%02X%02X%02X%02X%02X",
                      app->special_uid[0], app->special_uid[1],
                      app->special_uid[2], app->special_uid[3],
                      app->special_uid[4], app->special_uid[5],
                      app->special_uid[6], app->special_uid[7]);
    else   FURI_LOG_E(TAG, "Special UID save failed");
    return ok;
}

bool sli_writer_load_special_uid(SliWriterApp* app) {
    File* f = storage_file_alloc(app->storage);
    bool ok = false;
    if(storage_file_open(f, SLI_SPECIAL_UID_PATH, FSAM_READ, FSOM_OPEN_EXISTING)) {
        ok = (storage_file_read(f, app->special_uid, 8) == 8);
        storage_file_close(f);
    }
    storage_file_free(f);
    if(ok) {
        app->special_uid_saved = true;
        FURI_LOG_I(TAG, "Special UID loaded: %02X%02X%02X%02X%02X%02X%02X%02X",
                   app->special_uid[0], app->special_uid[1],
                   app->special_uid[2], app->special_uid[3],
                   app->special_uid[4], app->special_uid[5],
                   app->special_uid[6], app->special_uid[7]);
    }
    return ok;
}

/* ============================================================================
 *  .nfc file parser
 * ========================================================================== */

bool sli_writer_parse_nfc_file(SliWriterApp* app, const char* path) {
    File* f = storage_file_alloc(app->storage);
    bool ok = false;

    memset(&app->nfc_data, 0x00, sizeof(app->nfc_data));
    furi_string_reset(app->error_message);

    if(storage_file_open(f, path, FSAM_READ, FSOM_OPEN_EXISTING)) {
        size_t sz = storage_file_size(f);
        char* buf = malloc(sz + 1);
        if(buf) {
            size_t n = storage_file_read(f, buf, sz);
            buf[n] = '\0';

            char* p;
            size_t uid_count = 0;

            if((p = strstr(buf, "UID: "))) {
                p += 5;
                char* q = p;
                for(int i = 0; i < 8; i++) {
                    while(*q == ' ') q++;
                    char* end = NULL;
                    long val = strtol(q, &end, 16);
                    if(end == q || val < 0 || val > 0xFF) break;
                    app->nfc_data.uid[i] = (uint8_t)val;
                    q = end;
                    uid_count++;
                }
            }

            if((p = strstr(buf, "Block Count: "))) {
                char* end = NULL;
                long val = strtol(p + 13, &end, 0);
                if(val > 0 && val <= SLI_MAGIC_MAX_BLOCKS) {
                    app->nfc_data.block_count = (uint8_t)val;
                }
            }

            if((p = strstr(buf, "Block Size: "))) {
                char* end = NULL;
                long val = strtol(p + 12, &end, 0);
                if(val > 0 && val <= 255) {
                    app->nfc_data.block_size = (uint8_t)val;
                }
            }

            size_t data_bytes_parsed = 0;
            size_t expected_total = (size_t)app->nfc_data.block_count * app->nfc_data.block_size;

            if(expected_total > 0 && expected_total <= sizeof(app->nfc_data.data)) {
                if((p = strstr(buf, "Data Content: "))) {
                    p += 14;
                    char* q2 = p;
                    for(size_t i = 0; i < expected_total; i++) {
                        while(*q2 == ' ' || *q2 == '\r' || *q2 == '\n' || *q2 == '\t') q2++;
                        if(*q2 == '\0') break;
                        char* end2 = NULL;
                        long val = strtol(q2, &end2, 16);
                        if(end2 == q2 || val < 0 || val > 0xFF) break;
                        app->nfc_data.data[i] = (uint8_t)val;
                        q2 = end2;
                        data_bytes_parsed++;
                    }
                }
            }

            /* Strict validation to prevent partial / zero-filled data from reaching writer:
             * 1. Exact 8-byte UID
             * 2. block_count between 1 and SLI_MAGIC_MAX_BLOCKS
             * 3. block_size == 4
             * 4. Data Content contains exactly block_count * block_size valid bytes */
            if(uid_count != 8) {
                furi_string_set(app->error_message, "Invalid UID in .nfc");
                FURI_LOG_E(TAG, "Parse error: expected 8 UID bytes, found %u", (unsigned)uid_count);
            } else if(app->nfc_data.block_count == 0 || app->nfc_data.block_count > SLI_MAGIC_MAX_BLOCKS) {
                furi_string_set(app->error_message, "Invalid block count in .nfc");
                FURI_LOG_E(TAG, "Parse error: invalid block count %u", (unsigned)app->nfc_data.block_count);
            } else if(app->nfc_data.block_size != 4) {
                furi_string_set(app->error_message, "Invalid block size (must be 4)");
                FURI_LOG_E(TAG, "Parse error: unsupported block size %u", (unsigned)app->nfc_data.block_size);
            } else if(data_bytes_parsed != expected_total) {
                furi_string_set(app->error_message, "Incomplete data in .nfc file");
                FURI_LOG_E(TAG, "Parse error: incomplete data %u / %u bytes",
                           (unsigned)data_bytes_parsed, (unsigned)expected_total);
            } else {
                FURI_LOG_I(TAG, "Parsed valid .nfc: blocks=%u size=%u uid=%02X%02X%02X%02X%02X%02X%02X%02X",
                           app->nfc_data.block_count, app->nfc_data.block_size,
                           app->nfc_data.uid[0], app->nfc_data.uid[1],
                           app->nfc_data.uid[2], app->nfc_data.uid[3],
                           app->nfc_data.uid[4], app->nfc_data.uid[5],
                           app->nfc_data.uid[6], app->nfc_data.uid[7]);
                ok = true;
            }

            free(buf);
        }
        storage_file_close(f);
    } else {
        furi_string_set(app->error_message, "Cannot open .nfc file");
    }
    storage_file_free(f);

    if(!ok) {
        memset(&app->nfc_data, 0x00, sizeof(app->nfc_data));
    }
    return ok;
}

/* ============================================================================
 *  Write operations
 * ========================================================================== */

/* Normal write: SELECT -> write blocks (non-addressed) -> write UID */
static WriteResult do_normal_write(SliWriterApp* app, Iso15693_3Poller* iso) {
    if(app->nfc_data.block_count == 0 || app->nfc_data.block_size != 4) {
        FURI_LOG_E(TAG, "Cannot write: invalid or incomplete NFC data");
        furi_string_set(app->error_message, "Incomplete NFC data");
        return WriteResultBlockWriteFailed;
    }

    select_card(iso, app->detected_uid);
    furi_delay_ms(10);

    FURI_LOG_I(TAG, "Normal write: %u blocks", app->nfc_data.block_count);
    WriteResult b_res = write_blocks(iso, app->nfc_data.data,
                                     app->nfc_data.block_count, app->nfc_data.block_size);
    if(b_res != WriteResultOk) {
        return b_res;
    }
    FURI_LOG_I(TAG, "Blocks OK");

    static const uint8_t zero_uid[8] = {0};
    if(memcmp(app->nfc_data.uid, zero_uid, 8) != 0 &&
       memcmp(app->nfc_data.uid, app->detected_uid, 8) != 0) {
        furi_delay_ms(30);
        if(!reset_card_to_ready(iso, NULL)) {
            FURI_LOG_E(TAG, "Card not responding after data block write");
            return WriteResultCardLost;
        }
        furi_delay_ms(20);

        FURI_LOG_I(TAG, "Writing target UID...");
        WriteResult res = magic_write_uid(iso, app->nfc_data.uid);
        if(res != WriteResultOk) {
            return res;
        }
        FURI_LOG_I(TAG, "UID OK");
    } else {
        FURI_LOG_I(TAG, "UID skip (same or zero)");
    }
    return WriteResultOk;
}

/* Special write:
 *   1. Restore factory UID (so blocks become writable)
 *   2. Write blocks addressed (flags=0x62) using factory UID
 *   3. Set target UID from .nfc file */
static WriteResult do_special_write(SliWriterApp* app, Iso15693_3Poller* iso) {
    if(app->nfc_data.block_count == 0 || app->nfc_data.block_size != 4) {
        FURI_LOG_E(TAG, "Cannot write: invalid or incomplete NFC data");
        furi_string_set(app->error_message, "Incomplete NFC data");
        return WriteResultBlockWriteFailed;
    }

    FURI_LOG_I(TAG, "Special write: factory=%02X%02X.. target=%02X%02X..",
               app->special_uid[0], app->special_uid[1],
               app->nfc_data.uid[0], app->nfc_data.uid[1]);

    /* Step 1: restore factory UID (skip if card already has factory UID) */
    bool already_factory = (memcmp(app->detected_uid, app->special_uid, 8) == 0);
    if(already_factory) {
        FURI_LOG_I(TAG, "Step 1: skip (card already has factory UID)");
    } else {
        FURI_LOG_I(TAG, "Step 1: restore factory UID");
        WriteResult res = magic_write_uid(iso, app->special_uid);
        if(res != WriteResultOk) {
            return res;
        }
        furi_delay_ms(50);
    }

    /* Require inventoried UID == factory UID before allowing any block writes */
    furi_delay_ms(50);
    uint8_t uid_resync[8];
    bool factory_uid_verified = false;
    for(int i = 0; i < 5; i++) {
        if(iso15693_3_poller_inventory(iso, uid_resync) == Iso15693_3ErrorNone) {
            if(memcmp(uid_resync, app->special_uid, 8) == 0) {
                factory_uid_verified = true;
                break;
            }
            FURI_LOG_W(TAG, "Factory UID mismatch in resync: expected %02X.. got %02X..",
                       app->special_uid[0], uid_resync[0]);
        }
        furi_delay_ms(25);
    }

    if(!factory_uid_verified) {
        FURI_LOG_E(TAG, "Card does not have factory UID active; aborting Special write");
        return WriteResultFactoryUidMismatch;
    }

    /* Step 2: write blocks addressed using factory UID */
    FURI_LOG_I(TAG, "Step 2: write blocks addressed (0x62)");
    WriteResult b_res = write_blocks_addressed(iso, app->special_uid,
                                               app->nfc_data.data,
                                               app->nfc_data.block_count,
                                               app->nfc_data.block_size);
    if(b_res != WriteResultOk) {
        return b_res;
    }
    FURI_LOG_I(TAG, "Blocks OK");

    /* Wait for card EEPROM write to settle after block writes */
    furi_delay_ms(100);

    /* Observed device-specific requirement: reset card to Ready state before vendor UID commands */
    FURI_LOG_I(TAG, "Resynchronizing card to ready state before UID write...");
    if(!reset_card_to_ready(iso, app->special_uid)) {
        FURI_LOG_E(TAG, "Card not responding or UID mismatch after block write");
        return WriteResultCardLost;
    }
    furi_delay_ms(30);

    /* Step 3: set target UID */
    static const uint8_t zero_uid[8] = {0};
    if(memcmp(app->nfc_data.uid, zero_uid, 8) != 0 &&
       memcmp(app->nfc_data.uid, app->special_uid, 8) != 0) {
        FURI_LOG_I(TAG, "Step 3: write target UID");
        WriteResult res = magic_write_uid(iso, app->nfc_data.uid);
        if(res != WriteResultOk) {
            return res;
        }
        FURI_LOG_I(TAG, "Target UID OK");
    } else {
        FURI_LOG_I(TAG, "Step 3: UID skip (same as factory or zero)");
    }
    return WriteResultOk;
}

static const char* write_result_get_message(WriteResult result) {
    switch(result) {
    case WriteResultOk:
        return "Success";
    case WriteResultTagInventoryFailed:
        return "Card inventory failed";
    case WriteResultBlockWriteFailed:
        return "Block write failed";
    case WriteResultBlockVerifyFailed:
        return "Block verification failed";
    case WriteResultCardLost:
        return "Card lost during write";
    case WriteResultFactoryUidMismatch:
        return "Factory UID mismatch";
    case WriteResultUidCmdFailed:
        return "UID write command failed";
    case WriteResultUidReadbackUnavailable:
        return "Card lost during UID verify";
    case WriteResultUidMismatch:
        return "UID verify mismatch";
    case WriteResultSaveUidFailed:
        return "Failed to save UID to SD";
    default:
        return "Write failed";
    }
}

/* ============================================================================
 *  UI Helpers
 * ========================================================================== */

static void prepare_dialog(SliWriterApp* app) {
    dialog_ex_reset(app->dialog_ex);
    dialog_ex_set_context(app->dialog_ex, app);
    dialog_ex_set_result_callback(app->dialog_ex, sli_writer_dialog_ex_callback);
}

static void show_message(SliWriterApp* app, const char* title, const char* message) {
    prepare_dialog(app);
    dialog_ex_set_header(app->dialog_ex, title, 64, 0, AlignCenter, AlignTop);
    dialog_ex_set_text(app->dialog_ex, message, 64, 32, AlignCenter, AlignCenter);
    dialog_ex_set_left_button_text(app->dialog_ex, "Back");
    dialog_ex_set_center_button_text(app->dialog_ex, "OK");
    view_dispatcher_switch_to_view(app->view_dispatcher, SliWriterViewDialogEx);
}

/* ============================================================================
 *  NFC poller callback
 * ========================================================================== */

static NfcCommand sli_poller_callback(NfcGenericEvent event, void* context) {
    SliWriterApp* app = context;

    if(event.protocol != NfcProtocolIso15693_3)
        return NfcCommandContinue;

    Iso15693_3PollerEvent* iso_event = event.event_data;
    if(iso_event->type != Iso15693_3PollerEventTypeReady)
        return NfcCommandContinue;

    Iso15693_3Poller* iso = event.instance;
    app->is_writing = true;
    view_dispatcher_send_custom_event(app->view_dispatcher, SliWriterCustomEventWriteStarted);

    uint8_t inventory_uid[8];
    Iso15693_3Error uid_err = iso15693_3_poller_inventory(iso, inventory_uid);
    if(uid_err != Iso15693_3ErrorNone) {
        FURI_LOG_E(TAG, "Inventory failed: err=%d", (int)uid_err);
        app->write_result = WriteResultTagInventoryFailed;
        goto done;
    }

    memcpy(app->detected_uid, inventory_uid, 8);
    app->have_uid = true;
    FURI_LOG_I(TAG, "Card UID: %02X%02X%02X%02X%02X%02X%02X%02X",
               app->detected_uid[0], app->detected_uid[1],
               app->detected_uid[2], app->detected_uid[3],
               app->detected_uid[4], app->detected_uid[5],
               app->detected_uid[6], app->detected_uid[7]);
    furi_delay_ms(20);

    switch(app->write_mode) {
    case SliWriterModeSaveUid:
        memcpy(app->special_uid, app->detected_uid, 8);
        app->special_uid_saved = true;
        if(sli_writer_save_special_uid(app)) {
            app->write_result = WriteResultOk;
        } else {
            app->write_result = WriteResultSaveUidFailed;
        }
        break;
    case SliWriterModeSpecial:
        app->write_result = do_special_write(app, iso);
        break;
    case SliWriterModeNormal:
    default:
        app->write_result = do_normal_write(app, iso);
        break;
    }

done:;
    NotificationApp* notif = furi_record_open(RECORD_NOTIFICATION);
    if(app->write_result == WriteResultOk) {
        notification_message(notif, &seq_success);
    } else {
        notification_message(notif, &seq_error);
    }
    furi_record_close(RECORD_NOTIFICATION);

    view_dispatcher_send_custom_event(app->view_dispatcher, SliWriterCustomEventWriteDone);
    return NfcCommandStop;
}

/* ============================================================================
 *  UI Callbacks
 * ========================================================================== */

void sli_writer_submenu_callback(void* context, uint32_t index) {
    SliWriterApp* app = context;
    view_dispatcher_send_custom_event(app->view_dispatcher, index);
}

void sli_writer_dialog_ex_callback(DialogExResult result, void* context) {
    SliWriterApp* app = context;
    view_dispatcher_send_custom_event(app->view_dispatcher, SLI_DIALOG_RESULT_OFFSET + result);
}

bool sli_writer_custom_event_callback(void* context, uint32_t event) {
    SliWriterApp* app = context;
    return scene_manager_handle_custom_event(app->scene_manager, event);
}

bool sli_writer_back_event_callback(void* context) {
    SliWriterApp* app = context;
    return scene_manager_handle_back_event(app->scene_manager);
}

/* ============================================================================
 *  Scenes
 * ========================================================================== */

/* --- Start --- */
void sli_writer_scene_start_on_enter(void* context) {
    SliWriterApp* app = context;
    app->in_about = false;
    submenu_reset(app->submenu);

    submenu_add_item(app->submenu, "Write NFC File",
        SliWriterSubmenuIndexWrite, sli_writer_submenu_callback, app);

    submenu_add_item(app->submenu, "Save Special UID",
        SliWriterSubmenuIndexSaveUid, sli_writer_submenu_callback, app);

    /* Show saved special UID as a non-clickable info line */
    if(app->special_uid_saved) {
        char uid_info[48];
        snprintf(uid_info, sizeof(uid_info), "  > %02X %02X %02X %02X %02X %02X %02X %02X",
                 app->special_uid[0], app->special_uid[1],
                 app->special_uid[2], app->special_uid[3],
                 app->special_uid[4], app->special_uid[5],
                 app->special_uid[6], app->special_uid[7]);
        /* Index 99 — ignored by event handler, just visual info */
        submenu_add_item(app->submenu, uid_info, 99, sli_writer_submenu_callback, app);
    }

    submenu_add_item(
        app->submenu,
        app->special_uid_saved ? "Write Special" : "Write Special (no UID saved)",
        SliWriterSubmenuIndexWriteSpec, sli_writer_submenu_callback, app);

    submenu_add_item(app->submenu, "About",
        SliWriterSubmenuIndexAbout, sli_writer_submenu_callback, app);

    view_dispatcher_switch_to_view(app->view_dispatcher, SliWriterViewSubmenu);
}

bool sli_writer_scene_start_on_event(void* context, SceneManagerEvent event) {
    SliWriterApp* app = context;

    if(event.type == SceneManagerEventTypeBack) {
        if(app->in_about) {
            app->in_about = false;
            view_dispatcher_switch_to_view(app->view_dispatcher, SliWriterViewSubmenu);
            return true;
        }
        return false;
    }

    if(event.type != SceneManagerEventTypeCustom) return false;

    if(event.event >= SLI_DIALOG_RESULT_OFFSET) {
        if(app->in_about) {
            app->in_about = false;
            view_dispatcher_switch_to_view(app->view_dispatcher, SliWriterViewSubmenu);
            return true;
        }
    }

    if(event.event == SliWriterSubmenuIndexWrite) {
        app->write_mode = SliWriterModeNormal;
        scene_manager_next_scene(app->scene_manager, SliWriterSceneFileSelect);
        return true;
    }

    if(event.event == SliWriterSubmenuIndexSaveUid) {
        app->write_mode = SliWriterModeSaveUid;
        scene_manager_next_scene(app->scene_manager, SliWriterSceneWrite);
        return true;
    }

    if(event.event == SliWriterSubmenuIndexWriteSpec) {
        if(!app->special_uid_saved) {
            app->write_result = WriteResultUnknown;
            furi_string_set(app->error_message,
                "No special UID saved!\nUse 'Save Special UID' first.");
            scene_manager_next_scene(app->scene_manager, SliWriterSceneResult);
            return true;
        }
        app->write_mode = SliWriterModeSpecial;
        scene_manager_next_scene(app->scene_manager, SliWriterSceneFileSelect);
        return true;
    }

    if(event.event == SliWriterSubmenuIndexAbout) {
        app->in_about = true;
        show_message(app, "SLI Writer",
            "ISO15693 magic card writer\nSLI / SLIX-L / Special");
        return true;
    }
    return false;
}

void sli_writer_scene_start_on_exit(void* context) {
    SliWriterApp* app = context;
    app->in_about = false;
    submenu_reset(app->submenu);
}

/* --- File Select --- */
void sli_writer_scene_file_select_on_enter(void* context) {
    SliWriterApp* app = context;
    furi_string_set(app->file_path, "/ext/nfc");

    DialogsFileBrowserOptions opts;
    dialog_file_browser_set_basic_options(&opts, SLI_WRITER_FILE_EXTENSION, NULL);

    if(dialog_file_browser_show(app->dialogs, app->file_path, app->file_path, &opts)) {
        if(sli_writer_parse_nfc_file(app, furi_string_get_cstr(app->file_path))) {
            scene_manager_next_scene(app->scene_manager, SliWriterSceneWrite);
        } else {
            app->write_result = WriteResultUnknown;
            if(furi_string_size(app->error_message) == 0) {
                furi_string_set(app->error_message, "Cannot parse .nfc file");
            }
            scene_manager_next_scene(app->scene_manager, SliWriterSceneResult);
        }
    } else {
        scene_manager_previous_scene(app->scene_manager);
    }
}

bool sli_writer_scene_file_select_on_event(void* context, SceneManagerEvent event) {
    (void)context; (void)event;
    return false;
}

void sli_writer_scene_file_select_on_exit(void* context) {
    (void)context;
}

/* --- Write --- */
void sli_writer_scene_write_on_enter(void* context) {
    SliWriterApp* app = context;

    prepare_dialog(app);
    dialog_ex_set_header(app->dialog_ex, "SLI Writer", 64, 0, AlignCenter, AlignTop);

    if(app->write_mode == SliWriterModeSaveUid) {
        dialog_ex_set_text(app->dialog_ex, "Approach card\nto save UID...",
                           64, 32, AlignCenter, AlignCenter);
    } else {
        dialog_ex_set_text(app->dialog_ex, "Approach card\nto Flipper...",
                           64, 32, AlignCenter, AlignCenter);
    }
    dialog_ex_set_left_button_text(app->dialog_ex, "Back");
    view_dispatcher_switch_to_view(app->view_dispatcher, SliWriterViewDialogEx);

    NotificationApp* notif = furi_record_open(RECORD_NOTIFICATION);
    notification_message(notif, &seq_blink_start);
    furi_record_close(RECORD_NOTIFICATION);

    app->have_uid = false;
    app->is_writing = false;
    furi_string_reset(app->error_message);

    app->poller = nfc_poller_alloc(app->nfc, NfcProtocolIso15693_3);
    app->nfc_started = true;

    nfc_poller_start(app->poller, sli_poller_callback, app);
    FURI_LOG_I(TAG, "Poller started, mode=%d", (int)app->write_mode);
}

bool sli_writer_scene_write_on_event(void* context, SceneManagerEvent event) {
    SliWriterApp* app = context;

    if(event.type == SceneManagerEventTypeBack ||
       (event.type == SceneManagerEventTypeCustom &&
        event.event == (SLI_DIALOG_RESULT_OFFSET + DialogExResultLeft))) {
        /* Consume Back while write is in progress to prevent UI freeze and partial write */
        if(app->is_writing) {
            return true;
        }
        scene_manager_search_and_switch_to_previous_scene(
            app->scene_manager, SliWriterSceneStart);
        return true;
    }

    if(event.type == SceneManagerEventTypeCustom) {
        if(event.event == SliWriterCustomEventWriteStarted) {
            dialog_ex_set_text(app->dialog_ex, "Writing...\nDo not remove tag",
                               64, 32, AlignCenter, AlignCenter);
            dialog_ex_set_left_button_text(app->dialog_ex, NULL);
            return true;
        }
        if(event.event == SliWriterCustomEventWriteDone) {
            scene_manager_next_scene(app->scene_manager, SliWriterSceneResult);
            return true;
        }
    }
    return false;
}

void sli_writer_scene_write_on_exit(void* context) {
    SliWriterApp* app = context;
    app->is_writing = false;
    if(app->poller) {
        nfc_poller_stop(app->poller);
        nfc_poller_free(app->poller);
        app->poller      = NULL;
        app->nfc_started = false;
    }
}

/* --- Result (combines Success and Error scenes) --- */
void sli_writer_scene_result_on_enter(void* context) {
    SliWriterApp* app = context;

    if(app->write_result == WriteResultOk) {
        if(app->write_mode == SliWriterModeSaveUid) {
            char msg[64];
            snprintf(msg, sizeof(msg), "UID saved:\n%02X %02X %02X %02X\n%02X %02X %02X %02X",
                     app->special_uid[0], app->special_uid[1],
                     app->special_uid[2], app->special_uid[3],
                     app->special_uid[4], app->special_uid[5],
                     app->special_uid[6], app->special_uid[7]);
            show_message(app, "Success!", msg);
        } else {
            show_message(app, "Success!", "Card written successfully");
        }
    } else {
        const char* msg = (furi_string_size(app->error_message) > 0) ?
            furi_string_get_cstr(app->error_message) :
            write_result_get_message(app->write_result);
        show_message(app, "Error", msg);
    }
}

bool sli_writer_scene_result_on_event(void* context, SceneManagerEvent event) {
    SliWriterApp* app = context;
    if(event.type == SceneManagerEventTypeBack ||
       (event.type == SceneManagerEventTypeCustom && event.event >= SLI_DIALOG_RESULT_OFFSET)) {
        scene_manager_search_and_switch_to_previous_scene(
            app->scene_manager, SliWriterSceneStart);
        return true;
    }
    return false;
}

void sli_writer_scene_result_on_exit(void* context) {
    SliWriterApp* app = context;
    dialog_ex_reset(app->dialog_ex);
}

/* ============================================================================
 *  Scene manager dispatch tables
 * ========================================================================== */

static void (*const sli_scene_on_enter[])(void*) = {
    sli_writer_scene_start_on_enter,
    sli_writer_scene_file_select_on_enter,
    sli_writer_scene_write_on_enter,
    sli_writer_scene_result_on_enter,
};

static bool (*const sli_scene_on_event[])(void*, SceneManagerEvent) = {
    sli_writer_scene_start_on_event,
    sli_writer_scene_file_select_on_event,
    sli_writer_scene_write_on_event,
    sli_writer_scene_result_on_event,
};

static void (*const sli_scene_on_exit[])(void*) = {
    sli_writer_scene_start_on_exit,
    sli_writer_scene_file_select_on_exit,
    sli_writer_scene_write_on_exit,
    sli_writer_scene_result_on_exit,
};

static const SceneManagerHandlers sli_scene_handlers = {
    .on_enter_handlers = sli_scene_on_enter,
    .on_event_handlers = sli_scene_on_event,
    .on_exit_handlers  = sli_scene_on_exit,
    .scene_num         = SliWriterSceneNum,
};

/* ============================================================================
 *  App lifecycle
 * ========================================================================== */

SliWriterApp* sli_writer_app_alloc(void) {
    SliWriterApp* app = malloc(sizeof(SliWriterApp));
    furi_check(app);
    memset(app, 0x00, sizeof(SliWriterApp));

    app->gui     = furi_record_open(RECORD_GUI);
    app->storage = furi_record_open(RECORD_STORAGE);
    app->dialogs = furi_record_open(RECORD_DIALOGS);

    app->nfc = nfc_alloc();

    app->view_dispatcher = view_dispatcher_alloc();
    app->scene_manager   = scene_manager_alloc(&sli_scene_handlers, app);

    view_dispatcher_set_event_callback_context(app->view_dispatcher, app);
    view_dispatcher_set_custom_event_callback(app->view_dispatcher, sli_writer_custom_event_callback);
    view_dispatcher_set_navigation_event_callback(app->view_dispatcher, sli_writer_back_event_callback);

    app->submenu = submenu_alloc();
    view_dispatcher_add_view(app->view_dispatcher,
        SliWriterViewSubmenu, submenu_get_view(app->submenu));

    app->dialog_ex = dialog_ex_alloc();
    dialog_ex_set_context(app->dialog_ex, app);
    dialog_ex_set_result_callback(app->dialog_ex, sli_writer_dialog_ex_callback);
    view_dispatcher_add_view(app->view_dispatcher,
        SliWriterViewDialogEx, dialog_ex_get_view(app->dialog_ex));

    app->loading = loading_alloc();
    view_dispatcher_add_view(app->view_dispatcher,
        SliWriterViewLoading, loading_get_view(app->loading));

    app->file_path     = furi_string_alloc();
    app->error_message = furi_string_alloc();

    /* Load special UID from SD if it was previously saved */
    sli_writer_load_special_uid(app);

    view_dispatcher_attach_to_gui(app->view_dispatcher, app->gui, ViewDispatcherTypeFullscreen);
    scene_manager_next_scene(app->scene_manager, SliWriterSceneStart);

    return app;
}

void sli_writer_app_free(SliWriterApp* app) {
    furi_assert(app);

    if(app->poller) {
        nfc_poller_stop(app->poller);
        nfc_poller_free(app->poller);
        app->poller = NULL;
    }

    if(app->nfc) {
        nfc_free(app->nfc);
        app->nfc = NULL;
    }

    view_dispatcher_remove_view(app->view_dispatcher, SliWriterViewSubmenu);
    view_dispatcher_remove_view(app->view_dispatcher, SliWriterViewDialogEx);
    view_dispatcher_remove_view(app->view_dispatcher, SliWriterViewLoading);

    submenu_free(app->submenu);
    dialog_ex_free(app->dialog_ex);
    loading_free(app->loading);

    view_dispatcher_free(app->view_dispatcher);
    scene_manager_free(app->scene_manager);

    furi_string_free(app->file_path);
    furi_string_free(app->error_message);

    furi_record_close(RECORD_GUI);
    furi_record_close(RECORD_STORAGE);
    furi_record_close(RECORD_DIALOGS);

    free(app);
}

/* ============================================================================
 *  Entry point
 * ========================================================================== */

int32_t sli_writer_app(void* p) {
    UNUSED(p);
    SliWriterApp* app = sli_writer_app_alloc();
    view_dispatcher_run(app->view_dispatcher);
    sli_writer_app_free(app);
    return 0;
}
