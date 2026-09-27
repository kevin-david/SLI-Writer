/* ============================================================================
 *  SLI-Writer PR #2 Host Regression Test Suite
 *  Tests Gen3 detection, UID verification, framing validation, and .nfc parser.
 * ========================================================================== */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <assert.h>

#define TAG "TEST"
#define FURI_LOG_I(...) do {} while(0)
#define FURI_LOG_W(...) do {} while(0)
#define FURI_LOG_E(...) do {} while(0)
#define FURI_LOG_D(...) do {} while(0)
#define furi_delay_ms(ms) do {} while(0)

#define SLI_MAGIC_BLOCK_SIZE       4
#define SLI_MAGIC_MAX_BLOCKS       64
#define SLI_BLOCK_WRITE_RETRIES    5
#define SLI_BLOCK_READ_RETRIES     2
#define SLI_EEPROM_WRITE_DELAY_MS  20
#define ISO15693_FWT_FC            500000

#define ISO15693_CMD_READ_BLOCK    0x20
#define ISO15693_CMD_WRITE_BLOCK   0x21
#define ISO15693_CMD_RESET_READY   0x26

#define ISO15_GEN3_BLOCK_UID_LOW   0x10
#define ISO15_GEN3_BLOCK_UID_HIGH  0x11
#define ISO15_GEN3_BLOCK_SIG_A     0x14
#define ISO15_GEN3_BLOCK_SIG_B     0x15

#define ISO15693_3_SYSINFO_FLAG_MEMORY 0x04

typedef enum {
    WriteResultOk = 0,
    WriteResultTagInventoryFailed,
    WriteResultBlockWriteFailed,
    WriteResultBlockVerifyFailed,
    WriteResultCardLost,
    WriteResultFactoryUidMismatch,
    WriteResultUidCmdFailed,
    WriteResultUidReadbackUnavailable,
    WriteResultUidMismatch,
    WriteResultSaveUidFailed,
    WriteResultGen3UidPartial,
    WriteResultUnknown,
} WriteResult;

typedef enum {
    BlockReadOk = 0,
    BlockReadUnsupported,
    BlockReadCardError,
    BlockReadCommError,
} BlockReadResult;

typedef enum {
    GEN3_NO = 0,
    GEN3_YES,
    GEN3_UNKNOWN,
} Gen3Detection;

typedef enum {
    Iso15693_3ErrorNone = 0,
    Iso15693_3ErrorTimeout,
    Iso15693_3ErrorWrongCrc,
    Iso15693_3ErrorFormat,
} Iso15693_3Error;

typedef struct {
    uint8_t flags;
    uint8_t uid[8];
    uint8_t dsfid;
    uint8_t afi;
    uint16_t block_count;
    uint8_t block_size;
    uint8_t ic_ref;
} Iso15693_3SystemInfo;

/* Mock BitBuffer */
typedef struct {
    uint8_t data[256];
    size_t size_bits;
} BitBuffer;

static BitBuffer* bit_buffer_alloc(size_t capacity_bytes) {
    (void)capacity_bytes;
    BitBuffer* bb = (BitBuffer*)calloc(1, sizeof(BitBuffer));
    return bb;
}

static void bit_buffer_free(BitBuffer* bb) {
    free(bb);
}

static size_t bit_buffer_get_size(const BitBuffer* bb) {
    return bb ? bb->size_bits : 0;
}

static size_t bit_buffer_get_size_bytes(const BitBuffer* bb) {
    return bb ? (bb->size_bits + 7) / 8 : 0;
}

static uint8_t bit_buffer_get_byte(const BitBuffer* bb, size_t byte_index) {
    if(!bb || byte_index >= (bb->size_bits + 7) / 8) return 0;
    return bb->data[byte_index];
}

static void bit_buffer_append_byte(BitBuffer* bb, uint8_t byte) {
    if(!bb) return;
    bb->data[bb->size_bits / 8] = byte;
    bb->size_bits += 8;
}

static void bit_buffer_append_bytes(BitBuffer* bb, const uint8_t* data, size_t size) {
    if(!bb || !data) return;
    for(size_t i = 0; i < size; i++) {
        bit_buffer_append_byte(bb, data[i]);
    }
}

static BitBuffer* bb_alloc_from(const uint8_t* data, size_t len) {
    BitBuffer* bb = bit_buffer_alloc(len);
    if(bb) {
        bit_buffer_append_bytes(bb, data, len);
    }
    return bb;
}

static BitBuffer* bb_alloc_rx(size_t max_bytes) {
    return bit_buffer_alloc(max_bytes);
}

static bool iso_reply_ok(BitBuffer* rx) {
    if(bit_buffer_get_size_bytes(rx) < 1) return false;
    return (bit_buffer_get_byte(rx, 0) & 0x01) == 0;
}

static void append_uid_wire_order(BitBuffer* bb, const uint8_t uid_msb[8]) {
    for(int i = 7; i >= 0; i--) {
        bit_buffer_append_byte(bb, uid_msb[i]);
    }
}

/* Mock Poller & Simulated ISO15693 Tag */
typedef struct Iso15693_3Poller {
    uint8_t blocks[SLI_MAGIC_MAX_BLOCKS][4];
    bool block_readable[SLI_MAGIC_MAX_BLOCKS];
    uint8_t block_read_err_code[SLI_MAGIC_MAX_BLOCKS];
    bool block_writeable[SLI_MAGIC_MAX_BLOCKS];

    uint8_t inventory_uid[8];
    Iso15693_3Error inventory_err;
    int inventory_attempts;

    Iso15693_3SystemInfo sysinfo;
    Iso15693_3Error sysinfo_err;

    /* Override raw frame responses */
    bool frame_override;
    Iso15693_3Error frame_err;
    uint8_t frame_rx_bytes[64];
    size_t frame_rx_bits;

    /* Execution counters */
    int send_frame_calls;
    int read_attempts;
    int write_attempts;
} Iso15693_3Poller;

static void mock_poller_reset(Iso15693_3Poller* iso) {
    memset(iso, 0, sizeof(*iso));
    for(int i = 0; i < SLI_MAGIC_MAX_BLOCKS; i++) {
        iso->block_readable[i] = true;
        iso->block_writeable[i] = true;
    }
    iso->sysinfo.flags = ISO15693_3_SYSINFO_FLAG_MEMORY;
    iso->sysinfo.block_count = 8;
    iso->sysinfo.block_size = 4;
}

static Iso15693_3Error iso15693_3_poller_send_frame(
    Iso15693_3Poller* iso,
    BitBuffer* tx,
    BitBuffer* rx,
    uint32_t fwt)
{
    (void)fwt;
    iso->send_frame_calls++;

    if(iso->frame_override) {
        rx->size_bits = iso->frame_rx_bits;
        memcpy(rx->data, iso->frame_rx_bytes, (iso->frame_rx_bits + 7) / 8);
        return iso->frame_err;
    }

    size_t tx_bytes = bit_buffer_get_size_bytes(tx);
    if(tx_bytes < 2) return Iso15693_3ErrorFormat;

    uint8_t flags = bit_buffer_get_byte(tx, 0);
    uint8_t cmd = bit_buffer_get_byte(tx, 1);

    if(cmd == ISO15693_CMD_READ_BLOCK) {
        iso->read_attempts++;
        uint8_t blk = 0;
        if(flags & 0x20) {
            /* Addressed: flags(1) + cmd(1) + uid(8) + blk(1) */
            if(tx_bytes < 11) return Iso15693_3ErrorFormat;
            blk = bit_buffer_get_byte(tx, 10);
        } else {
            /* Non-addressed: flags(1) + cmd(1) + blk(1) */
            if(tx_bytes < 3) return Iso15693_3ErrorFormat;
            blk = bit_buffer_get_byte(tx, 2);
        }

        if(blk >= SLI_MAGIC_MAX_BLOCKS) return Iso15693_3ErrorFormat;

        if(!iso->block_readable[blk]) {
            if(iso->block_read_err_code[blk] != 0) {
                bit_buffer_append_byte(rx, 0x01); /* Error flag */
                bit_buffer_append_byte(rx, iso->block_read_err_code[blk]);
                return Iso15693_3ErrorNone;
            }
            return Iso15693_3ErrorTimeout;
        }

        bit_buffer_append_byte(rx, 0x00); /* Success flag */
        bit_buffer_append_bytes(rx, iso->blocks[blk], 4);
        return Iso15693_3ErrorNone;
    } else if(cmd == ISO15693_CMD_WRITE_BLOCK) {
        iso->write_attempts++;
        uint8_t blk = 0;
        const uint8_t* wdata = NULL;
        if(flags & 0x20) {
            if(tx_bytes < 15) return Iso15693_3ErrorFormat;
            blk = bit_buffer_get_byte(tx, 10);
            wdata = &tx->data[11];
        } else {
            if(tx_bytes < 7) return Iso15693_3ErrorFormat;
            blk = bit_buffer_get_byte(tx, 2);
            wdata = &tx->data[3];
        }

        if(blk >= SLI_MAGIC_MAX_BLOCKS) return Iso15693_3ErrorFormat;

        if(!iso->block_writeable[blk]) {
            return Iso15693_3ErrorTimeout;
        }

        memcpy(iso->blocks[blk], wdata, 4);
        bit_buffer_append_byte(rx, 0x00);
        return Iso15693_3ErrorNone;
    }

    /* Default ACK */
    bit_buffer_append_byte(rx, 0x00);
    return Iso15693_3ErrorNone;
}

static Iso15693_3Error iso15693_3_poller_inventory(Iso15693_3Poller* iso, uint8_t uid[8]) {
    iso->inventory_attempts++;
    if(iso->inventory_err != Iso15693_3ErrorNone) {
        return iso->inventory_err;
    }
    memcpy(uid, iso->inventory_uid, 8);
    return Iso15693_3ErrorNone;
}

static Iso15693_3Error iso15693_3_poller_get_system_info(Iso15693_3Poller* iso, Iso15693_3SystemInfo* info) {
    if(iso->sysinfo_err != Iso15693_3ErrorNone) {
        return iso->sysinfo_err;
    }
    memcpy(info, &iso->sysinfo, sizeof(*info));
    return Iso15693_3ErrorNone;
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
    bit_buffer_free(tx);
    bit_buffer_free(rx);
    return ok;
}

/* ============================================================================
 *  Verbatim algorithms under test from Flipper/sli_writer.c
 * ========================================================================== */

static BlockReadResult read_single_block(
    Iso15693_3Poller* iso,
    const uint8_t uid_msb[8],
    uint8_t block_number,
    uint8_t data[4])
{
    BlockReadResult result = BlockReadCommError;

    for(int attempt = 0; attempt < SLI_BLOCK_READ_RETRIES; attempt++) {
        BitBuffer* tx = NULL;
        if(uid_msb) {
            tx = bit_buffer_alloc(11);
            if(!tx) return BlockReadCommError;
            bit_buffer_append_byte(tx, 0x22);
            bit_buffer_append_byte(tx, ISO15693_CMD_READ_BLOCK);
            append_uid_wire_order(tx, uid_msb);
            bit_buffer_append_byte(tx, block_number);
        } else {
            uint8_t frame[3] = {0x02, ISO15693_CMD_READ_BLOCK, block_number};
            tx = bb_alloc_from(frame, sizeof(frame));
            if(!tx) return BlockReadCommError;
        }

        BitBuffer* rx = bb_alloc_rx(16);
        if(!rx) {
            bit_buffer_free(tx);
            return BlockReadCommError;
        }

        Iso15693_3Error err = iso15693_3_poller_send_frame(iso, tx, rx, ISO15693_FWT_FC);
        size_t rx_bits = bit_buffer_get_size(rx);
        size_t rx_bytes = bit_buffer_get_size_bytes(rx);

        if(err == Iso15693_3ErrorNone && rx_bytes >= 1) {
            uint8_t flags = bit_buffer_get_byte(rx, 0);
            if(flags & 0x01) {
                if(rx_bits == 16 && rx_bytes == 2) {
                    uint8_t error_code = bit_buffer_get_byte(rx, 1);
                    if(error_code == 0x10 || error_code == 0x01 || error_code == 0x02) {
                        result = BlockReadUnsupported;
                    } else {
                        result = BlockReadCardError;
                    }
                } else {
                    result = BlockReadCommError;
                }
                bit_buffer_free(tx);
                bit_buffer_free(rx);
                break;
            } else if(rx_bits == 40 && rx_bytes == 5) {
                for(size_t i = 0; i < 4; i++) {
                    data[i] = bit_buffer_get_byte(rx, 1 + i);
                }
                result = BlockReadOk;
                bit_buffer_free(tx);
                bit_buffer_free(rx);
                break;
            } else {
                result = BlockReadCommError;
            }
        }

        bit_buffer_free(tx);
        bit_buffer_free(rx);
        result = BlockReadCommError;
        if(attempt + 1 < SLI_BLOCK_READ_RETRIES) {
            furi_delay_ms(15);
        }
    }

    return result;
}

static Gen3Detection detect_gen3(Iso15693_3Poller* iso) {
    static const uint8_t gen3_sig14[4] = {0xA5, 0x2B, 0x44, 0x2C};
    static const uint8_t gen3_sig15[4] = {0x21, 0xAE, 0x93, 0x00};

    uint8_t data14[4] = {0};
    uint8_t data15[4] = {0};

    BlockReadResult res14 = read_single_block(iso, NULL, ISO15_GEN3_BLOCK_SIG_A, data14);
    if(res14 == BlockReadCommError || res14 == BlockReadCardError) {
        return GEN3_UNKNOWN;
    }

    furi_delay_ms(15);

    BlockReadResult res15 = read_single_block(iso, NULL, ISO15_GEN3_BLOCK_SIG_B, data15);
    if(res15 == BlockReadCommError || res15 == BlockReadCardError) {
        return GEN3_UNKNOWN;
    }

    bool sig14_match = (res14 == BlockReadOk && memcmp(data14, gen3_sig14, 4) == 0);
    bool sig15_match = (res15 == BlockReadOk && memcmp(data15, gen3_sig15, 4) == 0);

    if(sig14_match && sig15_match) {
        return GEN3_YES;
    }

    if(sig14_match || sig15_match) {
        return GEN3_UNKNOWN;
    }

    if(res14 == BlockReadUnsupported && res15 == BlockReadUnsupported) {
        return GEN3_NO;
    }

    Iso15693_3SystemInfo sys_info;
    Iso15693_3Error sys_err = iso15693_3_poller_get_system_info(iso, &sys_info);
    if(sys_err == Iso15693_3ErrorNone) {
        if((sys_info.flags & ISO15693_3_SYSINFO_FLAG_MEMORY)) {
            if(sys_info.block_count >= 80) {
                return GEN3_UNKNOWN;
            }
            if(sys_info.block_count <= 8) {
                return GEN3_NO;
            }
        }
        return GEN3_UNKNOWN;
    } else {
        return GEN3_UNKNOWN;
    }
}

static bool write_single_block_verified(
    Iso15693_3Poller* iso,
    uint8_t block_number,
    const uint8_t data[4],
    uint8_t readback_out[4])
{
    uint8_t wframe[7] = {
        0x02,
        ISO15693_CMD_WRITE_BLOCK,
        block_number,
        data[0], data[1], data[2], data[3],
    };

    for(int attempt = 0; attempt < SLI_BLOCK_WRITE_RETRIES; attempt++) {
        iso_send_raw(iso, wframe, sizeof(wframe), ISO15693_FWT_FC);
        furi_delay_ms(SLI_EEPROM_WRITE_DELAY_MS);

        if(read_single_block(iso, NULL, block_number, readback_out) == BlockReadOk) {
            if(memcmp(readback_out, data, 4) == 0) {
                return true;
            }
        }
        if(attempt + 1 < SLI_BLOCK_WRITE_RETRIES) {
            furi_delay_ms(15);
        }
    }

    return false;
}

static WriteResult gen3_write_uid(Iso15693_3Poller* iso, const uint8_t uid[8]) {
    const uint8_t expected_10[4] = {uid[7], uid[6], uid[5], uid[4]};
    const uint8_t expected_11[4] = {uid[3], uid[2], uid[1], uid[0]};

    uint8_t readback[4] = {0};

    if(!write_single_block_verified(iso, ISO15_GEN3_BLOCK_UID_LOW, expected_10, readback)) {
        return WriteResultUidCmdFailed;
    }

    furi_delay_ms(SLI_EEPROM_WRITE_DELAY_MS);

    memset(readback, 0, sizeof(readback));
    if(!write_single_block_verified(iso, ISO15_GEN3_BLOCK_UID_HIGH, expected_11, readback)) {
        return WriteResultGen3UidPartial;
    }

    furi_delay_ms(50);
    uint8_t actual_uid[8] = {0};
    bool inventory_received = false;

    for(int attempt = 0; attempt < 5; attempt++) {
        if(iso15693_3_poller_inventory(iso, actual_uid) == Iso15693_3ErrorNone) {
            inventory_received = true;
            if(memcmp(actual_uid, uid, 8) == 0) {
                return WriteResultOk;
            }
        }
        if(attempt + 1 < 5) {
            furi_delay_ms(25);
        }
    }

    if(!inventory_received) {
        return WriteResultUidReadbackUnavailable;
    }

    return WriteResultUidMismatch;
}

static const char* find_line_key(const char* buf, const char* key) {
    size_t key_len = strlen(key);
    const char* p = buf;
    while(p && *p) {
        if(strncmp(p, key, key_len) == 0) {
            return p + key_len;
        }
        p = strchr(p, '\n');
        if(p) p++;
    }
    return NULL;
}

static const char* find_line_end(const char* p) {
    while(*p && *p != '\r' && *p != '\n') {
        p++;
    }
    return p;
}

static size_t parse_hex_bytes_bounded(
    const char* start,
    const char* end,
    uint8_t* out,
    size_t max_bytes)
{
    size_t count = 0;
    const char* q = start;

    while(q < end && count < max_bytes) {
        while(q < end && (*q == ' ' || *q == '\t')) q++;
        if(q >= end) break;

        char* token_end = NULL;
        long val = strtol(q, &token_end, 16);
        if(token_end == q || token_end > end || val < 0 || val > 0xFF) {
            break;
        }
        out[count++] = (uint8_t)val;
        q = token_end;
    }

    while(q < end && (*q == ' ' || *q == '\t')) q++;
    if(q < end) {
        return 0;
    }

    return count;
}

/* ============================================================================
 *  Test Cases
 * ========================================================================== */

/* 1. Exact Response Length & Error Classification */
static void test_read_single_block_framing(void) {
    printf("[TEST] read_single_block framing and error classification\n");
    Iso15693_3Poller iso;
    mock_poller_reset(&iso);
    uint8_t data[4] = {0};

    /* 1.1 Exact 5-byte (40-bit) valid read */
    iso.frame_override = true;
    iso.frame_rx_bits = 40;
    iso.frame_rx_bytes[0] = 0x00; /* flags */
    iso.frame_rx_bytes[1] = 0x11;
    iso.frame_rx_bytes[2] = 0x22;
    iso.frame_rx_bytes[3] = 0x33;
    iso.frame_rx_bytes[4] = 0x44;
    iso.frame_err = Iso15693_3ErrorNone;
    assert(read_single_block(&iso, NULL, 0, data) == BlockReadOk);
    assert(data[0] == 0x11 && data[1] == 0x22 && data[2] == 0x33 && data[3] == 0x44);

    /* 1.2 Oversized 9-byte (72-bit) read response is rejected */
    iso.frame_rx_bits = 72;
    iso.frame_rx_bytes[0] = 0x00;
    assert(read_single_block(&iso, NULL, 0, data) == BlockReadCommError);

    /* 1.3 Truncated 3-byte (24-bit) read response is rejected */
    iso.frame_rx_bits = 24;
    iso.frame_rx_bytes[0] = 0x00;
    assert(read_single_block(&iso, NULL, 0, data) == BlockReadCommError);

    /* 1.4 Exact 2-byte (16-bit) error 0x10 is BlockReadUnsupported */
    iso.frame_rx_bits = 16;
    iso.frame_rx_bytes[0] = 0x01; /* error bit set */
    iso.frame_rx_bytes[1] = 0x10; /* block not available */
    assert(read_single_block(&iso, NULL, 0, data) == BlockReadUnsupported);

    /* 1.5 Exact 2-byte (16-bit) error 0x01/0x02 is BlockReadUnsupported */
    iso.frame_rx_bytes[1] = 0x01;
    assert(read_single_block(&iso, NULL, 0, data) == BlockReadUnsupported);
    iso.frame_rx_bytes[1] = 0x02;
    assert(read_single_block(&iso, NULL, 0, data) == BlockReadUnsupported);

    /* 1.6 Exact 2-byte (16-bit) other error 0x0F is BlockReadCardError */
    iso.frame_rx_bytes[1] = 0x0F;
    assert(read_single_block(&iso, NULL, 0, data) == BlockReadCardError);

    /* 1.7 Truncated 1-byte (8-bit) error response is BlockReadCommError */
    iso.frame_rx_bits = 8;
    iso.frame_rx_bytes[0] = 0x01;
    assert(read_single_block(&iso, NULL, 0, data) == BlockReadCommError);

    /* 1.8 Oversized 3-byte (24-bit) error response is BlockReadCommError */
    iso.frame_rx_bits = 24;
    iso.frame_rx_bytes[0] = 0x01;
    iso.frame_rx_bytes[1] = 0x10;
    iso.frame_rx_bytes[2] = 0x00;
    assert(read_single_block(&iso, NULL, 0, data) == BlockReadCommError);

    printf("  -> PASS\n\n");
}

/* 2. Tri-State Gen3 Detection */
static void test_detect_gen3_tristate(void) {
    printf("[TEST] detect_gen3 tri-state safety classification\n");
    Iso15693_3Poller iso;

    /* 2.1 Genuine Gen3 tag: both signatures match */
    mock_poller_reset(&iso);
    const uint8_t sig14[4] = {0xA5, 0x2B, 0x44, 0x2C};
    const uint8_t sig15[4] = {0x21, 0xAE, 0x93, 0x00};
    memcpy(iso.blocks[0x14], sig14, 4);
    memcpy(iso.blocks[0x15], sig15, 4);
    assert(detect_gen3(&iso) == GEN3_YES);

    /* 2.2 Partial signature match (A matches, B altered): fails closed to GEN3_UNKNOWN */
    mock_poller_reset(&iso);
    memcpy(iso.blocks[0x14], sig14, 4);
    iso.blocks[0x15][0] = 0xFF; /* Corrupted/changed sig B */
    assert(detect_gen3(&iso) == GEN3_UNKNOWN);

    /* 2.3 Partial signature match (B matches, A altered): fails closed to GEN3_UNKNOWN */
    mock_poller_reset(&iso);
    iso.blocks[0x14][0] = 0xFF;
    memcpy(iso.blocks[0x15], sig15, 4);
    assert(detect_gen3(&iso) == GEN3_UNKNOWN);

    /* 2.4 Communication error / timeout reading signature block 0x14 -> GEN3_UNKNOWN */
    mock_poller_reset(&iso);
    iso.block_readable[0x14] = false; /* timeout */
    assert(detect_gen3(&iso) == GEN3_UNKNOWN);

    /* 2.5 Communication error / timeout reading signature block 0x15 -> GEN3_UNKNOWN */
    mock_poller_reset(&iso);
    memcpy(iso.blocks[0x14], sig14, 4);
    iso.block_readable[0x15] = false; /* timeout */
    assert(detect_gen3(&iso) == GEN3_UNKNOWN);

    /* 2.6 Generic card error 0x0F on block 0x14 -> GEN3_UNKNOWN (does NOT fall through to GEN3_NO) */
    mock_poller_reset(&iso);
    iso.block_readable[0x14] = false;
    iso.block_read_err_code[0x14] = 0x0F;
    assert(detect_gen3(&iso) == GEN3_UNKNOWN);

    /* 2.7 Malformed 1-byte error response on block 0x14 -> GEN3_UNKNOWN */
    mock_poller_reset(&iso);
    iso.frame_override = true;
    iso.frame_rx_bits = 8;
    iso.frame_rx_bytes[0] = 0x01;
    assert(detect_gen3(&iso) == GEN3_UNKNOWN);

    /* 2.8 Both blocks return unsupported (0x10) and sysinfo block count <= 8 -> GEN3_NO (standard tag) */
    mock_poller_reset(&iso);
    iso.block_readable[0x14] = false;
    iso.block_read_err_code[0x14] = 0x10;
    iso.block_readable[0x15] = false;
    iso.block_read_err_code[0x15] = 0x10;
    iso.sysinfo.block_count = 8;
    assert(detect_gen3(&iso) == GEN3_NO);

    /* 2.9 Finalized Gen3 protection: readable altered signatures + sysinfo >= 80 blocks -> GEN3_UNKNOWN */
    mock_poller_reset(&iso);
    iso.blocks[0x14][0] = 0x00;
    iso.blocks[0x15][0] = 0x00;
    iso.sysinfo.block_count = 80;
    assert(detect_gen3(&iso) == GEN3_UNKNOWN);

    /* 2.10 Readable altered signatures + sysinfo error -> GEN3_UNKNOWN */
    mock_poller_reset(&iso);
    iso.blocks[0x14][0] = 0x00;
    iso.blocks[0x15][0] = 0x00;
    iso.sysinfo_err = Iso15693_3ErrorTimeout;
    assert(detect_gen3(&iso) == GEN3_UNKNOWN);

    /* 2.11 Readable altered signatures + missing memory flag in sysinfo -> GEN3_UNKNOWN */
    mock_poller_reset(&iso);
    iso.blocks[0x14][0] = 0x00;
    iso.blocks[0x15][0] = 0x00;
    iso.sysinfo.flags = 0; /* No memory flag */
    assert(detect_gen3(&iso) == GEN3_UNKNOWN);

    printf("  -> PASS\n\n");
}

/* 3. Canonical MSB UID Inventory Verification */
static void test_gen3_write_uid_verification(void) {
    printf("[TEST] gen3_write_uid canonical MSB verification & granular error reporting\n");
    Iso15693_3Poller iso;
    const uint8_t target_uid[8] = {0xE0, 0x04, 0x03, 0x12, 0x34, 0x56, 0x78, 0x9A};

    /* 3.1 Successful write and verification in canonical MSB order */
    mock_poller_reset(&iso);
    memcpy(iso.inventory_uid, target_uid, 8);
    WriteResult res = gen3_write_uid(&iso, target_uid);
    assert(res == WriteResultOk);
    /* Verify blocks 0x10 and 0x11 held expected slices */
    assert(iso.blocks[0x10][0] == target_uid[7]);
    assert(iso.blocks[0x10][1] == target_uid[6]);
    assert(iso.blocks[0x10][2] == target_uid[5]);
    assert(iso.blocks[0x10][3] == target_uid[4]);
    assert(iso.blocks[0x11][0] == target_uid[3]);
    assert(iso.blocks[0x11][1] == target_uid[2]);
    assert(iso.blocks[0x11][2] == target_uid[1]);
    assert(iso.blocks[0x11][3] == target_uid[0]);

    /* 3.2 Block 0x10 write failure -> WriteResultUidCmdFailed */
    mock_poller_reset(&iso);
    iso.block_writeable[0x10] = false;
    res = gen3_write_uid(&iso, target_uid);
    assert(res == WriteResultUidCmdFailed);

    /* 3.3 Block 0x10 succeeds, Block 0x11 fails -> WriteResultGen3UidPartial */
    mock_poller_reset(&iso);
    iso.block_writeable[0x11] = false;
    res = gen3_write_uid(&iso, target_uid);
    assert(res == WriteResultGen3UidPartial);

    /* 3.4 Both blocks succeed, but inventory timeout -> WriteResultUidReadbackUnavailable */
    mock_poller_reset(&iso);
    iso.inventory_err = Iso15693_3ErrorTimeout;
    res = gen3_write_uid(&iso, target_uid);
    assert(res == WriteResultUidReadbackUnavailable);

    /* 3.5 Both blocks succeed, but inventory returns mismatched UID -> WriteResultUidMismatch */
    mock_poller_reset(&iso);
    memcpy(iso.inventory_uid, target_uid, 8);
    iso.inventory_uid[7] ^= 0x01; /* 1-bit mismatch */
    res = gen3_write_uid(&iso, target_uid);
    assert(res == WriteResultUidMismatch);

    printf("  -> PASS\n\n");
}

/* 4. Hardened .nfc Parser Regression Tests */
static void test_nfc_parser_hardened(void) {
    printf("[TEST] .nfc parser line-anchored & field-bounded token validation\n");

    /* 4.1 Valid Tonie 8x4 file */
    const char* valid_nfc =
        "Filetype: Flipper NFC device\n"
        "Version: 4\n"
        "Device type: ISO15693\n"
        "UID: E0 04 03 12 34 56 78 9A\n"
        "DSFID: 00\n"
        "AFI: 00\n"
        "Block Count: 8\n"
        "Block Size: 4\n"
        "Data Content: 00 11 22 33 44 55 66 77 88 99 AA BB CC DD EE FF 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F 10\n";

    uint8_t uid[8] = {0};
    const char* p = find_line_key(valid_nfc, "UID:");
    assert(p != NULL);
    const char* end = find_line_end(p);
    size_t count = parse_hex_bytes_bounded(p, end, uid, 8);
    assert(count == 8);
    assert(uid[0] == 0xE0 && uid[1] == 0x04 && uid[2] == 0x03);

    p = find_line_key(valid_nfc, "Data Content:");
    assert(p != NULL);
    end = find_line_end(p);
    uint8_t data[32] = {0};
    count = parse_hex_bytes_bounded(p, end, data, 32);
    assert(count == 32);
    assert(data[0] == 0x00 && data[31] == 0x10);

    /* 4.2 Truncated 7-byte UID followed by DSFID: line - NO BLEED */
    const char* truncated_uid_nfc =
        "Device type: ISO15693\n"
        "UID: E0 04 03 01 02 03 04\n"
        "DSFID: 00\n";

    memset(uid, 0, sizeof(uid));
    p = find_line_key(truncated_uid_nfc, "UID:");
    assert(p != NULL);
    end = find_line_end(p);
    count = parse_hex_bytes_bounded(p, end, uid, 8);
    assert(count == 7); /* Must NOT read 'D' from DSFID: -> returns 7 bytes */

    /* 4.3 Line anchoring: key matching does NOT match substring keys */
    const char* subkey_nfc =
        "Shadow UID: AA BB CC DD EE FF 00 11\n"
        "UID: E0 04 03 12 34 56 78 9A\n";

    p = find_line_key(subkey_nfc, "UID:");
    assert(p != NULL);
    end = find_line_end(p);
    count = parse_hex_bytes_bounded(p, end, uid, 8);
    assert(count == 8);
    assert(uid[0] == 0xE0); /* Matched "UID:", NOT "Shadow UID:" */

    /* 4.4 Incomplete Data Content (28 bytes instead of 32) */
    const char* short_data_nfc =
        "Block Count: 8\n"
        "Block Size: 4\n"
        "Data Content: 00 11 22 33 44 55 66 77 88 99 AA BB CC DD EE FF 01 02 03 04 05 06 07 08 09 0A 0B 0C\n"; /* 28 bytes */

    p = find_line_key(short_data_nfc, "Data Content:");
    assert(p != NULL);
    end = find_line_end(p);
    count = parse_hex_bytes_bounded(p, end, data, 32);
    assert(count == 28); /* Bounded parser returns exactly parsed count, allowing caller to detect mismatch */

    /* 4.5 Extra bytes on line are rejected (returns 0) */
    const char* extra_trailing_nfc =
        "UID: E0 04 03 12 34 56 78 9A EXTRA_GARBAGE\n";

    p = find_line_key(extra_trailing_nfc, "UID:");
    assert(p != NULL);
    end = find_line_end(p);
    count = parse_hex_bytes_bounded(p, end, uid, 8);
    assert(count == 0); /* Non-whitespace trailing garbage causes parse failure */

    printf("  -> PASS\n\n");
}

/* 5. Retry Budget & Single-Owner Verification */
static void test_retry_budget_and_io(void) {
    printf("[TEST] Bounded retry budget and single-owner I/O\n");
    Iso15693_3Poller iso;
    mock_poller_reset(&iso);

    /* 5.1 read_single_block caps attempts at SLI_BLOCK_READ_RETRIES (2) */
    iso.block_readable[0] = false;
    uint8_t data[4] = {0};
    assert(read_single_block(&iso, NULL, 0, data) == BlockReadCommError);
    assert(iso.read_attempts == SLI_BLOCK_READ_RETRIES);

    /* 5.2 write_single_block_verified succeeds on first attempt without extra reads */
    mock_poller_reset(&iso);
    const uint8_t wdata[4] = {0x11, 0x22, 0x33, 0x44};
    uint8_t rdata[4] = {0};
    assert(write_single_block_verified(&iso, 0, wdata, rdata) == true);
    assert(iso.write_attempts == 1);
    assert(iso.read_attempts == 1);

    /* 5.3 write_single_block_verified worst-case retries capped at SLI_BLOCK_WRITE_RETRIES (5) */
    mock_poller_reset(&iso);
    iso.block_writeable[0] = false;
    assert(write_single_block_verified(&iso, 0, wdata, rdata) == false);
    assert(iso.write_attempts == SLI_BLOCK_WRITE_RETRIES);
    /* 5 write attempts * 2 read attempts = 10 reads maximum (previously 30!) */
    assert(iso.read_attempts <= SLI_BLOCK_WRITE_RETRIES * SLI_BLOCK_READ_RETRIES);

    printf("  -> PASS\n\n");
}

int main(void) {
    printf("============================================================\n");
    printf("  SLI-Writer PR #2: Comprehensive Host Regression Test Suite\n");
    printf("============================================================\n\n");

    test_read_single_block_framing();
    test_detect_gen3_tristate();
    test_gen3_write_uid_verification();
    test_nfc_parser_hardened();
    test_retry_budget_and_io();

    printf("============================================================\n");
    printf("  ALL REGRESSION TESTS PASSED SUCCESSFULLY!\n");
    printf("============================================================\n");
    return 0;
}
