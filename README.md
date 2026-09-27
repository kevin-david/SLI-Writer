# SLI Writer — Magic ISO15693 UID Writer

I made a simple Flipper app to write **magic ISO15693 tags with changeable UID** using `.nfc` files.
I also developed an **Android version** of the app, available as an `.apk`.
Sadly it is impossible to read a tag in privacy mode due to Android limitations.

---

## 🏷️ Supported Tags

### SLIX2 / ISO15693 (Magic UID)

[rfidfriend.com](http://rfidfriend.com) in **normal** mode or [AliExpress — PiSwords](https://aliexpress.com/item/1005006949791537.html) in **special** mode.

These are weird tags that need to be configured back to their original UID to unlock data write.

The old rectangulars tags were working fine with the **normal** mode - always try it first.

Save the original UID (usually the same if you order several tags from the same batch) and use **Write Special**.

> ⚠️ **Back up the original UID — if you lose it, you will never be able to rewrite the tags.**

---

### SLIX-L Tags

[rfidfriend.com](http://rfidfriend.com) in **normal** mode.

---

### Gen3 ISO15693 Magic Tags

Unfinalized Gen3 tags (with signature blocks `0x14 = A5 2B 44 2C` and `0x15 = 21 AE 93 00`) in **normal** mode.

- **UID Mapping**: UID is stored across blocks `0x10` (`UID[7..4]`) and `0x11` (`UID[3..0]`), which are written and individually verified via readback.
- **Tonie 8x4 Layout & UID Requirement**: Source `.nfc` files must strictly have 8 blocks × 4 bytes (32 bytes user data) and a UID beginning with `E0 04 03` (standard Toniebox UID prefix). Restricting writes to 8 blocks guarantees that writing user data will never overwrite or corrupt the UID registers (`0x10`/`0x11`) or magic signature blocks (`0x14`/`0x15`).
- **No Auto-Finalize (Reusable Magic State)**: The app intentionally does **not** lock or finalize Gen3 tags (it never sends finalization or lock commands). Tags remain in their unfinalized magic state so that UIDs and data blocks can be rewritten indefinitely.

---

## ⚠️ Important Constraints

### Single-Tag-in-Field Requirement
All ISO15693 operations (both Normal and Special modes) require that **only one tag is present in the Flipper's RF field at a time**:
- Non-addressed commands (such as `0x02` block write and Gen2 vendor commands `0x40`/`0x41`) broadcast to every tag in the field.
- Even addressed commands (`0x62`) and inventory checks cannot differentiate between two magic tags sharing the same factory or target UID.
- Always remove other tags before reading, saving special UIDs, or writing.

### Gen2 Layout Command Omitted
The Gen2 layout command (`0x47`) is **intentionally NOT sent**:
- Not required for most readers.
- **Will brick SLIX-L magic cards.**

---

## ✍️ Write Sequence

### Normal mode

#### 1. Pre-Write Safety & Tri-State Auto-Detection
Before issuing any write commands, the app queries signature blocks `0x14` and `0x15`:
- **`GEN3_YES` (`0x14 == A5 2B 44 2C` and `0x15 == 21 AE 93 00`)**:
  - Confirmed unfinalized Gen3 magic tag.
  - Validates source `.nfc` layout: strictly requires 8 blocks × 4 bytes and UID starting with `E0 04 03` (Tonie layout) before proceeding.
- **`GEN3_NO`**:
  - Proven standard / Gen2 tag. Strictly requires both signature blocks to return explicit ISO15693 `Unsupported` error codes (`0x10` block not available, or `0x01`/`0x02` not supported) **and** system information reporting memory $\le 8$ blocks. Only this proven non-Gen3 case authorizes legacy Gen2 writes.
- **`GEN3_UNKNOWN` (Fail-Closed Safety)**:
  - If any communication error, timeout, malformed frame, generic card error (`0x0F`), partial signature match (one block matches but not the other), failed system information query, or system information reporting $\ge 80$ blocks occurs, the tag cannot be safely classified.
  - The write is **immediately aborted** with `"Cannot safely identify tag"`, preventing legacy Gen2 backdoor commands (`0x40`/`0x41`) from being sent to an unfinalized or finalized Gen3 tag.

#### 2. Write Data Blocks
- Command: `WRITE_SINGLE_BLOCK` (`0x21`), non-addressed, flags `0x02` (retries with Option flag `0x42` if write ACK is dropped).
- Every block is strictly verified via byte-for-byte readback.
- On Gen3 tags, signature blocks `0x14` and `0x15` are re-verified after data writes to confirm they remain intact.

#### 3. Write & Verify UID
- **Gen3**:
  1. Writes block `0x10` (`<uid[7..4]>`) and verifies via readback.
  2. Writes block `0x11` (`<uid[3..0]>`) and verifies via readback. If block `0x10` succeeded but `0x11` fails, reports `Partial UID written!` to warn of a split UID state.
  3. Resynchronizes card to Ready state and runs ISO15693 inventory, strictly comparing canonical MSB-first UID against target UID.
- **Gen2 Fallback**:
  Only executed if `GEN3_NO` was explicitly established:
  ```
  02 E0 09 40 <uid_high>   → sets bytes 0–3
  02 E0 09 41 <uid_low>    → sets bytes 4–7
  ```
  Equivalent to `proxmark hf 15 csetuid -u <uid> --v2`.
  Followed by inventory readback verification.

---

### Special mode (TAG-it TI2048 / AliExpress batch)

> ℹ️ **Gen3 tags do not use Special mode.** Special mode automatically detects Gen3 tags at entry and aborts with `"Gen3: use Normal write"` to protect the tag.

These tags require the original factory UID to be present before data blocks can be written.

**Step 1 — Restore factory UID** *(skipped automatically if card already has it)*
```
02 E0 09 40 <factory_uid_high>
02 E0 09 41 <factory_uid_low>
```

**Step 2 — Write data blocks (addressed + option flag)**
- Command: `WRITE_SINGLE_BLOCK`
- Mode: **addressed**
- Flags: `0x62` (high data rate `0x02` + addressed `0x20` + option `0x40`)
- Frame format:
```
62 21 <UID[8] LSB-first> <block_num> <data[4]>
```
Example for UID `E0 07 81 2B 4F 10 4B 15`, block 0, data `11 11 11 11`:
```
62 21 15 4B 10 4F 2B 81 07 E0 00 11 11 11 11
```

> **Note:** With Option flag (`0x62`), NXP cards use a 2-phase response. The Flipper will log timeouts after each block write — this is **normal** and does not indicate a failure.

**Step 3 — Write target UID**
```
02 E0 09 40 <target_uid_high>
02 E0 09 41 <target_uid_low>
```

---

## 🔨 Build from source

```bash
# Install ufbt
pip3 install ufbt

# Pull Unleashed SDK
ufbt update --index-url=https://up.unleashedflip.com/directory.json

# Build
cd sli_writer
ufbt build

# Copy .fap to your Flipper SD card
cp /home/$USER/.ufbt/build/sli_writer.fap /path/to/SD/apps/NFC/
```

---

## 🛠️ Debugging

If writing fails:
1. Connect your Flipper via USB
2. Open a serial console (Putty, screen, etc.)
3. Set baud rate to `230400`

### Enable debug logs:
```
> log debug
```
Then look for `[SLI_Writer]` lines.

### Key debug messages
```
iso_send_raw: err=0 rxbytes=2 resp=[XX YY]
```
Command received — card returned an error. `YY` = ISO15693 error code.

```
iso_send_raw: err=6 rxbytes=0
```
No response — likely timeout or CRC issue.

```
block N: err=6 rxbytes=0
```
Normal behavior with Option flag (`0x62`) — not an error.

```
Write block N failed
```
Block write failed after all retries.

---

## Related

- [Unleashed Firmware](https://github.com/DarkFlippers/unleashed-firmware)
- [iso15693_nfc_writer (Unleashed non-catalog)](https://github.com/xMasterX/all-the-plugins/tree/dev/non_catalog_apps/iso15693_nfc_writer)
- [Proxmark3 hf 15 commands](https://github.com/RfidResearchGroup/proxmark3)
- [Toniebox community forum](https://forum.revvox.de)
