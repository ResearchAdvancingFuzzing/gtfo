// DISTRIBUTION STATEMENT A. Approved for public release. Distribution is unlimited.
//
// This material is based upon work supported by the Department of the Air Force under Air Force Contract No. FA8702-15-D-0001. Any opinions, findings, conclusions or recommendations expressed in this material are those of the author(s) and do not necessarily reflect the views of the Department of the Air Force.
//
// © 2019 Massachusetts Institute of Technology.
//
// Subject to FAR52.227-11 Patent Rights - Ownership by the contractor (May 2014)
//
// The software/firmware is provided to you on an As-Is basis
//
// Delivered to the U.S. Government with Unlimited Rights, as defined in DFARS Part 252.227-7013 or 7014 (Feb 2014). Notwithstanding any copyright notice, U.S. Government rights in this work are defined by DFARS 252.227-7013 or DFARS 252.227-7014 as detailed above. Use of this work other than as specifically authorized by the U.S. Government may violate any copyrights that exist in this work.

/*
______
|  _  \
| | | | __ _  _ __    __ _   ___  _ __
| | | |/ _` || '_ \  / _` | / _ \| '__|
| |/ /| (_| || | | || (_| ||  __/| |
|___/  \__,_||_| |_| \__, | \___||_|
                      __/ |
                     |___/

This doesn't parse TNT packets properly. The right way would be to extract a
bitstream and then hash it. We need to test this.
*/
#include <bits/stdint-uintn.h>
#include <fcntl.h>
#include <nmmintrin.h>
#include <string.h>
#include <unistd.h>

#include "analysis.h"
#include "common/logger.h"
#include "common/types.h"

static u8    *hashes       = NULL;
static size_t hashes_size  = 0;
static size_t current_used = 0;

#define TNT_HASH 0
#define TIP_HASH 1
#define FUP_HASH 2

static int
compare_hash(const void *a, const void *b)
{
	return memcmp(a, b, sizeof(u32) * 3);
}

// BEGIN: taken and modified from https://github.com/andikleen/simple-pt/blob/master/fastdecode.c
#define BIT(x) (1U << (x))
#define LEFT(x) ((end - p) >= (x))
// One-Left-Shift.  Used to test for bits in a bitmap
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wsign-conversion"
static char              psb[16] = {0x02, 0x82, 0x02, 0x82, 0x02, 0x82, 0x02, 0x82, 0x02, 0x82, 0x02, 0x82, 0x02, 0x82, 0x02, 0x82};
#pragma clang diagnostic pop
static u64               tnt_buffer       = 0;
static u8                tnt_buffer_index = 0;

inline static void
process_tip_packet(u64 ip, u32 *hash)
{
	*hash = (u32)_mm_crc32_u64(*hash, ip);
}

inline static void
finalize_tnt_hash(u32 *hash)
{
	u64 zeros = (u64)(64 - tnt_buffer_index);
	*hash     = (u32)_mm_crc32_u64(*hash, tnt_buffer);
	*hash     = (u32)_mm_crc32_u64(*hash, zeros);

	tnt_buffer       = 0;
	tnt_buffer_index = 0;
}

// Adds a given number of TNT bits to the TNT hash (or the buffer if it's not full)
inline static void
update_tnt_bits(u64 payload, u8 num_bits, u32 *hash)
{
	s32 i = 0;
	for (i = num_bits - 1; i >= 0; i--) {
		if (payload & (1 << i)) {
			tnt_buffer |= (1 << tnt_buffer_index);
		} else {
			tnt_buffer &= ~(1 << tnt_buffer_index);
		}
		tnt_buffer_index++;
		if (tnt_buffer_index == 64) {
			*hash            = (u32)_mm_crc32_u64(*hash, tnt_buffer);
			tnt_buffer_index = 0;
			tnt_buffer       = 0;
		}
	}
}

inline static u64
get_ip_val(unsigned char **pp, const unsigned char *end, int len, uint64_t *last_ip)
{
	unsigned char *p     = *pp;
	u64            v     = *last_ip;
	int            i     = 0;
	unsigned       shift = 0;

	if (len == 0) {
		*last_ip = 0;
		return 0; // out of context
	}
	if (len < 4) {
		if (!LEFT(len)) {
			log_fatal("error parsing IP");
		}
		for (i = 0; i < len; i++, shift += 16, p += 2) {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wcast-align"
			uint64_t b = *(uint16_t *)p;
#pragma clang diagnostic pop
			v = (v & ~(0xffffULL << shift)) | (b << shift);
		}
		v = ((u64)(v << (64 - 48))) >> (64 - 48); /* sign extension */
	} else {
		log_fatal("error parsing IP");
	}
	*pp      = p;
	*last_ip = v;
	return v;
}

inline static void
process_tnt64_packet(unsigned char *p, u32 *hash)
{
	u64 payload        = 0;
	u8  num_bits       = 0;
	int byte_index     = 0;
	int bit_index      = 0;
	int found_stop_bit = 0;

	p = p + 2; // Skip the TNT64 header
	for (byte_index = 5; byte_index >= 0; byte_index--) {
		if (found_stop_bit) { // We've already found the stop bit, just copy this byte
			payload = (payload << 8) | p[byte_index];
		} else if (p[byte_index] == 0) { // Skip any bytes that are all 0
		} else {
			// Otherwise look for the stop bit
			for (bit_index = 7; bit_index >= 0; bit_index--) {
				if (p[byte_index] & BIT(bit_index)) {
					num_bits       = (u8)((byte_index * 8) + bit_index);
					payload        = p[byte_index] & (BIT(bit_index) - 1);
					found_stop_bit = 1;
					break;
				}
			}
		}
	}

	if (found_stop_bit) {
		update_tnt_bits(payload, num_bits, hash);
	} else {
		log_fatal("Unable to decode TNT64 packet");
	}
}

// Process a new TNT8 packet and add its bits to the TNT hash
inline static void
process_tnt8_packet(const unsigned char *p, u32 *hash)
{
	u8  i        = 0;
	u64 payload  = 0;
	u8  num_bits = 0;

	for (i = 7; i > 0; i--) {
		if (*p & BIT(i)) {
			num_bits = (u8)(i - 1);
			break;
		}
	}

	if (num_bits) {
		payload = (*p >> 1) & (BIT(num_bits) - 1);
		update_tnt_bits(payload, num_bits, hash);
	}
}

static bool
decode_and_hash(u8 *pt_buffer, size_t size, u32 *tnt_hash, u32 *tip_hash, u32 *fup_hash)
{
	bool           found                   = false;
	unsigned char *end                     = pt_buffer + size;
	unsigned char *p                       = pt_buffer;
	unsigned char *sync                    = NULL;
	u64            last_ip                 = 0;
	u64            dummy                   = 0;
	int            type                    = 0;
	int            ipl                     = 0;
	u64            tmpip                   = 0;
	u64            duplicate_detect_ip_tip = 0;
	u64            duplicate_detect_ip_fup = 0;
	while (p < end) {
		// Sync to the PSB
		sync = memmem(p, (size_t)(end - p), psb, 16);
		if (!sync) {
			break;
		}
		p = sync + 16;

		while (p < end) {
			if (*p == 0x02 && LEFT(2)) {
				if (p[1] == 0xa3 && LEFT(8)) {
					process_tnt64_packet(p, tnt_hash); // TNT64 packet
					found = true;
					p += 8;
					continue;
				}

				if (p[1] == 0x43 && LEFT(8)) {
					p += 8;
					continue;
				}

				if (p[1] == 3 && LEFT(4)) {
					p += 4;
					continue;
				}

				if (p[1] == 0x83) {
					p += 2;
					continue;
				}

				if (p[1] == 0xf3) {
					p += 2;
					continue;
				}

				if (p[1] == 0x82 && LEFT(16) && !memcmp(p, psb, 16)) {
					p += 16;
					continue;
				}

				if (p[1] == 0x23) {
					p += 2;
					continue;
				}

				if (p[1] == 0xc3 && p[2] == 0x88) {
					p += 11;
					continue;
				}

				if (p[1] == 0x73) {
					p += 7;
					continue;
				}

				if (p[1] == 0xc8) {
					p += 7;
					continue;
				}

				if ((p[1] & 0x7f) == 0x62) {
					p += 2;
					continue;
				}

				if (p[1] == 0xc2) {
					p += 10;
					continue;
				}

				if (p[1] == 0x22) {
					p += 4;
					continue;
				}

				if (p[1] == 0xa2) {
					p += 7;
					continue;
				}
			}

			if ((*p & BIT(0)) == 0) {
				if (*p == 0) {
					p++;
					continue;
				}

				process_tnt8_packet(p, tnt_hash); // TNT8 packet
				found = true;
				p++;
				continue;
			}

			type = (*p & 0x1f);
			if (type == 0xd || type == 0x1 || type == 0x11 || type == 0x1d) { // The various types of TIP packets
				ipl = *p >> 5;
				p++;

				switch (type) {
				case 0x1: { // TIP.PGD
					tmpip = get_ip_val(&p, end, ipl, &dummy);
					if (tmpip != duplicate_detect_ip_tip) {
						process_tip_packet(tmpip, tip_hash);
						duplicate_detect_ip_tip = tmpip;
					}
					break;
				}
				case 0xd:    // TIP
				case 0x11: { // TIP.PGE
					tmpip = get_ip_val(&p, end, ipl, &last_ip);
					if (tmpip != duplicate_detect_ip_tip) {
						process_tip_packet(tmpip, tip_hash);
						duplicate_detect_ip_tip = tmpip;
					}
					break;
				}
				case 0x1d: { // FUP
					tmpip = get_ip_val(&p, end, ipl, &last_ip);
					if (tmpip != duplicate_detect_ip_fup) {
						process_tip_packet(tmpip, fup_hash);
						duplicate_detect_ip_fup = tmpip;
					}
					break;
				}
				}
				found = true;
				continue;
			}

			if (*p == 0x99) {
				p += 2;
				continue;
			}

			if (*p == 0x19) {
				p += 8;
				continue;
			}

			if (*p == 0x59) {
				p += 2;
				continue;
			}

			if ((*p & 3) == 3) {
				if (*p & BIT(2)) {
					do {
						p++;
					} while ((*p & 1) && p < end);
				}
				p++;
				continue;
			}
			// Unknown
			log_fatal("Got Unknown Packet Type, will probably break decoding: (%d bytes left)", end - p);
		}
	}
	finalize_tnt_hash(tnt_hash);
	// log_debug("Hash of PT data: %x %x %x", *tnt_hash, *tip_hash, *fup_hash);
	return found;
}
// END: taken and modified from https://github.com/andikleen/simple-pt/blob/master/fastdecode.c

#pragma clang diagnostic ignored "-Wunused-parameter"
static bool
add(u8 *element, size_t size, strategy_state * state)
{
	u32 hash[3] = {0};

	u32  tnt_hash      = 1;
	u32  tip_hash      = 1;
	u32  fup_hash      = 1;
	bool packets_found = decode_and_hash(element, size, &tnt_hash, &tip_hash, &fup_hash);

	if (!packets_found) {
		log_debug("No TNT or TIP packets found.");
		return true;
	}

	hash[TNT_HASH] = tnt_hash;
	hash[TIP_HASH] = tip_hash;
	hash[FUP_HASH] = fup_hash;

	void *hash_found = bsearch(hash, hashes, current_used / (sizeof(u32) * 3), sizeof(u32) * 3, compare_hash);
	if (hash_found != NULL) {
		return true;
	}
	if (current_used != hashes_size) {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wcast-align"
		u32 *hashes_32 = (u32 *)(hashes + current_used);
#pragma clang diagnostic pop
		hashes_32[0] = hash[0];
		hashes_32[1] = hash[1];
		hashes_32[2] = hash[2];
		current_used += (sizeof(u32) * 3);
	}
	qsort(hashes, current_used / (sizeof(u32) * 3), sizeof(u32) * 3, compare_hash);
	return false;
}

static int
load_from_file(char *filename)
{
	int file_fd = open(filename, O_RDONLY);
	if (file_fd == -1) {
		log_fatal("loading analysis open failed");
	}

	ssize_t read_size = read(file_fd, &current_used, sizeof(current_used));
	if (read_size == -1) {
		log_fatal("loading analysis read failed");
	}
	if (read_size != sizeof(current_used)) {
		log_fatal("loading analysis size mismatch");
	}

	if (current_used >= hashes_size) {
		log_fatal("analysis size too small to load from file");
	}

	read_size = read(file_fd, hashes, hashes_size);
	if (read_size == -1) {
		log_fatal("loading analysis read failed");
	}
	if (read_size >= 0 && (size_t)read_size != hashes_size) {
		log_fatal("loading analysis size mismatch");
	}
	close(file_fd);
	return 0;
}

static void
save_to_file(char *filename)
{
	int file_fd = open(filename, O_WRONLY | O_CREAT, 0600);
	if (file_fd == -1) {
		log_fatal("saving analysis open failed");
	}

	ssize_t write_size = write(file_fd, &current_used, sizeof(current_used));
	if (write_size == -1) {
		log_fatal("saving analysis write failed");
	}
	if (write_size != sizeof(current_used)) {
		log_fatal("saving analysis size mismatch");
	}

	write_size = write(file_fd, hashes, hashes_size);
	if (write_size == -1) {
		log_fatal("saving analysis write failed");
	}
	if (write_size >= 0 && (size_t)write_size != hashes_size) {
		log_fatal("saving analysis size mismatch");
	}
	close(file_fd);
}

static void
merge_load(char *filename, size_t *used, u8 **buffer)
{
	int file_fd = open(filename, O_RDONLY);
	if (file_fd == -1) {
		log_fatal("loading analysis open failed");
	}

	ssize_t read_size = read(file_fd, used, sizeof(*used));
	if (read_size == -1) {
		log_fatal("loading analysis read failed");
	}
	if (read_size != sizeof(current_used)) {
		log_fatal("loading analysis size mismatch");
	}

	*buffer = calloc(*used, 1);

	read_size = read(file_fd, *buffer, *used);
	if (read_size == -1) {
		log_fatal("loading analysis read failed");
	}
	if (read_size >= 0 && (size_t)read_size != *used) {
		log_fatal("loading analysis size mismatch");
	}
	close(file_fd);
}

static void
merge(char *a, char *b, char *merge)
{
	init_logging();

	u8 *a_buffer     = NULL;
	u8 *b_buffer     = NULL;
	u8 *merge_buffer = NULL;

	size_t a_used     = 0;
	size_t b_used     = 0;
	size_t merge_used = 0;

	merge_load(a, &a_used, &a_buffer);
	merge_load(b, &b_used, &b_buffer);

	merge_used = a_used + b_used;

	calloc(merge_used, 1);

	memcpy(merge_buffer, a_buffer, a_used);
	memcpy(merge_buffer + a_used, b_buffer, b_used);
	qsort(merge_buffer, merge_used / (sizeof(u32) * 3), sizeof(u32) * 3, compare_hash);

	int file_fd = open(merge, O_WRONLY | O_CREAT, 0600);
	if (file_fd == -1) {
		log_fatal("saving merged analysis open failed");
	}

	ssize_t write_size = write(file_fd, &merge_used, sizeof(merge_used));
	if (write_size == -1) {
		log_fatal("saving merged analysis write failed");
	}
	if (write_size != sizeof(merge_used)) {
		log_fatal("saving merged analysis size mismatch");
	}

	write_size = write(file_fd, merge_buffer, merge_used);
	if (write_size == -1) {
		log_fatal("saving merged analysis write failed");
	}
	if (write_size >= 0 && (size_t)write_size != merge_used) {
		log_fatal("saving merged analysis size mismatch");
	}
	close(file_fd);
}

static void
destroy()
{
	free(hashes);
	hashes       = NULL;
	hashes_size  = 0;
	current_used = 0;
}

static void
init(char *filename)
{
	init_logging();

	char *env_size = getenv("ANALYSIS_SIZE");
	if (env_size == NULL) {
		log_fatal("Missing ANALYSIS_SIZE environment variable.");
	}
	size_t size = strtoull(env_size, NULL, 0);
	if (size == 0) {
		log_fatal("ANALYSIS_SIZE invalid");
	}

	if (size % (sizeof(u32) * 3) != 0) {
		log_fatal("invalid analysis size");
	}

	hashes = (u8 *)calloc(1, size);
	if (hashes == NULL) {
		log_fatal("malloc failed");
	}
	hashes_size  = size;
	current_used = 0;
	if (filename != NULL) {
		load_from_file(filename);
	}
}

static void
create_analysis(analysis_api *s)
{
	s->version     = VERSION_ONE;
	s->name        = "pt_hash";
	s->description = "This decodes Intel PT data, seperates TNT and TIP packets, and then hashes them with CRC32";
	s->initialize  = init;
	s->add         = add;
	s->save        = save_to_file;
	s->destroy     = destroy;
	s->merge       = merge;
}

analysis_api_getter get_analysis_api = create_analysis;
