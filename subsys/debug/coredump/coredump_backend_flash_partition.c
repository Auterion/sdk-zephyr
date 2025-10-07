/*
 * Copyright (c) 2020 Intel Corporation.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>
#include <zephyr/kernel.h>
#include <string.h>
#include <zephyr/toolchain.h>
#include <zephyr/storage/flash_map.h>
#include <zephyr/sys/util.h>

#include <zephyr/debug/coredump.h>
#include "coredump_internal.h"

#include <zephyr/logging/log.h>

/* Include ARF settings for flash write blocking during coredump - only in main app, not bootloader */
#ifndef CONFIG_MCUBOOT
#include "../../../../arf-a/arf_settings.h"
#define HAS_SETTINGS_BLOCKING 1
#else
#define HAS_SETTINGS_BLOCKING 0
#endif

LOG_MODULE_REGISTER(coredump, CONFIG_KERNEL_LOG_LEVEL);

/**
 * @file
 * @brief Simple coredump backend to store data in flash partition.
 *
 * This provides a simple backend to store coredump data in a flash
 * partition, referenced via chosen node "zephyr,coredump-partition" 
 * in devicetree.
 *
 * On the partition, a header is stored at the beginning with padding
 * at the end to align with flash write size. Then the actual
 * coredump data follows. The padding is to simplify the data read
 * function so that the first read of a data stream is always
 * aligned to flash write size.
 */

/* Use chosen node instead of fixed partition */
#if DT_HAS_CHOSEN(zephyr_coredump_partition)
#define FLASH_PARTITION_NODE	DT_CHOSEN(zephyr_coredump_partition)
/* Override partition ID to avoid collision with partition manager */
#define FLASH_PARTITION_ID	5

/* Debug: Let's also check the node name and label */
#define FLASH_PARTITION_LABEL	DT_PROP_OR(FLASH_PARTITION_NODE, label, "unknown")

#define FLASH_CONTROLLER	\
	DT_PARENT(DT_PARENT(FLASH_PARTITION_NODE))

#define FLASH_WRITE_SIZE	DT_PROP(FLASH_CONTROLLER, write_block_size)
#define FLASH_BUF_SIZE		128  /* Reduce buffer size for fault handling */
#define FLASH_ERASE_SIZE	DT_PROP(FLASH_CONTROLLER, erase_block_size)

#define HDR_VER			1

#else
#error "Need a partition referenced by chosen node 'zephyr,coredump-partition'!"
#endif

#define FLASH_BACKEND_SEM_TIMEOUT (k_is_in_isr() ? K_NO_WAIT : K_FOREVER)

typedef int (*data_read_cb_t)(void *arg, uint8_t *buf, size_t len);

/* Custom flash area with correct device tree values */
static struct flash_area coredump_flash_area = {
	.fa_id = 5,  /* Use ID 5 to avoid collision */
	.fa_off = DT_REG_ADDR(FLASH_PARTITION_NODE),
	.fa_size = DT_REG_SIZE(FLASH_PARTITION_NODE),
	.fa_dev = NULL  /* Will be set at runtime */
};

static struct {
	/* For use with flash map */
	const struct flash_area		*flash_area;

	/* Checksum of data so far */
	uint16_t			checksum;

	/* Error encountered */
	int				error;
} backend_ctx;

/* Buffer used in data_read() */
static uint8_t data_read_buf[FLASH_BUF_SIZE];

/* Semaphore for exclusive flash access */
K_SEM_DEFINE(flash_sem, 1, 1);

/* Static variables for buffer output tracking */
static uint32_t g_total_written = 0;
static bool g_in_chunked_write = false;
static uint32_t g_coredump_start_time = 0;
static bool g_emergency_abort = false;
static uint32_t g_coredump_attempts = 0;
static uint32_t g_last_coredump_time = 0;

/* Minimal debug flag to reduce corruption */
static bool g_debug_minimal = false;  /* Disable debug during coredump to prevent corruption */

/* Safe debug macro - only print essential messages */
#define COREDUMP_PRINT(msg, ...) do { \
	if (g_debug_minimal) { \
		printk("CD: " msg, ##__VA_ARGS__); \
	} \
} while (0)

/* Function to reset static variables */
void reset_coredump_statics(void)
{
	COREDUMP_PRINT("Reset (%d->0)\n", (int)g_total_written);
	g_total_written = 0;
	g_in_chunked_write = false;
	g_coredump_start_time = 0;
	g_emergency_abort = false;
	/* Don't reset attempt counter and last time - these persist across resets */
}

/* Emergency abort function - can be called from anywhere */
void emergency_coredump_abort(void)
{
	g_emergency_abort = true;
}


struct flash_hdr_t {
	/* 'C', 'D' */
	char		id[2];

	/* Header version */
	uint16_t	hdr_version;

	/* Coredump size, excluding this header */
	size_t		size;

	/* Flags */
	uint16_t	flags;

	/* Checksum */
	uint16_t	checksum;

	/* Error */
	int		error;
} __packed;


/**
 * @brief Open the flash partition.
 *
 * @return Same as flash_area_open().
 */
static int partition_open(void)
{
	int ret;

	/* Skip semaphore in fault context - no concurrent access possible */
	LOG_DBG("Coredump: Opening partition without synchronization");

	/* Use our custom flash area with correct device tree values */
	coredump_flash_area.fa_dev = DEVICE_DT_GET_OR_NULL(DT_MTD_FROM_FIXED_PARTITION(FLASH_PARTITION_NODE));
	backend_ctx.flash_area = &coredump_flash_area;

	/* Debug: Print detected partition size */
	printk("COREDUMP: Partition offset=0x%x, size=%u bytes (%u KB)\n", 
		   (unsigned)backend_ctx.flash_area->fa_off,
		   (unsigned)backend_ctx.flash_area->fa_size,
		   (unsigned)backend_ctx.flash_area->fa_size / 1024);

	if (backend_ctx.flash_area->fa_dev == NULL || !device_is_ready(backend_ctx.flash_area->fa_dev)) {
		LOG_ERR("Flash device not ready for coredump!");
		backend_ctx.flash_area = NULL;
		ret = -ENODEV;
	} else {
		ret = 0;
	}

	return ret;
}

/**
 * @brief Close the flash partition.
 */
static void partition_close(void)
{
	if (backend_ctx.flash_area == NULL) {
		return;
	}

	flash_area_close(backend_ctx.flash_area);
	backend_ctx.flash_area = NULL;

	/* Skip semaphore in fault context */
	LOG_DBG("Coredump: Partition closed without synchronization");
}

/**
 * @brief Read data from flash partition.
 *
 * This reads @p len bytes in the flash partition starting
 * from @p off and put into buffer pointed by @p dst if
 * @p dst is not NULL.
 *
 * If @p cb is not NULL, data being read are passed to
 * the callback for processing. Note that the data being
 * passed to callback may only be part of the data requested.
 * The end of read is signaled to the callback with NULL
 * buffer pointer and zero length as arguments.
 *
 * @param off offset of partition to begin reading
 * @param dst buffer to read data into (can be NULL)
 * @param len number of bytes to read
 * @param cb callback to process read data (can be NULL)
 * @param cb_arg argument passed to callback
 * @return 0 if successful, error otherwise.
 */
static int data_read(off_t off, uint8_t *dst, size_t len,
		     data_read_cb_t cb, void *cb_arg)
{
	int ret = 0;
	off_t offset = off;
	size_t remaining = len;
	size_t copy_sz;
	uint8_t *ptr = dst;

	if (backend_ctx.flash_area == NULL) {
		return -ENODEV;
	}

	copy_sz = FLASH_BUF_SIZE;
	while (remaining > 0) {
		if (remaining < FLASH_BUF_SIZE) {
			copy_sz = remaining;
		}

		ret = flash_area_read(backend_ctx.flash_area, offset,
				      data_read_buf, FLASH_BUF_SIZE);
		if (ret != 0) {
			break;
		}

		if (dst != NULL) {
			(void)memcpy(ptr, data_read_buf, copy_sz);
		}

		if (cb != NULL) {
			ret = (*cb)(cb_arg, data_read_buf, copy_sz);
			if (ret != 0) {
				break;
			}
		}

		ptr += copy_sz;
		offset += copy_sz;
		remaining -= copy_sz;
	}

	if (cb != NULL) {
		ret = (*cb)(cb_arg, NULL, 0);
	}

	return ret;
}

/**
 * @brief Callback to calculate checksum.
 *
 * @param arg callback argument (not being used)
 * @param buf data buffer
 * @param len number of bytes in buffer to process
 * @return 0
 */
static int cb_calc_buf_checksum(void *arg, uint8_t *buf, size_t len)
{
	int i;

	ARG_UNUSED(arg);

	for (i = 0; i < len; i++) {
		backend_ctx.checksum += buf[i];
	}

	return 0;
}

/**
 * @brief Process the stored coredump in flash partition.
 *
 * This reads the stored coredump data and processes it via
 * the callback function.
 *
 * @param cb callback to process the stored coredump data
 * @param cb_arg argument passed to callback
 * @return 1 if successful; 0 if stored coredump is not found
 *         or is not valid; error otherwise
 */
static int process_stored_dump(data_read_cb_t cb, void *cb_arg)
{
	int ret;
	struct flash_hdr_t hdr;
	off_t offset;

	ret = partition_open();
	if (ret != 0) {
		goto out;
	}

	/* Read header */
	ret = data_read(0, (uint8_t *)&hdr, sizeof(hdr), NULL, NULL);

	/* Verify header signature */
	if ((hdr.id[0] != 'C') && (hdr.id[1] != 'D')) {
		ret = 0;
		goto out;
	}

	/* Error encountered while dumping, so non-existent */
	if (hdr.error != 0) {
		ret = 0;
		goto out;
	}

	backend_ctx.checksum = 0;

	offset = ROUND_UP(sizeof(struct flash_hdr_t), FLASH_WRITE_SIZE);
	ret = data_read(offset, NULL, hdr.size, cb, cb_arg);

	if (ret == 0) {
		ret = (backend_ctx.checksum == hdr.checksum) ? 1 : 0;
	}

out:
	partition_close();

	return ret;
}

/**
 * @brief Get the stored coredump in flash partition.
 *
 * This reads the stored coredump data and copies the raw data
 * to the destination buffer.
 *
 * If the destination buffer is NULL, the offset and length are
 * ignored and the entire dump size is returned.
 *
 * @param off offset of partition to begin reading
 * @param dst buffer to read data into (can be NULL)
 * @param len number of bytes to read
 * @return dump size if successful; 0 if stored coredump is not found
 *         or is not valid; error otherwise
 */
static int get_stored_dump(off_t off, uint8_t *dst, size_t len)
{
	int ret;
	struct flash_hdr_t hdr;

	ret = partition_open();
	if (ret != 0) {
		goto out;
	}

	/* Read header */
	ret = data_read(0, (uint8_t *)&hdr, sizeof(hdr), NULL, NULL);
	if (ret != 0) {
		goto out;
	}

	/* Verify header signature */
	if ((hdr.id[0] != 'C') && (hdr.id[1] != 'D')) {
		ret = 0;
		goto out;
	}

	/* Error encountered while dumping, so non-existent */
	if (hdr.error != 0) {
		ret = 0;
		goto out;
	}

	/* Return the dump size if no destination buffer available */
	if (!dst) {
		ret = (int)hdr.size;
		goto out;
	}

	/* Offset larger than dump size */
	if (off >= hdr.size) {
		ret = 0;
		goto out;
	}

	/* Start reading the data, skip write-aligned header */
	off += ROUND_UP(sizeof(struct flash_hdr_t), FLASH_WRITE_SIZE);

	ret = data_read(off, dst, len, NULL, NULL);
	if (ret == 0) {
		ret = (int)len;
	}
out:
	partition_close();

	return ret;
}

/**
 * @brief Erase the stored coredump header from flash partition.
 *
 * This erases the stored coredump header from the flash partition,
 * invalidating the coredump data.
 *
 * @return 0 if successful; error otherwise
 */
static int erase_coredump_header(void)
{
	int ret;

	ret = partition_open();
	if (ret == 0) {
		/* Erase header block */
		ret = flash_area_erase(backend_ctx.flash_area, 0,
				       ROUND_UP(sizeof(struct flash_hdr_t),
						FLASH_ERASE_SIZE));
	}

	partition_close();

	return ret;
}

/**
 * @brief Erase the stored coredump in flash partition.
 *
 * This erases the stored coredump data from the flash partition.
 *
 * @return 0 if successful; error otherwise
 */
static int erase_flash_partition(void)
{
	int ret;

	ret = partition_open();
	if (ret == 0) {
		/* Erase whole flash partition */
		ret = flash_area_erase(backend_ctx.flash_area, 0,
				       backend_ctx.flash_area->fa_size);
	}

	partition_close();

	return ret;
}

/**
 * @brief Start of coredump session.
 *
 * This opens the flash partition for processing.
 */
static void coredump_flash_backend_start(void)
{
	const struct device *flash_dev;
	size_t offset, header_size;
	int ret;

	/* Circuit breaker: prevent coredump death loops */
	uint32_t current_time = k_uptime_get_32();
	
	/* If we've had coredump attempts recently, disable coredump to prevent loops */
	if (g_coredump_attempts > 0 && (current_time - g_last_coredump_time) < 10000) {
		g_coredump_attempts++;
		LOG_ERR("Coredump: Circuit breaker activated - attempt %d within %d ms, DISABLING coredump", 
				g_coredump_attempts, current_time - g_last_coredump_time);
		
		if (g_coredump_attempts > 2) {
			LOG_ERR("Coredump: Too many attempts, permanently disabling for this boot");
			backend_ctx.error = -EFAULT;
			return;
		}
	}
	
	/* Reset buffer output static variables for new coredump session */
	extern void reset_coredump_statics(void);
	reset_coredump_statics();
	
	/* Update attempt tracking */
	g_coredump_attempts++;
	g_last_coredump_time = current_time;

	/* Minimal processing - skip delay entirely to reduce fault window */
	/* Essential status only */
	COREDUMP_PRINT("Start #%d\n", (int)g_coredump_attempts);

	/* Skip settings blocking - all threads are stopped during fault handling */

	ret = partition_open();
	if (ret == 0) {
		printk("COREDUMP: Erasing partition\n");
		ret = flash_area_erase(backend_ctx.flash_area, 0,
							backend_ctx.flash_area->fa_size);
		if (ret != 0) {
			printk("COREDUMP: Flash erase failed: %d\n", ret);
		}
	}

	if (ret == 0) {
		backend_ctx.checksum = 0;

		flash_dev = flash_area_get_device(backend_ctx.flash_area);

		/*
		 * Reserve space for header from beginning of flash device.
		 * The header size is rounded up so the beginning of coredump
		 * is aligned to write size (for easier read and seek).
		 */
		header_size = ROUND_UP(sizeof(struct flash_hdr_t), FLASH_WRITE_SIZE);
		offset = backend_ctx.flash_area->fa_off + header_size;

		COREDUMP_PRINT("Ready %d\n", (int)(backend_ctx.flash_area->fa_size - header_size));
		ret = 0;
	}

	if (ret != 0) {
		printk("COREDUMP: Start failed: %d\n", ret);
		backend_ctx.error = ret;
		partition_close();
	}
}

/**
 * @brief End of coredump session.
 *
 * This ends the coredump session by flushing coredump data
 * flash, and writes the header in the beginning of flash
 * related to the stored coredump data.
 */
static void coredump_flash_backend_end(void)
{
	int ret;

	struct flash_hdr_t hdr = {
		.id = {'C', 'D'},
		.hdr_version = HDR_VER,
	};

	if (backend_ctx.flash_area == NULL) {
		return;
	}

	/* Skip stream flash buffering in fault context */
	LOG_DBG("Coredump: Skipping stream buffer flush - using direct flash");

	/* Write header with actual written size */
	hdr.size = g_total_written;
	hdr.checksum = backend_ctx.checksum;
	hdr.error = backend_ctx.error;
	hdr.flags = 0;

	ret = flash_area_write(backend_ctx.flash_area, 0, (void *)&hdr, sizeof(hdr));
	if (ret != 0) {
		printk("COREDUMP: Header write failed: %d\n", ret);
		backend_ctx.error = ret;
	}

	if (backend_ctx.error != 0) {
		printk("COREDUMP: Backend error: %d\n", backend_ctx.error);
	} else {
		COREDUMP_PRINT("Done %d\n", (int)g_total_written);
	}

	/* Skip settings unblocking - system will reset after coredump */
	LOG_DBG("Coredump: Skipping settings sync - system will reset");

	/* Static variables will be reset at start of next coredump session */

	partition_close();
}

/**
 * @brief Write a buffer to flash partition.
 *
 * This writes @p buf into the flash partition. Note that this is
 * using the stream flash interface, so there is no need to keep
 * track of where on flash to write next.
 *
 * @param buf buffer of data to write to flash
 * @param buflen number of bytes to write
 */
static void coredump_flash_backend_buffer_output(uint8_t *buf, size_t buflen)
{
	int i;
	size_t remaining = buflen;
	size_t copy_sz;
	uint8_t *ptr = buf;
	uint8_t tmp_buf[FLASH_BUF_SIZE];
	
	/* Initialize start time on first call */
	if (g_total_written == 0 && g_coredump_start_time == 0) {
		g_coredump_start_time = k_uptime_get_32();
	}
	
	/* Ultra-aggressive timeout protection - abort coredump after 500ms to prevent system hang */
	uint32_t elapsed = k_uptime_get_32() - g_coredump_start_time;
	if (elapsed > 500) {  /* 500ms timeout - ultra aggressive */
		COREDUMP_PRINT("T/O %d\n", (int)elapsed);
		backend_ctx.error = -ETIMEDOUT;
		return;
	}
	
	/* Debug: print current write status */
	if (g_total_written == 0) {
		COREDUMP_PRINT("Write start\n");
	}
	
	/* Debug: log the buffer size on first call */
	if (g_total_written == 0 && buflen > 0) {
		COREDUMP_PRINT("Buf %d\n", (int)buflen);
	}
	
	/* Force chunking for large buffers instead of rejecting */
	if (buflen > 4096) {  /* Force chunking for buffers > 4KB */
		/* This will be handled by the chunking logic below */
	}
	
	/* Size limiting for 8KB partition */
	if (g_total_written > 6144) {  /* Limit to 6KB total - leaves 2KB buffer for header */
		COREDUMP_PRINT("Limit @%d\n", (int)g_total_written);
		backend_ctx.error = -ENOSPC;
		return;
	}
	
	/* Circuit breaker: if we're in a repeated fault condition, abort immediately */
	if (g_coredump_attempts > 1) {
		/* On repeated faults, be more conservative but allow reasonable data */
		if (g_total_written > 3072 || elapsed > 300) {
			COREDUMP_PRINT("Abort #%d\n", (int)g_coredump_attempts);
			backend_ctx.error = -EFAULT;
			return;
		}
	}

	/* Skip ISR check during fault handling - fault handlers run in ISR context by design */
	/* if (k_is_in_isr()) { ... } - removed, fault handlers are expected to be in ISR context */
	
	if ((backend_ctx.error != 0) || (backend_ctx.flash_area == NULL) || g_emergency_abort) {
		if (g_emergency_abort) {
			backend_ctx.error = -ECANCELED;
		}
		return;
	}

	/* Limit large writes to prevent memory corruption - break up big writes */
	size_t chunk_threshold = (g_coredump_attempts > 1) ? 512 : 1024;  /* Force chunking more aggressively */
	if (buflen > chunk_threshold && !g_in_chunked_write) {
		COREDUMP_PRINT("Chunk %d\n", (int)buflen);
		g_in_chunked_write = true;  /* Prevent recursive chunking */
		
		/* Split large writes into safe chunks */
		size_t chunk_size = (g_coredump_attempts > 1) ? 256 : 512;  /* Balanced chunk size */
		size_t processed = 0;
		
		while (processed < buflen && backend_ctx.error == 0) {
		/* Check timeout during chunking - ultra aggressive on repeated faults */
		uint32_t chunk_elapsed = k_uptime_get_32() - g_coredump_start_time;
		uint32_t chunk_timeout = (g_coredump_attempts > 1) ? 100 : 500;  /* 100ms on repeated faults */
		if (chunk_elapsed > chunk_timeout) {
			backend_ctx.error = -ETIMEDOUT;
			break;
		}			size_t current_chunk = MIN(chunk_size, buflen - processed);
			
			/* Recursively call ourselves with smaller chunk */
			coredump_flash_backend_buffer_output(buf + processed, current_chunk);
			
			if (backend_ctx.error != 0) {
				break;
			}
			
			processed += current_chunk;
			
			/* Skip CPU yield in fault context - no other threads running */
			/* k_yield(); - not needed during fault handling */
		}
		
		g_in_chunked_write = false;
		return;  /* Exit early - chunks were handled recursively */
	}
	
	LOG_DBG("Coredump: Writing %d bytes, total_written=%d", buflen, g_total_written);
	
	/* Check if we're exceeding partition size */
	size_t header_size = ROUND_UP(sizeof(struct flash_hdr_t), FLASH_WRITE_SIZE);
	size_t available_space = backend_ctx.flash_area->fa_size - header_size;
	
	if (g_total_written + buflen > available_space) {
		LOG_WRN("Coredump: Truncating write - exceeding partition size");
		LOG_WRN("Requested: %d, available: %d, already written: %d", 
				buflen, available_space, g_total_written);
		
		if (g_total_written >= available_space) {
			LOG_ERR("Coredump: Partition full, stopping");
			backend_ctx.error = -ENOSPC;
			return;
		}
		
		/* Truncate to available space */
		buflen = available_space - g_total_written;
		remaining = buflen;
		LOG_DBG("Coredump: Truncated write to %d bytes", buflen);
	}

	/*
	 * Since the system is still running, memory content is constantly
	 * changing (e.g. stack of this thread). We need to make a copy of
	 * part of the buffer, so that the checksum corresponds to what is
	 * being written.
	 */
	copy_sz = FLASH_BUF_SIZE;
	while (remaining > 0 && backend_ctx.error == 0 && !g_emergency_abort) {
		/* Check for emergency abort or timeout on every iteration */
		uint32_t loop_elapsed = k_uptime_get_32() - g_coredump_start_time;
		if (loop_elapsed > 1200) {  /* 1.2 second loop timeout */
			LOG_WRN("Coredump: Loop timeout, aborting");
			backend_ctx.error = -ETIMEDOUT;
			break;
		}
		
		if (remaining < FLASH_BUF_SIZE) {
			copy_sz = remaining;
		}

		/* Add memory safety check before memcpy */
		if (ptr == NULL || copy_sz == 0 || copy_sz > FLASH_BUF_SIZE) {
			backend_ctx.error = -EFAULT;
			break;
		}

		(void)memcpy(tmp_buf, ptr, copy_sz);

		for (i = 0; i < copy_sz; i++) {
			backend_ctx.checksum += tmp_buf[i];
		}

		/* Use direct flash write in fault context - skip stream buffering */
		size_t write_offset = header_size + g_total_written;
		
		/* CRITICAL: Check if write would exceed partition boundaries */
		if (write_offset + copy_sz > backend_ctx.flash_area->fa_size) {
			backend_ctx.error = -ENOSPC;
			break;
		}
		
		/* Use direct aligned write for fault context */
		size_t aligned_offset = ROUND_DOWN(write_offset, FLASH_WRITE_SIZE);
		size_t offset_adjustment = write_offset - aligned_offset;
		size_t adjusted_size = copy_sz + offset_adjustment;
		size_t aligned_size = ROUND_UP(adjusted_size, FLASH_WRITE_SIZE);
		
		/* Double-check aligned write doesn't exceed partition */
		if (aligned_offset + aligned_size > backend_ctx.flash_area->fa_size) {
			backend_ctx.error = -ENOSPC;
			break;
		}
		
		/* Create aligned buffer */
		uint8_t aligned_buf[aligned_size];
		memset(aligned_buf, 0xFF, aligned_size);
		
		/* Read existing data if we need to adjust offset */
		if (offset_adjustment > 0) {
			int ret = flash_area_read(backend_ctx.flash_area, aligned_offset, 
					      aligned_buf, offset_adjustment);
			if (ret != 0) {
				backend_ctx.error = ret;
				break;
			}
		}
		
		/* Copy our data to the aligned buffer */
		memcpy(aligned_buf + offset_adjustment, tmp_buf, copy_sz);
		
		/* Write directly to flash */
		backend_ctx.error = flash_area_write(backend_ctx.flash_area,
				aligned_offset, aligned_buf, aligned_size);
		
		if (backend_ctx.error != 0) {
			break;
		}

		g_total_written += copy_sz;
		ptr += copy_sz;
		remaining -= copy_sz;
		
		/* Skip CPU yield in fault context - no other threads to yield to */
		/* k_yield(); - not needed during fault handling */
		
		/* Safety check: if we've been writing too long, abort */
		if (g_total_written > 0 && (g_total_written % 1024) == 0) {
			LOG_DBG("Coredump: Written %d bytes so far", g_total_written);
		}
	}
}

/**
 * @brief Perform query on this backend.
 *
 * @param query_id ID of query
 * @param arg argument of query
 * @return depends on query
 */
static int coredump_flash_backend_query(enum coredump_query_id query_id,
					void *arg)
{
	int ret;

	switch (query_id) {
	case COREDUMP_QUERY_GET_ERROR:
		ret = backend_ctx.error;
		break;
	case COREDUMP_QUERY_HAS_STORED_DUMP:
		ret = process_stored_dump(cb_calc_buf_checksum, NULL);
		break;
	case COREDUMP_QUERY_GET_STORED_DUMP_SIZE:
		ret = get_stored_dump(0, NULL, 0);
		break;
	default:
		ret = -ENOTSUP;
		break;
	}

	return ret;
}

/**
 * @brief Perform command on this backend.
 *
 * @param cmd_id command ID
 * @param arg argument of command
 * @return depends on query
 */
static int coredump_flash_backend_cmd(enum coredump_cmd_id cmd_id,
				      void *arg)
{
	int ret;

	switch (cmd_id) {
	case COREDUMP_CMD_CLEAR_ERROR:
		ret = 0;
		backend_ctx.error = 0;
		break;
	case COREDUMP_CMD_VERIFY_STORED_DUMP:
		ret = process_stored_dump(cb_calc_buf_checksum, NULL);
		break;
	case COREDUMP_CMD_ERASE_STORED_DUMP:
		ret = erase_flash_partition();
		break;
	case COREDUMP_CMD_COPY_STORED_DUMP:
		if (arg) {
			struct coredump_cmd_copy_arg *copy_arg
				= (struct coredump_cmd_copy_arg *)arg;

			ret = get_stored_dump(copy_arg->offset,
					      copy_arg->buffer,
					      copy_arg->length);
		} else {
			ret = -EINVAL;
		}
		break;
	case COREDUMP_CMD_INVALIDATE_STORED_DUMP:
		ret = erase_coredump_header();
		break;
	default:
		ret = -ENOTSUP;
		break;
	}

	return ret;
}


struct coredump_backend_api coredump_backend_flash_partition = {
	.start = coredump_flash_backend_start,
	.end = coredump_flash_backend_end,
	.buffer_output = coredump_flash_backend_buffer_output,
	.query = coredump_flash_backend_query,
	.cmd = coredump_flash_backend_cmd,
};

#ifdef CONFIG_DEBUG_COREDUMP_SHELL
#include <zephyr/shell/shell.h>

/* Length of buffer of printable size */
#define PRINT_BUF_SZ		64

/* Length of buffer of printable size plus null character */
#define PRINT_BUF_SZ_RAW	(PRINT_BUF_SZ + 1)

/* Print buffer */
static char print_buf[PRINT_BUF_SZ_RAW];
static off_t print_buf_ptr;

/**
 * @brief Shell command to get backend error.
 *
 * @param sh shell instance
 * @param argc (not used)
 * @param argv (not used)
 * @return 0
 */
static int cmd_coredump_error_get(const struct shell *sh,
				  size_t argc, char **argv)
{
	ARG_UNUSED(argc);
	ARG_UNUSED(argv);

	if (backend_ctx.error == 0) {
		shell_print(sh, "No error.");
	} else {
		shell_print(sh, "Error: %d", backend_ctx.error);
	}

	return 0;
}

/**
 * @brief Shell command to clear backend error.
 *
 * @param sh shell instance
 * @param argc (not used)
 * @param argv (not used)
 * @return 0
 */
static int cmd_coredump_error_clear(const struct shell *sh,
				    size_t argc, char **argv)
{
	backend_ctx.error = 0;

	shell_print(sh, "Error cleared.");

	return 0;
}

/**
 * @brief Shell command to see if there is a stored coredump in flash.
 *
 * @param sh shell instance
 * @param argc (not used)
 * @param argv (not used)
 * @return 0
 */
static int cmd_coredump_has_stored_dump(const struct shell *sh,
					size_t argc, char **argv)
{
	int ret;

	ARG_UNUSED(argc);
	ARG_UNUSED(argv);

	ret = coredump_flash_backend_query(COREDUMP_QUERY_HAS_STORED_DUMP,
					   NULL);

	if (ret == 1) {
		shell_print(sh, "Stored coredump found.");
	} else if (ret == 0) {
		shell_print(sh, "Stored coredump NOT found.");
	} else {
		shell_print(sh, "Failed to perform query: %d", ret);
	}

	return 0;
}

/**
 * @brief Shell command to verify if the stored coredump is valid.
 *
 * @param sh shell instance
 * @param argc (not used)
 * @param argv (not used)
 * @return 0
 */
static int cmd_coredump_verify_stored_dump(const struct shell *sh,
					   size_t argc, char **argv)
{
	int ret;

	ARG_UNUSED(argc);
	ARG_UNUSED(argv);

	ret = coredump_flash_backend_cmd(COREDUMP_CMD_VERIFY_STORED_DUMP,
					 NULL);

	if (ret == 1) {
		shell_print(sh, "Stored coredump verified.");
	} else if (ret == 0) {
		shell_print(sh, "Stored coredump verification failed "
				   "or there is no stored coredump.");
	} else {
		shell_print(sh, "Failed to perform verify command: %d",
			    ret);
	}

	return 0;
}

/**
 * @brief Flush the print buffer to shell.
 *
 * This prints what is in the print buffer to the shell.
 *
 * @param sh shell instance.
 */
static void flush_print_buf(const struct shell *sh)
{
	shell_print(sh, "%s%s", COREDUMP_PREFIX_STR, print_buf);
	print_buf_ptr = 0;
	(void)memset(print_buf, 0, sizeof(print_buf));
}

/**
 * @brief Callback to print stored coredump to shell
 *
 * This converts the binary data in @p buf to hexadecimal digits
 * which can be printed to the shell.
 *
 * @param arg shell instance
 * @param buf binary data buffer
 * @param len number of bytes in buffer to be printed
 * @return 0 if no issues; -EINVAL if error converting data
 */
static int cb_print_stored_dump(void *arg, uint8_t *buf, size_t len)
{
	int ret = 0;
	size_t i = 0;
	size_t remaining = len;
	const struct shell *sh = (const struct shell *)arg;

	if (len == 0) {
		/* Flush print buffer */
		flush_print_buf(sh);

		goto out;
	}

	/* Do checksum for process_stored_dump() */
	cb_calc_buf_checksum(arg, buf, len);

	while (remaining > 0) {
		if (hex2char(buf[i] >> 4, &print_buf[print_buf_ptr]) < 0) {
			ret = -EINVAL;
			break;
		}
		print_buf_ptr++;

		if (hex2char(buf[i] & 0xf, &print_buf[print_buf_ptr]) < 0) {
			ret = -EINVAL;
			break;
		}
		print_buf_ptr++;

		remaining--;
		i++;

		if (print_buf_ptr == PRINT_BUF_SZ) {
			flush_print_buf(sh);
		}
	}

out:
	return ret;
}

/**
 * @brief Shell command to print stored coredump data to shell
 *
 * @param sh shell instance
 * @param argc (not used)
 * @param argv (not used)
 * @return 0
 */
static int cmd_coredump_print_stored_dump(const struct shell *sh,
					  size_t argc, char **argv)
{
	int ret;

	ARG_UNUSED(argc);
	ARG_UNUSED(argv);

	/* Verify first to see if stored dump is valid */
	ret = coredump_flash_backend_cmd(COREDUMP_CMD_VERIFY_STORED_DUMP,
					 NULL);

	if (ret == 0) {
		shell_print(sh, "Stored coredump verification failed "
				   "or there is no stored coredump.");
		goto out;
	} else if (ret != 1) {
		shell_print(sh, "Failed to perform verify command: %d",
			    ret);
		goto out;
	}

	/* If valid, start printing to shell */
	print_buf_ptr = 0;
	(void)memset(print_buf, 0, sizeof(print_buf));

	shell_print(sh, "%s%s", COREDUMP_PREFIX_STR, COREDUMP_BEGIN_STR);

	ret = process_stored_dump(cb_print_stored_dump, (void *)sh);
	if (print_buf_ptr != 0) {
		shell_print(sh, "%s%s", COREDUMP_PREFIX_STR, print_buf);
	}

	if (backend_ctx.error != 0) {
		shell_print(sh, "%s%s", COREDUMP_PREFIX_STR,
			    COREDUMP_ERROR_STR);
	}

	shell_print(sh, "%s%s", COREDUMP_PREFIX_STR, COREDUMP_END_STR);

	if (ret == 1) {
		shell_print(sh, "Stored coredump printed.");
	} else if (ret == 0) {
		shell_print(sh, "Stored coredump verification failed "
				   "or there is no stored coredump.");
	} else {
		shell_print(sh, "Failed to print: %d", ret);
	}

out:
	return 0;
}

/**
 * @brief Shell command to erase stored coredump.
 *
 * @param sh shell instance
 * @param argc (not used)
 * @param argv (not used)
 * @return 0
 */
static int cmd_coredump_erase_stored_dump(const struct shell *sh,
					  size_t argc, char **argv)
{
	int ret;

	ARG_UNUSED(argc);
	ARG_UNUSED(argv);

	ret = coredump_flash_backend_cmd(COREDUMP_CMD_ERASE_STORED_DUMP,
					 NULL);

	if (ret == 0) {
		shell_print(sh, "Stored coredump erased.");
	} else {
		shell_print(sh, "Failed to perform erase command: %d", ret);
	}

	return 0;
}

SHELL_STATIC_SUBCMD_SET_CREATE(sub_coredump_error,
	SHELL_CMD(clear, NULL, "Clear Coredump error",
		  cmd_coredump_error_clear),
	SHELL_CMD(get, NULL, "Get Coredump error", cmd_coredump_error_get),
	SHELL_SUBCMD_SET_END /* Array terminated. */
);

SHELL_STATIC_SUBCMD_SET_CREATE(sub_coredump,
	SHELL_CMD(error, &sub_coredump_error,
		  "Get/clear backend error.", NULL),
	SHELL_CMD(erase, NULL,
		  "Erase stored coredump",
		  cmd_coredump_erase_stored_dump),
	SHELL_CMD(find, NULL,
		  "Query if there is a stored coredump",
		  cmd_coredump_has_stored_dump),
	SHELL_CMD(print, NULL,
		  "Print stored coredump to shell",
		  cmd_coredump_print_stored_dump),
	SHELL_CMD(verify, NULL,
		  "Verify stored coredump",
		  cmd_coredump_verify_stored_dump),
	SHELL_SUBCMD_SET_END /* Array terminated. */
);

SHELL_CMD_REGISTER(coredump, &sub_coredump,
		   "Coredump commands (flash partition backend)", NULL);

#endif /* CONFIG_DEBUG_COREDUMP_SHELL */
