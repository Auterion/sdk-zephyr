/*
 * Copyright (c) 2020 Intel Corporation.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>
#include <zephyr/kernel.h>
#include <string.h>
#include <zephyr/toolchain.h>
#include <zephyr/sys/util.h>
#include <zephyr/devicetree.h>

#include <zephyr/debug/coredump.h>
#include "coredump_internal.h"

/**
 * @file
 * @brief Coredump backend to store data in reserved RAM.
 *
 * This provides a backend to store coredump data in a reserved
 * memory region, referenced via chosen node "zephyr,coredump-memory" 
 * in devicetree.
 *
 * The coredump data is stored directly in the reserved memory region
 * with a header at the beginning containing size and validation info.
 * The data persists across resets as long as power is maintained.
 */

/* Use chosen node for reserved memory */
#if DT_HAS_CHOSEN(zephyr_coredump_memory)
#define COREDUMP_MEMORY_NODE	DT_CHOSEN(zephyr_coredump_memory)
#define COREDUMP_MEMORY_ADDR	DT_REG_ADDR(COREDUMP_MEMORY_NODE)
#define COREDUMP_MEMORY_SIZE	DT_REG_SIZE(COREDUMP_MEMORY_NODE)
#else
#error "Need a memory region referenced by chosen node 'zephyr,coredump-memory'!"
#endif

#define HDR_VER			1
#define COREDUMP_RAM_MAGIC	0x444D4152  /* "RAMD" in little endian */

typedef int (*data_read_cb_t)(void *arg, uint8_t *buf, size_t len);

static struct {
	/* Pointer to reserved memory area */
	uint8_t *memory_area;
	
	/* Size of reserved memory */
	size_t memory_size;
	
	/* Current write position */
	size_t write_pos;
	
	/* Checksum of data so far */
	uint16_t checksum;

	/* Error encountered */
	int error;

	/* Truncation occurred */
	bool truncated;
} backend_ctx;

struct ram_hdr_t {
	/* Magic number for validation */
	uint32_t	magic;

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

#define COREDUMP_FLAG_TRUNCATED	0x0001

/* Forward declarations */
static bool backend_has_stored_dump(void);

/**
 * @brief Initialize the RAM backend.
 */
static int backend_init(void)
{
	memset(&backend_ctx, 0, sizeof(backend_ctx));
	
	backend_ctx.memory_area = (uint8_t *)COREDUMP_MEMORY_ADDR;
	backend_ctx.memory_size = COREDUMP_MEMORY_SIZE;
	backend_ctx.write_pos = sizeof(struct ram_hdr_t);

	return 0;
}

/**
 * @brief Clear the RAM coredump area.
 */
static void backend_clear(void)
{
	if (backend_ctx.memory_area) {
		memset(backend_ctx.memory_area, 0, backend_ctx.memory_size);
	}
	backend_ctx.write_pos = sizeof(struct ram_hdr_t);
	backend_ctx.checksum = 0;
	backend_ctx.error = 0;
	backend_ctx.truncated = false;
}

/**
 * @brief Check if there's a valid coredump stored in RAM.
 */
static bool backend_has_stored_dump(void)
{
	/* Ensure backend is initialized for queries */
	if (!backend_ctx.memory_area) {
		backend_ctx.memory_area = (uint8_t *)COREDUMP_MEMORY_ADDR;
		backend_ctx.memory_size = COREDUMP_MEMORY_SIZE;
	}
	
	struct ram_hdr_t *hdr = (struct ram_hdr_t *)backend_ctx.memory_area;
	
	bool magic_ok = (hdr->magic == COREDUMP_RAM_MAGIC);
	bool id_ok = (hdr->id[0] == 'C' && hdr->id[1] == 'D');
	bool version_ok = (hdr->hdr_version == HDR_VER);
	bool size_ok = (hdr->size > 0 && hdr->size <= (backend_ctx.memory_size - sizeof(struct ram_hdr_t)));
	
	return (magic_ok && id_ok && version_ok && size_ok);
}

/**
 * @brief Verify stored coredump integrity.
 */
static bool backend_verify_stored_dump(void)
{
	if (!backend_has_stored_dump()) {
		return false;
	}
	
	struct ram_hdr_t *hdr = (struct ram_hdr_t *)backend_ctx.memory_area;
	uint8_t *data_start = backend_ctx.memory_area + sizeof(struct ram_hdr_t);
	uint16_t calculated_checksum = 0;
	
	/* Calculate checksum of stored data */
	for (size_t i = 0; i < hdr->size; i++) {
		calculated_checksum += data_start[i];
	}
	
	return (calculated_checksum == hdr->checksum);
}

/**
 * @brief Get size of stored coredump.
 */
static size_t backend_get_stored_dump_size(void)
{
	if (!backend_has_stored_dump()) {
		return 0;
	}
	
	struct ram_hdr_t *hdr = (struct ram_hdr_t *)backend_ctx.memory_area;
	return sizeof(struct ram_hdr_t) + hdr->size;
}

/**
 * @brief Copy data from stored coredump.
 */
static int backend_copy_stored_dump(off_t offset, uint8_t *buffer, size_t length)
{
	if (!backend_has_stored_dump()) {
		return -ENOENT;
	}
	
	struct ram_hdr_t *hdr = (struct ram_hdr_t *)backend_ctx.memory_area;
	size_t total_size = sizeof(struct ram_hdr_t) + hdr->size;
	
	if (offset >= total_size) {
		return 0; /* End of data */
	}
	
	if (offset + length > total_size) {
		length = total_size - offset;
	}
	
	memcpy(buffer, backend_ctx.memory_area + offset, length);
	return length;
}

/**
 * @brief Start coredump capture.
 */
static void backend_start(void)
{
	backend_init();
	
	/* Clear any existing coredump */
	backend_clear();
}

/**
 * @brief Write coredump data to RAM.
 */
static void backend_buffer_output(uint8_t *buf, size_t buflen)
{
	if (backend_ctx.error != 0) {
		return;
	}
	
	if (!backend_ctx.memory_area) {
		backend_ctx.error = -ENODEV;
		return;
	}
	
	/* Check available space and truncate if necessary */
	size_t available_space = backend_ctx.memory_size - backend_ctx.write_pos;
	if (buflen > available_space) {
		if (available_space == 0) {
			/* No space left, silently ignore */
			backend_ctx.truncated = true;
			return;
		}
		/* Truncate to available space */
		buflen = available_space;
		backend_ctx.truncated = true;
	}
	
	/* Copy data to RAM */
	memcpy(backend_ctx.memory_area + backend_ctx.write_pos, buf, buflen);
	backend_ctx.write_pos += buflen;
	
	/* Update checksum */
	for (size_t i = 0; i < buflen; i++) {
		backend_ctx.checksum += buf[i];
	}
}

/**
 * @brief Finalize coredump and write header.
 */
static void backend_end(void)
{
	if (backend_ctx.error != 0) {
		return;
	}
	
	if (!backend_ctx.memory_area) {
		backend_ctx.error = -ENODEV;
		return;
	}
	
	/* Calculate actual data size (excluding header) */
	size_t data_size = backend_ctx.write_pos - sizeof(struct ram_hdr_t);
	
	/* Write header */
	struct ram_hdr_t *hdr = (struct ram_hdr_t *)backend_ctx.memory_area;
	hdr->magic = COREDUMP_RAM_MAGIC;
	hdr->id[0] = 'C';
	hdr->id[1] = 'D';
	hdr->hdr_version = HDR_VER;
	hdr->size = data_size;
	hdr->flags = backend_ctx.truncated ? COREDUMP_FLAG_TRUNCATED : 0;
	hdr->checksum = backend_ctx.checksum;
	hdr->error = backend_ctx.error;
}

/**
 * @brief Query coredump backend.
 */
static int backend_query(enum coredump_query_id query_id, void *arg)
{
	int ret = 0;

	switch (query_id) {
	case COREDUMP_QUERY_GET_ERROR:
		ret = backend_ctx.error;
		break;

	case COREDUMP_QUERY_HAS_STORED_DUMP:
		ret = backend_has_stored_dump() ? 1 : 0;
		break;

	case COREDUMP_QUERY_GET_STORED_DUMP_SIZE:
		ret = backend_get_stored_dump_size();
		break;

	default:
		ret = -ENOTSUP;
		break;
	}

	return ret;
}

/**
 * @brief Execute coredump backend command.
 */
static int backend_cmd(enum coredump_cmd_id cmd_id, void *arg)
{
	int ret = 0;

	switch (cmd_id) {
	case COREDUMP_CMD_CLEAR_ERROR:
		backend_ctx.error = 0;
		break;

	case COREDUMP_CMD_VERIFY_STORED_DUMP:
		ret = backend_verify_stored_dump() ? 1 : 0;
		break;

	case COREDUMP_CMD_ERASE_STORED_DUMP:
		backend_clear();
		break;

	case COREDUMP_CMD_COPY_STORED_DUMP:
		if (arg != NULL) {
			struct coredump_cmd_copy_arg *copy_arg = 
				(struct coredump_cmd_copy_arg *)arg;
			ret = backend_copy_stored_dump(copy_arg->offset,
			                               copy_arg->buffer,
			                               copy_arg->length);
		} else {
			ret = -EINVAL;
		}
		break;

	default:
		ret = -ENOTSUP;
		break;
	}

	return ret;
}

/* Coredump backend interface */
struct coredump_backend_api coredump_backend_ram = {
	.start = backend_start,
	.end = backend_end,
	.buffer_output = backend_buffer_output,
	.query = backend_query,
	.cmd = backend_cmd,
};