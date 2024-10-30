/*
 * Copyright (c) 2023-2024 Qualcomm Innovation Center, Inc. All rights reserved.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/**
 * @file cfgmgr_public.h
 *	Config Manager definitions.
 */

#ifndef _CFGMGR_DEF_H_
#define _CFGMGR_DEF_H_

struct cfgmgr_ctx;
#define MAC_ADDR_SIZE 6

/**
 * Real pointer size of the system.
 */
#ifdef __LP64__
typedef uint64_t dpdk_ptr_t;
#else
typedef uint32_t dpdk_ptr_t;
#endif

/*
 * enum cfgmgr_status
 *	Config Manager return status
 */
typedef enum cfgmgr_status {
	CFGMGR_STATUS_SUCCESS = 0,		/* Return success */
	CFGMGR_STATUS_ERROR,			/* Return success */
} cfgmgr_status_t;

/*
 * cfgmgr_cmn_msg
 *	Common message control header for each message.
 *
 * Deprecated fields (May use later)
 * 	uint8_t resv;		unused
 *	uint32_t sk_fd;		socket fd, used by kernel; or *

 * #ifdef ALIGN2_16B
 * 	void *dummy;		make 32B size hdr *
 * #endif
 */
struct cfgmgr_cmn_msg {
	dpdk_ptr_t sock_data;	/* Socket specific info, used by kernel */
	uint32_t pid;		/* PID of the sender process (Kernel is 0) */
	uint16_t version;	/* Message version */
	uint16_t msg_len;	/* Next Data message length */
	uint32_t msg_type;	/* Next header message type */
	uint32_t reserved;

	void *cb;		/* Disabled for now */
	void *cb_data;		/* Disabled for now */
} __attribute__((packed));

/*
 * cfgmgr_msg_cb_type_t
 *	Config manager rx handler callback type.
 */
typedef int (*cfgmgr_msg_cb_type_t)(struct cfgmgr_cmn_msg *cm, void *cb_data);
extern void cfgmgr_cmn_msg_init(struct cfgmgr_cmn_msg *ccm, uint16_t msg_len, uint32_t msg_type, void *cb, void *cb_data);

#endif /* _CFGMGR_DEF_H_ */
