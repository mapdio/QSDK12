/*
 * Copyright (c) 2023 Qualcomm Innovation Center, Inc. All rights reserved.
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
 * @file cfgmgr_wlan.h
 *	Config Manager wlan driver interface.
 */

#ifndef _CFGMGR_WLAN_H_
#define _CFGMGR_WLAN_H_

/*
 * sending a wifi msg to the userspace
 * We will control everything inside here.
 */
extern cfgmgr_status_t cfgmgr_wlan_send_msg(struct cfgmgr_cmn_msg *cmn,
					    uint32_t msg_len, uint32_t msg_type);

/*
 * wifi driver callback registration
 */
extern cfgmgr_status_t cfgmgr_wlan_unregister_msg_handler(void);
extern cfgmgr_status_t cfgmgr_wlan_register_msg_handler(cfgmgr_msg_cb_type_t cb,
							void *cb_data);

#endif /* _CFGMGR_WLAN_H_ */
