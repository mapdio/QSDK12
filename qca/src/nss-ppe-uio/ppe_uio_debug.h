/*
 * Copyright (c) 2023, Qualcomm Innovation Center, Inc. All rights reserved.
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

#ifndef __PPE_UIO_DEBUG_H__
#define __PPE_UIO_DEBUG_H__

#if (PPE_UIO_DEBUG_LEVEL < 1)
#define ppe_uio_err(s, ...)
#else
#define ppe_uio_err(s, ...) pr_err("%s[%d]:" s, __func__, __LINE__, ##__VA_ARGS__)
#endif

#if (PPE_UIO_DEBUG_LEVEL < 2)
#define ppe_uio_warn(s, ...)
#else
#define ppe_uio_warn(s, ...) pr_warn("%s[%d]:" s, __func__, __LINE__, ##__VA_ARGS__)
#endif

#if (PPE_UIO_DEBUG_LEVEL < 3)
#define ppe_uio_info(s, ...)
#else
#define ppe_uio_info(s, ...) pr_info("%s[%d]:" s, __func__, __LINE__, ##__VA_ARGS__)
#endif

#if (PPE_UIO_DEBUG_LEVEL < 4)
#define ppe_uio_debug(s, ...)
#else
#if defined(CONFIG_DYNAMIC_DEBUG)
#define ppe_uio_debug(s, ...) pr_debug("%s[%d]:" s, __func__, __LINE__, ##__VA_ARGS__)
#else
#define ppe_uio_debug(s, ...) printk(KERN_DEBUG"%s[%d]:" s, __func__, __LINE__, ##__VA_ARGS__)
#endif
#endif

#endif	/*__PPE_UIO_DEBUG_H__ */
