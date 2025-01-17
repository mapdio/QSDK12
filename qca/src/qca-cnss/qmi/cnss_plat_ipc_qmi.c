// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2021, The Linux Foundation. All rights reserved. */

/* Copyright (c) 2022-2023, Qualcomm Innovation Center, Inc. All rights reserved. */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/qrtr.h>
#include <linux/soc/qcom/qmi.h>
#if IS_ENABLED(CONFIG_IPC_LOGGING)
#include <linux/ipc_logging.h>
#endif
#include <linux/limits.h>
#include <linux/slab.h>
#include "qmi/cnss_plat_ipc_qmi.h"
#include "cnss_plat_ipc_service_v01.h"
#include "../main.h"
#include "cnss_common/cnss_common.h"
#ifdef CNSS_DEBUG_SUPPORT
#include "debug/debug.h"
#endif

#define CNSS_MAX_FILE_SIZE (32 * 1024 * 1024)
#define CNSS_PLAT_IPC_MAX_USER 1
#define CNSS_PLAT_IPC_QMI_FILE_TXN_TIMEOUT 60000

/**
 * struct cnss_plat_ipc_file_data: File transfer context data
 * @name: File name
 * @buf: Buffer provided for TX/RX file contents
 * @id: File ID corresponding to file name
 * @buf_size: Buffer size
 * @file_fize: File Size
 * @seg_index: Running index for buffer segments
 * @seg_len: Total number of segments
 * @end: End of transaction
 * @complete: Completion variable for file transfer
 */
struct cnss_plat_ipc_file_data {
	char *name;
	char *buf;
	u32 id;
	u32 buf_size;
	u32 file_size;
	u32 seg_index;
	u32 seg_len;
	u32 end;
	struct completion complete;
};

/**
 * struct cnss_plat_ipc_qmi_client_ctx: Context for QMI IPC client
 * @client_sq: QMI IPC client QRTR socket
 * @client_connected: QMI IPC client connection status
 * @ipc_qmi_callbacks: Registered user callback functions for QMI req
 * @cb_ctx: Context for registered user
 * @num_user: Number of registered users
 */
struct cnss_plat_ipc_qmi_client_ctx {
	struct sockaddr_qrtr client_sq;
	bool client_connected;

	struct cnss_plat_ipc_qmi_cb ipc_qmi_callbacks[CNSS_PLAT_IPC_MAX_USER];
	void *cb_ctx[CNSS_PLAT_IPC_MAX_USER];
	u32 num_user;
};

/**
 * struct cnss_plat_ipc_qmi_svc_ctx: Platform context for QMI IPC service
 * @svc_hdl: QMI server handle
 * @file_idr: File ID generator
 * @flle_idr_lock: File ID generator usage lock
 * @qmi_client_ctx: ontext for QMI IPC client
 */
struct cnss_plat_ipc_qmi_svc_ctx {
	struct qmi_handle *svc_hdl;
	struct idr file_idr;
	struct mutex file_idr_lock; /* File ID generator usage lock */
	struct cnss_plat_ipc_qmi_client_ctx
		qmi_client_ctx[CNSS_PLAT_IPC_MAX_QMI_CLIENTS + 1];
	struct completion daemon_connected;
};

static struct cnss_plat_ipc_qmi_svc_ctx plat_ipc_qmi_svc;
static struct cnss_plat_ipc_daemon_config daemon_cfg;

/**
 * cnss_plat_ipc_init_file_data() - Initialize file transfer context data
 * @name: File name
 * @buf: Buffer pointer for file contents
 * @buf_size: Buffer size for download / upload
 * @file_size: File size for upload
 *
 * Return: File data pointer
 */
static
struct cnss_plat_ipc_file_data *cnss_plat_ipc_init_file_data(char *name,
							     char *buf,
							     u32 buf_size,
							     u32 file_size)
{
	struct cnss_plat_ipc_qmi_svc_ctx *svc = &plat_ipc_qmi_svc;
	struct cnss_plat_ipc_file_data *fd;

	fd = kmalloc(sizeof(*fd), GFP_KERNEL);
	if (!fd)
		goto end;
	fd->name = name;
	fd->buf = buf;
	fd->buf_size = buf_size;
	fd->file_size = file_size;
	fd->seg_index = 0;
	fd->end = 0;
	if (file_size)
		fd->seg_len =
			(file_size / CNSS_PLAT_IPC_QMI_MAX_DATA_SIZE_V01) +
			!!(file_size % CNSS_PLAT_IPC_QMI_MAX_DATA_SIZE_V01);
	else
		fd->seg_len = 0;
	init_completion(&fd->complete);
	mutex_lock(&svc->file_idr_lock);
	fd->id = idr_alloc_cyclic(&svc->file_idr, fd, 0, U32_MAX, GFP_KERNEL);
	if (fd->id < 0) {
		kfree(fd);
		fd = NULL;
	}
	mutex_unlock(&svc->file_idr_lock);
end:
	return fd;
}

/**
 * cnss_plat_ipc_deinit_file_data() - Release file transfer context data
 * @fd: File data pointer
 *
 * Return: 0 on success, negative error values otherwise
 */
static int cnss_plat_ipc_deinit_file_data(struct cnss_plat_ipc_file_data *fd)
{
	struct cnss_plat_ipc_qmi_svc_ctx *svc = &plat_ipc_qmi_svc;
	int ret = 0;

	if (unlikely(!fd))
		return -EINVAL;

	mutex_lock(&svc->file_idr_lock);
	idr_remove(&svc->file_idr, fd->id);
	mutex_unlock(&svc->file_idr_lock);

	if (!fd->end)
		ret = -EINVAL;
	kfree(fd);
	return ret;
}

/**
 * cnss_plat_ipc_qmi_update_user() - Inform registered users about QMI
 *                                      update
 *
 * Return: None
 */
static void
cnss_plat_ipc_qmi_update_user(enum cnss_plat_ipc_qmi_client_id_v01 client_id)
{
	struct cnss_plat_ipc_qmi_svc_ctx *svc = &plat_ipc_qmi_svc;
	struct cnss_plat_ipc_qmi_client_ctx *qmi_client =
			&svc->qmi_client_ctx[client_id];
	struct cnss_plat_data *plat_priv = NULL;
	int i;

	for (i = 0; i < qmi_client->num_user; i++) {
		if (qmi_client->ipc_qmi_callbacks[i].connection_update_cb)
			qmi_client->ipc_qmi_callbacks[i].connection_update_cb
						(qmi_client->cb_ctx[i],
						 qmi_client->client_connected);
	}

	switch (client_id) {
	case CNSS_PLAT_IPC_DAEMON_QMI_CLIENT_V01:
		if (qmi_client->client_connected) {
			cnss_pr_info("CNSS Daemon connected\n");
			complete(&svc->daemon_connected);
		} else {
			cnss_pr_info("CNSS Daemon disconnected\n");
			reinit_completion(&svc->daemon_connected);
		}
		break;
	default:
		break;
	}
}

/**
 * cnss_plat_ipc_qmi_file_upload() - Upload data as platform accessible file
 * @client_id: User space QMI IPC client ID. Also works as
 *		array index for QMI client context
 * @file_mame: File name to store in platform data location
 * @file_buf: Pointer to buffer with file contents
 * @file_size: Provides the size of buffer / file size
 *
 * Return: 0 on success, negative error values otherwise
 */
int cnss_plat_ipc_qmi_file_upload(enum cnss_plat_ipc_qmi_client_id_v01
				  client_id, char *file_name, u8 *file_buf,
				  u32 file_size)
{
	struct cnss_plat_ipc_qmi_file_upload_ind_msg_v01 ind;
	struct cnss_plat_ipc_qmi_svc_ctx *svc = &plat_ipc_qmi_svc;
	struct cnss_plat_ipc_qmi_client_ctx *qmi_client;
	int ret;
	struct cnss_plat_ipc_file_data *fd;
	struct cnss_plat_data *plat_priv = NULL;

	if (client_id > CNSS_PLAT_IPC_MAX_QMI_CLIENTS) {
		cnss_pr_err("Invalid Client ID: %d\n", client_id);
		return -EINVAL;
	}

	qmi_client = &svc->qmi_client_ctx[client_id];

	if (!qmi_client->client_connected || !file_name || !file_buf)
		return -EINVAL;

	cnss_pr_info("%s: File name: %s Size: %d\n", __func__, file_name, file_size);

	if (file_size == 0 || file_size > CNSS_MAX_FILE_SIZE)
		return -EINVAL;

	fd = cnss_plat_ipc_init_file_data(file_name, file_buf, file_size,
					  file_size);
	if (!fd) {
		cnss_pr_err("%s: Unable to initialize file transfer data\n",
		       __func__);
		return -EINVAL;
	}
	scnprintf(ind.file_name, CNSS_PLAT_IPC_QMI_MAX_FILE_NAME_LEN_V01, "%s",
		  fd->name);
	ind.file_size = fd->file_size;
	ind.file_id = fd->id;

	ret = qmi_send_indication
			(svc->svc_hdl, &qmi_client->client_sq,
			 CNSS_PLAT_IPC_QMI_FILE_UPLOAD_IND_V01,
			 CNSS_PLAT_IPC_QMI_FILE_UPLOAD_IND_MSG_V01_MAX_MSG_LEN,
			 cnss_plat_ipc_qmi_file_upload_ind_msg_v01_ei, &ind);

	if (ret < 0) {
		cnss_pr_err("%s: QMI failed: %d\n", __func__, ret);
		goto end;
	}
	ret = wait_for_completion_timeout(&fd->complete,
					  msecs_to_jiffies
					  (CNSS_PLAT_IPC_QMI_FILE_TXN_TIMEOUT));
	if (!ret)
		cnss_pr_err("%s: Timeout Uploading file: %s\n", __func__, fd->name);

end:
	ret = cnss_plat_ipc_deinit_file_data(fd);
	cnss_pr_dbg("%s: Status: %d\n", __func__, ret);

	return ret;
}

/**
 * cnss_plat_ipc_qmi_file_upload_req_handler() - QMI Upload data request handler
 * @handle: Pointer to QMI handle
 * @sq: QMI socket
 * @txn: QMI transaction pointer
 * @decoded_msg: Pointer to decoded QMI message
 *
 * Handles the QMI upload sequence from userspace. It uses the file descriptor
 * ID to upload buffer contents to QMI messages as segments.
 *
 * Return: None
 */
static void
cnss_plat_ipc_qmi_file_upload_req_handler(struct qmi_handle *handle,
					  struct sockaddr_qrtr *sq,
					  struct qmi_txn *txn,
					  const void *decoded_msg)
{
	struct cnss_plat_ipc_qmi_file_upload_req_msg_v01 *req_msg;
	struct cnss_plat_ipc_qmi_file_upload_resp_msg_v01 *resp;
	struct cnss_plat_ipc_qmi_svc_ctx *svc = &plat_ipc_qmi_svc;
	int ret = 0;
	struct cnss_plat_ipc_file_data *fd;
	struct cnss_plat_data *plat_priv = NULL;

	req_msg = (struct cnss_plat_ipc_qmi_file_upload_req_msg_v01 *)
		   decoded_msg;
	if (!req_msg)
		return;

	mutex_lock(&svc->file_idr_lock);
	fd = idr_find(&svc->file_idr, req_msg->file_id);
	mutex_unlock(&svc->file_idr_lock);
	if (!fd) {
		cnss_pr_err("%s: Invalid File ID %d\n", __func__,
			    req_msg->file_id);
		return;
	}

	if (req_msg->seg_index != fd->seg_index) {
		cnss_pr_err("%s: File %s transfer segment failure\n", __func__,
		       fd->name);
		complete(&fd->complete);
	}

	resp = kzalloc(sizeof(*resp), GFP_KERNEL);
	if (!resp)
		return;

	resp->file_id = fd->id;
	resp->seg_index = fd->seg_index++;
	resp->seg_buf_len =
		(fd->buf_size > CNSS_PLAT_IPC_QMI_MAX_DATA_SIZE_V01 ?
		 CNSS_PLAT_IPC_QMI_MAX_DATA_SIZE_V01 : fd->buf_size);
	resp->end = (fd->seg_index == fd->seg_len);
	memcpy(resp->seg_buf, fd->buf, resp->seg_buf_len);

	ret = qmi_send_response
		(svc->svc_hdl, sq, txn,
		CNSS_PLAT_IPC_QMI_FILE_UPLOAD_RESP_V01,
		CNSS_PLAT_IPC_QMI_FILE_UPLOAD_RESP_MSG_V01_MAX_MSG_LEN,
		cnss_plat_ipc_qmi_file_upload_resp_msg_v01_ei,
		resp);

	if (ret < 0) {
		cnss_pr_err("%s: QMI failed: %d\n", __func__, ret);
		goto end;
	}

	fd->buf_size -= resp->seg_buf_len;
	fd->buf += resp->seg_buf_len;
	if (resp->end) {
		fd->end = true;
		complete(&fd->complete);
	}
end:
	kfree(resp);
}

/**
 * cnss_plat_ipc_qmi_file_download() - Download platform accessible file
 * @client_id: User space QMI IPC client ID. Also works as
 *		array index for QMI client context
 * @file_mame: File name to get from platform data location
 * @buf: Pointer of the buffer to store file contents
 * @size: Provides the size of buffer. It is updated to reflect the file size
 *        at the end of file download.
 */
int cnss_plat_ipc_qmi_file_download(enum cnss_plat_ipc_qmi_client_id_v01
				    client_id, char *file_name, char *buf,
				    u32 *size)
{
	struct cnss_plat_ipc_qmi_file_download_ind_msg_v01 ind;
	struct cnss_plat_ipc_qmi_svc_ctx *svc = &plat_ipc_qmi_svc;
	struct cnss_plat_ipc_qmi_client_ctx *qmi_client;
	int ret;
	struct cnss_plat_ipc_file_data *fd;
	struct cnss_plat_data *plat_priv = NULL;
	if (client_id > CNSS_PLAT_IPC_MAX_QMI_CLIENTS) {
		cnss_pr_err("Invalid Client ID: %d\n", client_id);
		return -EINVAL;
	}
	cnss_pr_dbg("%s: File name %s size %u\n", __func__, file_name, *size);
	qmi_client = &svc->qmi_client_ctx[client_id];

	if (!qmi_client->client_connected || !file_name || !buf)
		return -EINVAL;

	fd = cnss_plat_ipc_init_file_data(file_name, buf, *size, 0);
	if (!fd) {
		cnss_pr_err("%s: Unable to initialize file transfer data\n",
		       __func__);
		return -EINVAL;
	}

	scnprintf(ind.file_name, CNSS_PLAT_IPC_QMI_MAX_FILE_NAME_LEN_V01, "%s",
		  file_name);
	ind.file_id = fd->id;

	ret = qmi_send_indication
		(svc->svc_hdl, &qmi_client->client_sq,
		 CNSS_PLAT_IPC_QMI_FILE_DOWNLOAD_IND_V01,
		 CNSS_PLAT_IPC_QMI_FILE_DOWNLOAD_IND_MSG_V01_MAX_MSG_LEN,
		 cnss_plat_ipc_qmi_file_download_ind_msg_v01_ei, &ind);

	if (ret < 0) {
		cnss_pr_err("%s: QMI failed: %d\n", __func__, ret);
		goto end;
	}
	ret = wait_for_completion_timeout(&fd->complete,
					  msecs_to_jiffies
					  (CNSS_PLAT_IPC_QMI_FILE_TXN_TIMEOUT));
	if (!ret)
		cnss_pr_err("%s: Timeout downloading file:%s\n", __func__, fd->name);

end:
	*size = fd->file_size;
	ret = cnss_plat_ipc_deinit_file_data(fd);
	cnss_pr_dbg("%s: Status: %d Size: %d\n", __func__, ret, *size);

	return ret;
}

/**
 * cnss_plat_ipc_qmi_file_download_req_handler() - QMI download request handler
 * @handle: Pointer to QMI handle
 * @sq: QMI socket
 * @txn: QMI transaction pointer
 * @decoded_msg: Pointer to decoded QMI message
 *
 * Handles the QMI download request sequence to userspace. It uses the file
 * descriptor ID to download QMI message buffer segment to file descriptor
 * buffer.
 *
 * Return: None
 */
static void
cnss_plat_ipc_qmi_file_download_req_handler(struct qmi_handle *handle,
					    struct sockaddr_qrtr *sq,
					    struct qmi_txn *txn,
					    const void *decoded_msg)
{
	struct cnss_plat_ipc_qmi_file_download_req_msg_v01 *req_msg;
	struct cnss_plat_ipc_qmi_file_download_resp_msg_v01 resp = {0};
	struct cnss_plat_ipc_qmi_svc_ctx *svc = &plat_ipc_qmi_svc;
	int ret = 0;
	struct cnss_plat_ipc_file_data *fd;
	struct cnss_plat_data *plat_priv = NULL;

	req_msg = (struct cnss_plat_ipc_qmi_file_download_req_msg_v01 *)
		   decoded_msg;
	if (!req_msg)
		return;

	mutex_lock(&svc->file_idr_lock);
	fd = idr_find(&svc->file_idr, req_msg->file_id);
	mutex_unlock(&svc->file_idr_lock);
	if (!fd) {
		cnss_pr_err("%s: Invalid File ID: %d\n", __func__, req_msg->file_id);
		return;
	}

	if (req_msg->file_size > fd->buf_size) {
		cnss_pr_err("%s: File %s size %d larger than buffer size %d\n",
		       __func__, fd->name, req_msg->file_size, fd->buf_size);
		goto file_error;
	}
	if (req_msg->seg_buf_len > CNSS_PLAT_IPC_QMI_MAX_DATA_SIZE_V01 ||
	    ((req_msg->seg_buf_len + fd->file_size) > fd->buf_size)) {
		cnss_pr_err("%s: Segment buf ID: %d buffer size %d not allowed\n",
		       __func__, req_msg->seg_index, req_msg->seg_buf_len);
		goto file_error;
	}
	if (req_msg->seg_index != fd->seg_index) {
		cnss_pr_err("%s: File %s transfer segment failure\n", __func__,
		       fd->name);
		goto file_error;
	}

	memcpy_toio(fd->buf, req_msg->seg_buf, req_msg->seg_buf_len);

	fd->seg_index++;
	fd->buf += req_msg->seg_buf_len;
	fd->file_size += req_msg->seg_buf_len;

	resp.file_id = fd->id;
	resp.seg_index = fd->seg_index;
	ret = qmi_send_response
		(svc->svc_hdl, sq, txn,
		CNSS_PLAT_IPC_QMI_FILE_DOWNLOAD_RESP_V01,
		CNSS_PLAT_IPC_QMI_FILE_DOWNLOAD_RESP_MSG_V01_MAX_MSG_LEN,
		cnss_plat_ipc_qmi_file_download_resp_msg_v01_ei,
		&resp);

	if (ret < 0)
		cnss_pr_err("%s: ERR! QMI failed: %d\n", __func__, ret);

	if (req_msg->end) {
		fd->end = true;
		complete(&fd->complete);
	}

	return;
file_error:
	complete(&fd->complete);
}



/**
 * cnss_plat_ipc_qmi_send_config_param_req_handler() - Config param QMI message
 * handler
 * @handle: Pointer to QMI handle
 * @sq: QMI socket
 * @txn: QMI transaction pointer
 * @decoded_msg: Pointer to decoded QMI message
 *
 * Handles the config parameters and their values from userspace.
 *
 * Return: None
 */
void
cnss_plat_ipc_qmi_send_config_param_req_handler(struct qmi_handle *handle,
						struct sockaddr_qrtr *sq,
						struct qmi_txn *txn,
						const void *decoded_msg)
{
	struct cnss_plat_ipc_qmi_send_config_param_req_msg_v01 *req_msg;
	struct cnss_plat_ipc_qmi_send_config_param_resp_msg_v01 resp = {0};
	struct cnss_plat_ipc_qmi_svc_ctx *svc = &plat_ipc_qmi_svc;
	struct cnss_plat_ipc_qmi_client_ctx *qmi_client;
	enum cnss_plat_ipc_qmi_client_id_v01 client_id;
	int ret = 0, i = 0;
	struct cnss_plat_data *plat_priv = NULL;

	req_msg =
	(struct cnss_plat_ipc_qmi_send_config_param_req_msg_v01 *)decoded_msg;

	cnss_pr_info("%s: Param: %d Instance ID: 0x%x Value: %llu\n", __func__,
		     req_msg->param, req_msg->instance_id, req_msg->value);

	client_id = req_msg->client_id;

	if (client_id <= CNSS_PLAT_IPC_MAX_QMI_CLIENTS) {
		qmi_client = &svc->qmi_client_ctx[client_id];
		for (i = 0; i < qmi_client->num_user; i++) {
			if (qmi_client->ipc_qmi_callbacks[i].config_param_cb)
				qmi_client->ipc_qmi_callbacks[i].config_param_cb(
							req_msg->instance_id,
							req_msg->param,
							req_msg->value);
		}
	} else {
		cnss_pr_err("%s: Invalid client ID %d\n", __func__,
			    req_msg->client_id);
	}

	ret = qmi_send_response
		(svc->svc_hdl, sq, txn,
		 CNSS_PLAT_IPC_QMI_SEND_CONFIG_PARAM_RESP_V01,
		 CNSS_PLAT_IPC_QMI_SEND_CONFIG_PARAM_RESP_MSG_V01_MAX_MSG_LEN,
		 cnss_plat_ipc_qmi_send_config_param_resp_msg_v01_ei, &resp);
	if (ret < 0)
		cnss_pr_err("%s: QMI failed: %d\n", __func__, ret);
}

/**
 * cnss_plat_ipc_qmi_init_setup_req_handler() - Init_Setup QMI message handler
 * @handle: Pointer to QMI handle
 * @sq: QMI socket
 * @txn: QMI transaction pointer
 * @decoded_msg: Pointer to decoded QMI message
 *
 * Handles the QMI Init setup handshake message from userspace.
 * buffer.
 *
 * Return: None
 */
static void
cnss_plat_ipc_qmi_init_setup_req_handler(struct qmi_handle *handle,
					 struct sockaddr_qrtr *sq,
					 struct qmi_txn *txn,
					 const void *decoded_msg)
{
	struct cnss_plat_ipc_qmi_init_setup_req_msg_v01 *req_msg;
	struct cnss_plat_ipc_qmi_init_setup_resp_msg_v01 resp = {0};
	struct cnss_plat_ipc_qmi_svc_ctx *svc = &plat_ipc_qmi_svc;
	int ret = 0;
	struct cnss_plat_data *plat_priv = NULL;
	struct cnss_plat_ipc_daemon_config *cfg = &daemon_cfg;

	req_msg =
		(struct cnss_plat_ipc_qmi_init_setup_req_msg_v01 *)decoded_msg;
	cnss_pr_info("%s: MAC: %d HW_TRC: %d CAL: %d\n", __func__,
		 req_msg->dms_mac_addr_supported,
		 req_msg->qdss_hw_trace_override,
		 req_msg->cal_file_available_bitmask);

	cfg->dms_mac_addr_supported = req_msg->dms_mac_addr_supported;
	cfg->qdss_hw_trace_override = req_msg->qdss_hw_trace_override;
	cfg->cal_file_available_bitmask = req_msg->cal_file_available_bitmask;

	ret = qmi_send_response
			(svc->svc_hdl, sq, txn,
			CNSS_PLAT_IPC_QMI_INIT_SETUP_RESP_V01,
			CNSS_PLAT_IPC_QMI_INIT_SETUP_RESP_MSG_V01_MAX_MSG_LEN,
			cnss_plat_ipc_qmi_init_setup_resp_msg_v01_ei, &resp);
	if (ret < 0)
		cnss_pr_err("%s: QMI failed: %d\n", __func__, ret);
}

/**
* cnss_plat_ipc_qmi_reg_client_req_handler() - Register QMI client
* @handle: Pointer to QMI handle
* @sq: QMI socket
* @txn: QMI transaction pointer
* @decoded_msg: Pointer to decoded QMI message
*
* Handles the userspace QMI client registration.
*
* Return: None
*/

static void
cnss_plat_ipc_qmi_reg_client_req_handler(struct qmi_handle *handle,
					 struct sockaddr_qrtr *sq,
					 struct qmi_txn *txn,
					 const void *decoded_msg)
{
	struct cnss_plat_ipc_qmi_reg_client_req_msg_v01 *req_msg;
	struct cnss_plat_ipc_qmi_reg_client_resp_msg_v01 resp = {0};
	struct cnss_plat_ipc_qmi_svc_ctx *svc = &plat_ipc_qmi_svc;
	struct cnss_plat_ipc_qmi_client_ctx *qmi_client = svc->qmi_client_ctx;
	struct cnss_plat_data *plat_priv = NULL;
	int ret = 0;

	req_msg =
		(struct cnss_plat_ipc_qmi_reg_client_req_msg_v01 *)decoded_msg;

	if (req_msg->client_id_valid) {
		if (req_msg->client_id <= CNSS_PLAT_IPC_MAX_QMI_CLIENTS &&
		    !qmi_client[req_msg->client_id].client_connected) {
			cnss_pr_info("%s: QMI Client Connected. QMI Socket Node: %d Port: %d ID: %d\n",
				      __func__, sq->sq_node, sq->sq_port,
				      req_msg->client_id);
			qmi_client[req_msg->client_id].client_sq = *sq;
			qmi_client[req_msg->client_id].client_connected = true;
			cnss_plat_ipc_qmi_update_user
					((enum cnss_plat_ipc_qmi_client_id_v01)
					req_msg->client_id);
		} else {
			cnss_pr_err("%s: QMI client already connected, connection status %u or Invalid client id %u\n",
				__func__,
				qmi_client[req_msg->client_id].client_connected,
				req_msg->client_id);
			return;
		}
	}

	ret = qmi_send_response
	      (svc->svc_hdl, sq, txn,
	       CNSS_PLAT_IPC_QMI_REG_CLIENT_RESP_V01,
	       CNSS_PLAT_IPC_QMI_REG_CLIENT_RESP_MSG_V01_MAX_MSG_LEN,
	       cnss_plat_ipc_qmi_reg_client_resp_msg_v01_ei, &resp);

	if (ret < 0)
		cnss_pr_err("QMI Response failed: %d\n", ret);
}

/**
 * cnss_plat_ipc_qmi_disconnect_cb() - Handler for QMI node disconnect specific
 *                                     to node and port
 * @handle: Pointer to QMI handle
 * @node: QMI node that is disconnected
 * @port: QMI port that is disconnected
 *
 * Return: None
 */
static void cnss_plat_ipc_qmi_disconnect_cb(struct qmi_handle *handle,
					    unsigned int node,
					    unsigned int port)
{
	struct cnss_plat_ipc_qmi_svc_ctx *svc = &plat_ipc_qmi_svc;
	struct cnss_plat_ipc_qmi_client_ctx *qmi_client =
					svc->qmi_client_ctx;
	struct cnss_plat_ipc_file_data *fd;
	u32 file_id;
	int i;
	struct cnss_plat_data *plat_priv = NULL;

	if (svc->svc_hdl != handle) {
		cnss_pr_err("%s: Invalid QMI Handle\n", __func__);
		return;
	}

	for (i = 0; i <= CNSS_PLAT_IPC_MAX_QMI_CLIENTS; i++) {
		if (qmi_client[i].client_connected &&
		    qmi_client[i].client_sq.sq_node == node &&
		    qmi_client[i].client_sq.sq_port == port) {
			cnss_pr_dbg("%s: QMI client disconnect. QMI Socket Node:%d Port:%d ID: %d\n",
				    __func__, node, port, i);
			qmi_client[i].client_sq.sq_node = 0;
			qmi_client[i].client_sq.sq_port = 0;
			qmi_client[i].client_sq.sq_family = 0;
			qmi_client[i].client_connected = false;

			/* Daemon killed. Fail any download / upload in
			 * progress. This will also free stale fd
			 */
			mutex_lock(&svc->file_idr_lock);
			idr_for_each_entry(&svc->file_idr, fd, file_id)
				complete(&fd->complete);
			mutex_unlock(&svc->file_idr_lock);
			cnss_plat_ipc_qmi_update_user(i);
		}
	}
}

bool is_ipc_qmi_client_connected(enum cnss_plat_ipc_qmi_client_id_v01 client_id,
				 unsigned int timeout)
{
	struct cnss_plat_ipc_qmi_svc_ctx *svc = &plat_ipc_qmi_svc;
	struct cnss_plat_ipc_qmi_client_ctx *qmi_client;
	int ret = 0;
	struct cnss_plat_data *plat_priv = NULL;

	if (client_id > CNSS_PLAT_IPC_MAX_QMI_CLIENTS) {
		cnss_pr_err("Invalid Client ID: %d\n", client_id);
		return false;
	}

	qmi_client = &svc->qmi_client_ctx[client_id];

	if (!(qmi_client->client_connected)) {
		if (!timeout) {
			cnss_pr_dbg("IPC QMI Client not connected!\n");
			return false;
		}
		cnss_pr_info("Waiting for IPC QMI Client connection\n");
		ret = wait_for_completion_timeout(&svc->daemon_connected,
						  msecs_to_jiffies(timeout));
		if (!ret)
			return false;
	}
	return true;
}

/**
 * cnss_plat_ipc_qmi_bye_cb() - Handler for QMI node disconnect for all port of
 *                              the given node.
 * @handle: Pointer to QMI handle
 * @node: QMI node that is disconnected
 *
 * Return: None
 */
static void cnss_plat_ipc_qmi_bye_cb(struct qmi_handle *handle,
				     unsigned int node)
{
	struct cnss_plat_ipc_qmi_svc_ctx *svc = &plat_ipc_qmi_svc;
	struct cnss_plat_ipc_qmi_client_ctx *qmi_client =
					svc->qmi_client_ctx;
	int i;

	for (i = 0; i <= CNSS_PLAT_IPC_MAX_QMI_CLIENTS; i++) {
		cnss_plat_ipc_qmi_disconnect_cb(
					 handle, node,
					 qmi_client[i].client_sq.sq_port);
	}
}

static struct qmi_ops cnss_plat_ipc_qmi_ops = {
	/* inform a client that all clients from a node are gone */
	.bye = cnss_plat_ipc_qmi_bye_cb,
	.del_client = cnss_plat_ipc_qmi_disconnect_cb,
};

static struct qmi_msg_handler cnss_plat_ipc_qmi_req_handlers[] = {
	{
		.type = QMI_REQUEST,
		.msg_id = CNSS_PLAT_IPC_QMI_REG_CLIENT_REQ_V01,
		.ei = cnss_plat_ipc_qmi_reg_client_req_msg_v01_ei,
		.decoded_size =
			sizeof(struct cnss_plat_ipc_qmi_reg_client_req_msg_v01),
		.fn = cnss_plat_ipc_qmi_reg_client_req_handler,
	},
	{
		.type = QMI_REQUEST,
		.msg_id = CNSS_PLAT_IPC_QMI_INIT_SETUP_REQ_V01,
		.ei = cnss_plat_ipc_qmi_init_setup_req_msg_v01_ei,
		.decoded_size =
			sizeof(struct cnss_plat_ipc_qmi_init_setup_req_msg_v01),
		.fn = cnss_plat_ipc_qmi_init_setup_req_handler,
	},
	{
		.type = QMI_REQUEST,
		.msg_id = CNSS_PLAT_IPC_QMI_FILE_DOWNLOAD_REQ_V01,
		.ei = cnss_plat_ipc_qmi_file_download_req_msg_v01_ei,
		.decoded_size =
		     sizeof(struct cnss_plat_ipc_qmi_file_download_req_msg_v01),
		.fn = cnss_plat_ipc_qmi_file_download_req_handler,
	},
	{
		.type = QMI_REQUEST,
		.msg_id = CNSS_PLAT_IPC_QMI_FILE_UPLOAD_REQ_V01,
		.ei = cnss_plat_ipc_qmi_file_upload_req_msg_v01_ei,
		.decoded_size =
		       sizeof(struct cnss_plat_ipc_qmi_file_upload_req_msg_v01),
		.fn = cnss_plat_ipc_qmi_file_upload_req_handler,
	},
	{
		.type = QMI_REQUEST,
		.msg_id = CNSS_PLAT_IPC_QMI_SEND_CONFIG_PARAM_REQ_V01,
		.ei = cnss_plat_ipc_qmi_send_config_param_req_msg_v01_ei,
		.decoded_size =
		   CNSS_PLAT_IPC_QMI_SEND_CONFIG_PARAM_REQ_MSG_V01_MAX_MSG_LEN,
		.fn = cnss_plat_ipc_qmi_send_config_param_req_handler,
	},
	{}
};

/**
 * cnss_plat_ipc_qmi_daemon_config() - Get daemon config for CNSS platform
 *
 * Return: Pointer to user space client config
 */
struct cnss_plat_ipc_daemon_config *cnss_plat_ipc_qmi_daemon_config(void)
{
	struct cnss_plat_ipc_qmi_svc_ctx *svc = &plat_ipc_qmi_svc;
	struct cnss_plat_ipc_qmi_client_ctx *qmi_client =
		&svc->qmi_client_ctx[CNSS_PLAT_IPC_DAEMON_QMI_CLIENT_V01];

	if (!qmi_client->client_connected)
		return NULL;

	return &daemon_cfg;
}

/**
 * cnss_plat_ipc_register() - Register for QMI IPC client status update
 * @client_id: User space QMI IPC client ID. Also works as
 *		array index for QMI client context
 * @connect_update_cb: Function pointer for callback
 * @cb_ctx: Callback context
 *
 * Return: 0 on success, negative error value otherwise
 */
int cnss_plat_ipc_register(enum cnss_plat_ipc_qmi_client_id_v01 client_id,
			   struct cnss_plat_ipc_qmi_cb *ipc_qmi_callbacks,
			   void *cb_ctx)
{
	struct cnss_plat_ipc_qmi_svc_ctx *svc = &plat_ipc_qmi_svc;
	struct cnss_plat_ipc_qmi_client_ctx *qmi_client;
	int num_user;
	struct cnss_plat_data *plat_priv = NULL;

	if (client_id > CNSS_PLAT_IPC_MAX_QMI_CLIENTS) {
		cnss_pr_err("QMI IPC connection call back register failed, Invalid Client ID: %d\n",
			    client_id);
		return -EINVAL;
	}

	qmi_client = &svc->qmi_client_ctx[client_id];
	num_user = qmi_client->num_user;

	if (num_user >= CNSS_PLAT_IPC_MAX_USER) {
		cnss_pr_err("QMI IPC connection call back register failed, Max Service users reached, Num users %d\n",
			    num_user);
		return -EINVAL;
	}

	qmi_client->ipc_qmi_callbacks[num_user].connection_update_cb
				= ipc_qmi_callbacks->connection_update_cb;
	qmi_client->ipc_qmi_callbacks[num_user].config_param_cb
				= ipc_qmi_callbacks->config_param_cb;
	qmi_client->cb_ctx[num_user] = cb_ctx;
	qmi_client->num_user++;
	cnss_pr_dbg("%s Successful registration for QMI IPC Client status update\n",
		    __func__);

	return 0;
}

/**
 * cnss_plat_ipc_unregister() - Unregister QMI IPC client status callback
 * @client_id: User space QMI IPC client ID. Also works as
 *		array index for QMI client context
 * @cb_ctx: Callback context provided during registration
 *
 * Return: None
 */
void cnss_plat_ipc_unregister(enum cnss_plat_ipc_qmi_client_id_v01 client_id,
			      void *cb_ctx)
{
	struct cnss_plat_ipc_qmi_svc_ctx *svc = &plat_ipc_qmi_svc;
	struct cnss_plat_ipc_qmi_client_ctx *qmi_client;
	struct cnss_plat_data *plat_priv = NULL;
	int i;

	if (client_id > CNSS_PLAT_IPC_MAX_QMI_CLIENTS) {
		cnss_pr_err("Invalid Client ID: %d\n", client_id);
		return;
	}

	qmi_client = &svc->qmi_client_ctx[client_id];

	for (i = 0; i < qmi_client->num_user; i++) {
		if (qmi_client->cb_ctx[i] == cb_ctx) {
			qmi_client->cb_ctx[i] = NULL;
			qmi_client->ipc_qmi_callbacks[i].connection_update_cb
									= NULL;
			qmi_client->ipc_qmi_callbacks[i].config_param_cb
									= NULL;
			qmi_client->num_user--;
			break;
		}
	}
}

/**
 * cnss_plat_ipc_qmi_svc_init() - CNSS Platform qmi service init function
 *
 * Initialize a QMI client handle and register new QMI service for CNSS Platform
 *
 * Return: 0 on success, negative error value otherwise
 */
int cnss_plat_ipc_qmi_svc_init(void)
{
	int ret = 0;
	struct cnss_plat_ipc_qmi_svc_ctx *svc = &plat_ipc_qmi_svc;
	struct cnss_plat_data *plat_priv = NULL;

	svc->svc_hdl = kzalloc(sizeof(*svc->svc_hdl), GFP_KERNEL);
	if (!svc->svc_hdl)
		return -ENOMEM;

	ret = qmi_handle_init(svc->svc_hdl,
			      CNSS_PLAT_IPC_QMI_MAX_MSG_SIZE_V01,
			      &cnss_plat_ipc_qmi_ops,
			      cnss_plat_ipc_qmi_req_handlers);
	if (ret < 0) {
		cnss_pr_err("%s: Handle init fail: %d\n", __func__, ret);
		goto free_svc_hdl;
	}

	ret = qmi_add_server(svc->svc_hdl,
			     CNSS_PLATFORM_SERVICE_ID_V01,
			     CNSS_PLATFORM_SERVICE_VERS_V01, 0);
	if (ret < 0) {
		cnss_pr_err("%s: Server add fail: %d\n", __func__, ret);
		goto release_svc_hdl;
	}

	init_completion(&svc->daemon_connected);

	cnss_pr_info("%s: CNSS Platform IPC QMI Service is started\n", __func__);
	idr_init(&svc->file_idr);
	mutex_init(&svc->file_idr_lock);
	return 0;

release_svc_hdl:
	qmi_handle_release(svc->svc_hdl);
free_svc_hdl:
	kfree(svc->svc_hdl);

	return ret;
}

/**
 * cnss_plat_ipc_qmi_svc_exit() - CNSS Platform qmi service exit
 *
 * Release all resources during exit
 *
 * Return: None
 */
void cnss_plat_ipc_qmi_svc_exit(void)
{
	struct cnss_plat_ipc_qmi_svc_ctx *svc = &plat_ipc_qmi_svc;

	complete_all(&svc->daemon_connected);

	if (svc->svc_hdl) {
		qmi_handle_release(svc->svc_hdl);
		kfree(svc->svc_hdl);
		idr_destroy(&svc->file_idr);
	}

}

