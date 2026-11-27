/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef DFM_SF_AVC_H
#define DFM_SF_AVC_H

#include <linux/types.h>

int dfm_sf_avc_init(void);
void dfm_sf_avc_exit(void);
bool dfm_sf_avc_ready(void);

#endif /* DFM_SF_AVC_H */
