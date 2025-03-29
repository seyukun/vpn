//go:build !android && !ios && !windows

/* ******************************************************************************************************************** */
/*                                                                                                                      */
/*                                                      :::    :::     :::     :::     :::   ::: ::::::::::: :::::::::: */
/*   queueconstants_default.go                         :+:   :+:    :+: :+:   :+:     :+:   :+:     :+:     :+:         */
/*                                                    +:+  +:+    +:+   +:+  +:+      +:+ +:+      +:+     +:+          */
/*   By: yus-sato <yus-sato@kalyte.ro>               +#++:++    +#++:++#++: +#+       +#++:       +#+     +#++:++#      */
/*                                                  +#+  +#+   +#+     +#+ +#+        +#+        +#+     +#+            */
/*   Created: 2025/03/29 05:01:07 by yus-sato      #+#   #+#  #+#     #+# #+#        #+#        #+#     #+#             */
/*   Updated: 2025/03/29 19:22:22 by yus-sato     ###    ### ###     ### ########## ###        ###     ##########.ro    */
/*                                                                                                                      */
/* ******************************************************************************************************************** */

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package device

import "golang.zx2c4.com/wireguard/conn"

const (
	QueueStagedSize    = conn.IdealBatchSize
	QueueOutboundSize  = 1024
	QueueInboundSize   = 1024
	QueueHandshakeSize = 1024
	/* ADDON  QueueStunSize  = 1024*/
	QueueStunSize              = 1024
	MaxSegmentSize             = (1 << 16) - 1 // largest possible UDP datagram
	PreallocatedBuffersPerPool = 0             // Disable and allow for infinite memory growth
)
