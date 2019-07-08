/*
 *
 *  Wireless daemon for Linux
 *
 *  Copyright (C) 2019  Intel Corporation. All rights reserved.
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdbool.h>

#include <ell/ell.h>

#include "src/p2putil.h"

void p2p_attr_iter_init(struct p2p_attr_iter *iter, const uint8_t *pdu,
			size_t len)

{
	iter->pos = pdu;
	iter->end = pdu + len;
	iter->type = -1;
}

bool p2p_attr_iter_next(struct p2p_attr_iter *iter)
{
	if (iter->type != (enum p2p_attr) -1)
		iter->pos += 3 + iter->len;

	if (iter->pos + 3 > iter->end ||
			iter->pos + 3 + l_get_le16(iter->pos + 1) > iter->end)
		return false;

	iter->type = iter->pos[0];
	iter->len = l_get_le16(iter->pos + 1);
	return true;
}
