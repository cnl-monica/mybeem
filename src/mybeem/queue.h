/*! \file list.h
 *  \brief Hlavièkový súbor modulu na prácu s jednosmerným cyklickym zoznamom.
 *
 */

/*
 *    Copyright (c) 2009 Lubos Husivarga
 *
 *    This file is part of BEEM.
 *
 *    BEEM is free software: you can redistribute it and/or modify
 *    it under the terms of the GNU General Public License as published by
 *    the Free Software Foundation, either version 3 of the License, or
 *    (at your option) any later version.
 *
 *    BEEM is distributed in the hope that it will be useful,
 *    but WITHOUT ANY WARRANTY; without even the implied warranty of
 *    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *    GNU General Public License for more details.
 *
 *    You should have received a copy of the GNU General Public License
 *    along with BEEM.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef _QUEUE_H_
#define _QUEUE_H_

#include "list.h"

struct queue {
        struct list_item        *last;
	int			size;
};

void queue_add_last(struct queue *queue, struct list_item *item);
struct list_item *queue_remove_first(struct queue *queue);

#endif	//_QUEUE_H_
