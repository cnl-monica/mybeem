/*! \file list.c
 *  \brief Modul pre prácu s jednosmerným cyklickym zoznamom
 *
 * Tento modul obsahuje funkcie na prácu s jednosmerným zoznamom.
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

#include "queue.h"

void inline insert_after(struct list_item *item, struct list_item *newitem){
	if(item == 0){
		newitem->next = newitem;
	}else{
		newitem->next = item->next;
		item->next = newitem;
	}
}
/*
void queue_add_first(struct queue *queue, struct list_item *item){
	insert_after(queue->last, item);
	if(queue->last == NULL)
		queue->last = item;
}
*/
void queue_add_last(struct queue *queue, struct list_item *item){
	insert_after(queue->last, item);
	queue->last = item;
	queue->size++;
}

struct list_item *queue_remove_first(struct queue *queue){
	struct list_item *item = queue->last;

	if(item == 0)	//empty queue
		return 0;
	if(item == item->next){	//one element in queue
		queue->last = 0;
		return item;
	}
	item = item->next;	//item is first item now
	queue->last->next = item->next;
	queue->size--;
	return item;
}

