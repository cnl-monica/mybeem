/*! \file list.c
*  \brief Modul pre pr�cu s jednosmern�m zoznamom
* 
* Tento modul obsahuje funkcie na pr�cu s jednosmern�m zoznamom.
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

#include "list.h"


int list_size(struct list *list){
	int size;
	struct list_item *item;

	size = 0;
	item = list->first;
	while(item){
		size++;
		item = item->next;
	}
	return size;
}
void list_add_first(struct list *list, struct list_item *item){
	if(!item)
		return;
	item->next = list->first;
	list->first = item;
}
void list_add_last(struct list *list, struct list_item *item){
	struct list_item *curr;

	if(!item)
		return;
	curr = list->first;
	if(!curr){
		list_add_first(list, item);
		return;
	}
	while(curr->next)
		curr = curr->next;
	curr->next = item;
	item->next = 0;
}
struct list_item *list_remove_first(struct list *list){
	struct list_item *first;
        
	first = list->first;
	if(!first)
		return first;
	list->first = first->next;
	first->next = 0;
	return first;
}
struct list_item *list_remove_last(struct list *list){
	struct list_item *curr, *last;

	curr = list->first;
	if(!curr)
		return curr;
	if(!curr->next){
		list->first = 0;
		return curr;
	}
	while(curr->next->next)
		curr = curr->next;
	last = curr->next;
	curr->next = 0;
	return last;
}
struct list_item *list_remove_item(struct list *list, struct list_item *item){
	struct list_item *curr, *ret;

	if(!item)
		return item;
	if(!list->first)
		return 0;
	curr = list->first;
	if(curr == item){
		list->first = curr->next;
		curr->next = 0;
		return curr;
	}
	while(curr->next != item)
		if(curr->next)
			curr = curr->next;
		else	return 0;
		ret = curr->next;
		curr->next = ret->next;
		ret->next = 0;
		return ret;
}
