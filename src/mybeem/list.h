/*! \file list.h
*  \brief Hlavièkový súbor modulu na prácu s jednosmerným zoznamom.
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

#ifndef _LIST_H_
#define _LIST_H_

struct list_item {
	struct list_item	*next;
	int			value;
};
struct list {
	struct list_item	*first;
	struct list_item	*last;
};

void list_add_first(struct list *list, struct list_item *item);
void list_add_last(struct list *list, struct list_item *item);
struct list_item *list_remove_first(struct list *list);
struct list_item *list_remove_last(struct list *list);
struct list_item *list_remove_item(struct list *list, struct list_item *item);
int list_size(struct list *list);

#endif

