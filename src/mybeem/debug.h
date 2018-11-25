/*! \file debug.h
*  \brief Hlavickovy subor obsahujuci deklaraciu funkcie a premennych potrebnych pre spravu kontrolnych vypisov programu.
*/

/*
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


#define	LOG_MESSAGE_SIZE	3000	

#include <stdio.h>

//extern char message[LOG_MESSAGE_SIZE];
extern int logLevel;

void log_message(char message[],int code);


