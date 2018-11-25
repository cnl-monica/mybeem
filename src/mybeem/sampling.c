/*! \file sampling.c
*  \brief S�bor s implement�ciou vozrkovac�ch algoritmov pod�a �tandardu PSAMP
* 
*  Implement�cia vhodn�ch a efekt�vnych algoritmov vzorkovania po�a konfigura�n�ch parametrov. 
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

#include "debug.h"
#include "sampling.h"
#include <stdlib.h>
#include <time.h>
#include <math.h>

#define LRAND_MAX 500

/*! 
* Extern� smern�k na konfigur�ciu
*/

/*!
*  Vyvol�va funkciu vzorkovania pod�a konfigura�n�ho parametra.
* \param type Typ vzorkovania, ktor� m� by� na spracov�van� paket pou�it�
* \param param1 Prv� parameter pre pou�itie vo vzorkovacom algoritme
* \param param2 Druh� parameter pre pou�itie vo vzorkovacom algoritme
*/
int is_sampled(int type, long int param1, long int param2)
{
        char message[LOG_MESSAGE_SIZE];
	/**  explicitne paket nevzorkujeme*/
	int sampled=0;

	/**  rozhodnutie o type pouziteho vzorkovacieho algoritmu */
	switch(type) {
		case 0: sampled=1;
			break;
		case 1: sampled=systematic_count_based_sampling(param1, param2);
			break;
		case 2: sampled=systematic_time_based_sampling(param1, param2);
			break;
		case 3: sampled=n_of_N_sampling(param1, param2);
			break;
		case 4: sampled=uniform_probability_sampling(param1);
			break;
		case 5: sampled=non_uniform_probability_sampling(param1,param2);
			break;
		default:	strcpy(message,"Wrong type of sampling specified");	
				log_message(message,3);
	}

	// vratime info o tom, ci paket bol zvoleny
	return sampled;
}

/*!
*  Funkcia implementuj�ca systematick� vzorkovanie pod�a po�tu
* \param param1 Prv� parameter ur�uj�ci po�et za sebou vybran�ch paketov
* \param param2 Druh� parameter ur�uj�ci po�et za sebou nevybran�ch paketov
*/
int systematic_count_based_sampling(long int param1, long int param2)
{
        char message[LOG_MESSAGE_SIZE];
	// interne pocitadlo paketov 
	unsigned long int static counter=0;
	static int helper=0;
	counter++;

	// pomocna premenna na uchovanie zvysku po deleni modulo


	// overenie parametrov
	if ( param1 <=0  ) {
		sprintf(message,"Wrong sampling parameter #1 (%li). Should be positive integer",param1);
		log_message(message,3);
	}
	if ( param2 <=0  ) {
		sprintf(message,"Wrong sampling parameter #2 (%li). Should be positive integer",param2);
		log_message(message,3);
	}
	// vzorkujeme
	helper = counter % (param1+param2);
	if ((helper < param1) && (helper > 0)) return 0;
	else if ((helper >= param1) && (helper <= (param1+param2))) return 1;

	return 0;

}

/*!
*  Funkcia implementuj�ca systematick� vzorkovanie pod�a �asu
* \param param1 Prv� parameter ur�uj�ci d�ku intervalu, v ktorom bud� pakety vybran� 
* \param param2 Druh� parameter ur�uj�ci d�ku intervalu, v ktorom nebud� pakety vybran� 
*/
int systematic_time_based_sampling(long int param1, long int param2)
{
        char message[LOG_MESSAGE_SIZE];
	static int helper=0;
	// overenie parametrov
	if ( param1 <=0  ) {
		sprintf(message,"Wrong sampling parameter #1 (%li). Should be positive integer",param1);
		log_message(message,3);
	}
	if ( param2 <=0  ) {
		sprintf(message,"Wrong sampling parameter #2 (%li). Should be positive integer",param2);
		log_message(message,3);
	}

	// pomocna premenna na uchovanie zvysku po deleni modulo

	helper = time(NULL) % (param1+param2);

	// vzorkujeme
	if ((helper < param1) && (helper > 0)) return 0;
	else if ((helper >= param1) && (helper <= (param1 + param2))) return 1;

	return 0;
}


/*!
*  Funkcia implementuj�ca vzorkovanie "n z N". Vybrane pakety su dopredu ur�en� st�paj�cou postupnos�ou n�hodn�ch ��sel, ktor� u�uj� poradie vybran�ch paketov v s�bore pozorovan�ch paketov.
* \param param1 Prv� parameter ur�uj�ci ve�kos� mno�iny vybran�ch paketov
* \param param2 Druh� parameter ur�uj�ci ve�kos� mno�iny paketov, z ktor�ch sa bude vybera� (max. 1000)
*/
int n_of_N_sampling(long int param1, long int param2)
{
        char message[LOG_MESSAGE_SIZE];
	// pole priznakov vzorkovania, index je poradie paketu
	static int sample[1001];

	// priznak incializovaneho pola
	static int initialised=0; 

	// pozicia paketu v ramci N	
	static int position=0;

	// pomovna premenna urcujuca pocet uz inicializovanych policok v poli	
	int active=0,i;

	// overenie parametrov
	if ( param1 <=0 || param2 > 1000 )
	{
		strcpy(message,"Wrong sampling parameters. Parameters should be positive integers smaller than 1000");
		log_message(message,3);
	}
	if (param1 > param2) 
	{
		strcpy(message,"Wrong sampling parameters. Parameter1 should be smaller than parameter2");
		log_message(message,3);
	}

	// inicializacia pola priznakov vzorkovania
	if (initialised==0)
	{
		// vynulujeme pole
		for (i=0; i<= param2; i++) sample[i]=0;

		// naplnime pole priznakmi samplovania
		do 
		{
			// generujeme nahodnu poziciu z intervalu <0,N>
			int temp=((long int)rand() % (param2));
			// ak pozicia este nie je zvolena nastav priznak na 1
			if (sample[temp] == 0) 
			{
				sample[temp]=1;
				// inkrementuj procet uz definovanych priznakov
				active++;
			}
		} while ( (param1) != active);
		initialised = 1;
	}	

	// vycerpane n - reinicializacia pola
	if (position>=param2)
	{
		position=0;
		initialised=0;
	}

	// vzorkujeme podla priznaku
	if ( sample[position]==1 )
	{
		position++;
		return 1;
	}
	else
	{
		position++;
		return 0;
	}

	return 0;
}

/*!
* Funkcia implementuj�ca n�hodn� vzorkovanie s uniformnou pravdepodobnos�ou
* \param param1 Parameter ur�uj�ci hodnotu pravdepodobnosti s akou bude ka�d� paket vybran�
*/
int uniform_probability_sampling(long int param1)
{
        char message[LOG_MESSAGE_SIZE];
	// pravdepodobnost	
	double probability = 0;

	// overenie parametrov
	if ( probability > 1 || probability < 0 )
	{
		sprintf(message,"Wrong sampling paramter #1 (%li). Should be integer from 1 to 100.",param1);
		log_message(message,3);
	}

	// prekonvertujeme % na pravdepodobnost
	probability= (double) param1 / 100;

	// vzorkujeme
	if (((long int) random() / (double) LRAND_MAX ) < probability )	return 1;
	else return 0;

	return 0;
}

/*!
* Funkcia implementuj�ca n�hodn� vzorkovanie s neuniformnou pravdepodobnos�ou. Pravdepodobnos� je funkcia rozdielu, medzi aktu�lnym �asom a spodnou alebo hornou hranicou "sure sample" intervalu.
* \param param1 Parameter ur�uj�ci spodn� hodnotu "sure sample" intervalu
* \param param2 Parameter ur�uj�ci vrchn� hodnotu "sure sample" intervalu
*/
int non_uniform_probability_sampling(long int param1, long int param2)
{
        char message[LOG_MESSAGE_SIZE];
	double probability = 0;
	long int sample_time = time(NULL);
	// overenie parametrov
	if (param1 < 0 || param2 < 0)
	{
		strcpy(message,"Wrong sampling parameters. Parameters should be positive integers");		
		log_message(message,3);
	}		
	// aktualny cas				

	// vypocitana pravdepodobnost	

	// vypocet pravdepodobnosti podla funkcie
	if (sample_time < param1)
	{
		probability = sample_time / param1;
	}
	else if (sample_time> param2)
	{
		probability = param2 / sample_time;
	}
	else probability = 1;	

	// vzorkujeme				
	if (((long int) random() / (double) LRAND_MAX ) < (pow(probability,4))) return 1;
	else return 0;

	return 0;
} 
