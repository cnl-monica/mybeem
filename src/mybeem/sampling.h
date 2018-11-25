/*! \file sampling.h
 *  \brief Hlavièkový súbor modulu vzorkovania
 *
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

#ifndef _SAMPLING__H_
#define _SAMPLING__H_
 
	int is_sampled(int type, long int param1, long int param2);

	int uniform_probability_sampling(long int param1);

	int systematic_count_based_sampling(long int param1, long int param2);

	int systematic_time_based_sampling(long int param1, long int param2);

	int n_of_N_sampling(long int param1, long int param2);	

	int non_uniform_probability_sampling(long int param1, long int param2);

#endif





