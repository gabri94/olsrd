/*
 * OLSRd proto plugin route aggregation function
 *
 * Copyright (c) 2013 Gabriel <gabriel@autistici.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * * Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 * * Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in
 *   the documentation and/or other materials provided with the
 *   distribution.
 * * Neither the name of olsr.org, olsrd nor the names of its
 *   contributors may be used to endorse or promote products derived
 *   from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * Visit http://www.olsr.org for more information.
 *
 * If you find this software useful feel free to make a donation
 * to the project. For more information see the website or contact
 * the copyright holders.
 *
 */
#include "aggreg.h"

int new_route_add(struct ip_prefix_list **list, const union olsr_ip_addr *net, uint8_t prefix_len){

	struct ip_prefix_list *h;
	for(h=list; h!='NULL'; h=h->next){ // scorro tutta la lista in cerca di route più grandi
		//controllo se la route è già contenunta in una route più grande
		if(check_route_relationship(net, prefix_len, h->net->prefix, h->net->prefix_len)==2){ // se la route nuova(net) è contenuta in quella attuale(h->net)
			//TODO: gestione delle route rimosse, o non aggiunte, attraverso lista di appoggio
			// non aggiungo la rotta in quanto ne annuncio già una più grande, ma la aggiungo a una lista di appoggio per ricordarmela quando rimuoverò qualcosa
			return 1; // termino l'esecuzione in quanto ho, in qualche maniera, reso la destinazione raggiungibile
		}
	}

	for(h=list; h!='NULL'; h=h->next){ // scorro tutta la lista in cerca di route più piccole
		//controllo se la route nuova contiene già route più piccole
		if(check_route_relationship(net, prefix_len, h->net->prefix, h->net->prefix_len)==1){ // se la route nuova contiene quella attuale
			ip_prefix_list_remove(list,h->net->prefix, h->net->prefix_len);
			//TODO: gestione delle route rimosse attraverso la lista di appoggio
			// non ritorno, perchè la route potrebbe ancora essere aggregata ad un altra
		}
	}

	for(h=list; h!='NULL'; h=h->next){ // scorro tutta la lista in cerca di route uguali

		if(check_route_relationship(net, prefix_len, h->net->prefix, h->net->prefix_len)==0){
			ip_prefix_list_remove(list,h->net->prefix, prefix_len); // rimuovo la subnet trovata
			ip_prefix_list_add(list, net, prefix_len-1); // annuncio la subnet più grande
			return 2; // termino l'esecuzione in quanto ho reso la destinazione raggiungibile
		}
	}
	// se arrivo qui significa che devo aggiungere manualmente la route
	ip_prefix_list_add(list, net, prefix_len);
	return 0;
}





int check_route_relationship(union olsr_ip_addr net1, uint8_t prefix_1, union olsr_ip_addr net2, uint8_t prefix_2){
/*This function check the relationship between two given routes:
 * 	return 0 if the two routes are joinable in a single bigger route: 192.168.0.0/24 and 192.168.1.0/24 can be joined in 192.168.0.0/23
 * 	return 1 if  net1/prefix_1 contains net2/prefix_2 : 192.168.0.0/16 contains 192.168.1.0/24
 * 	return 2 if net1/prefix_2 is contained by net1/prefix_1:  192.168.1.0/24 is contained by 192.168.0.0/16
 * 	return -1 if there is no relationship
 * 	*/
	if(prefix_1==prefix_2){
		if( get_network_address(net1->v4->s_addr, prefix_1-1) == get_network_address(net2->v4->s_addr, prefix_2-1)){
			return 0;
		}
	}
	else if(prefix_1<prefix_2){
		if(get_network_address(net2->v4->s_addr, prefix_1)== get_network_address(net1->v4->s_addr, prefix_1)){ //
			return 1;
		}
	}
	else if(prefix_1>prefix_2){// se la net2 è più grande
		if(get_network_address(net1->v4->s_addr, prefix_2)==get_network_address(net2->v4->s_addr, prefix_2)){
			return 2;
		}
	}
	return -1;
}


/* This function return the network address of a given ip address and netmask
 * eg: get_network_address(192.168.1.1, 16) will return 192.168.0.0
 * */
union olsr_ip_addr get_network_address(union olsr_ip_addr ip, uint8_t prefix_len){
	return (2^(prefix_len)-1)&ip; // bitwise AND between ip address and subnet mask
}
