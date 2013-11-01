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
//This function is called by the main plugin every time that a route has to be added to the HNA's list
//The parameters are the pointer to the pointer of the hna's list, the ip of the network and the lenght of the prefix of the net

int new_route_add(struct ip_prefix_list **list, const union olsr_ip_addr *net, uint8_t prefix_len){

	struct ip_prefix_list *h;
	for(h=*list; h!=NULL; h=h->next){ // search inside all the hna's list
		switch(check_route_relationship(*net, prefix_len, h->net.prefix, h->net.prefix_len)){
			case 2:
				//TODO: management of the deleted routes using another list to store it
				// don't add the new route in this case because it is already reachable using the bigger one.
				// must store this new route in the case of the bigger one have to be deleted.
				return 1;
				break;

			case 1:
				ip_prefix_list_remove(list, &h->net.prefix, h->net.prefix_len); // delete this route becaus it is contained in my new route
				//TODO: management of the deleted routes using another list to store it
				// this route could be still joined to another, so i don't return.
				break;

			case 0:
				ip_prefix_list_remove(list, &h->net.prefix, prefix_len); // delete this route because it has to be joined with the new one
				new_route_add(list, net, prefix_len-1); // add the bigger route that contains the the two ones
				return 2;
				break;

			default:
				//le due route non sono aggregabili
				break;
		}
	}
	ip_prefix_list_add(list, net, prefix_len); // no way, we have to add this route as it is.
	return 0;
}





int check_route_relationship(union olsr_ip_addr net1, uint8_t prefix_1, union olsr_ip_addr net2, uint8_t prefix_2){
/*This function check the relationship between two given routes:
 * 	return -1 if there is no relationship
 * 		eg: 192.168.1.0/24 and 192.168.3.0/24
 * 	return 0 if the two routes are joinable in a single bigger route
 * 		eg:	192.168.0.0/24 and 192.168.1.0/24 can be joined in 192.168.0.0/23
 * 	return 1 if  net1/prefix_1 contains net2/prefix_2
 * 		eg:	192.168.0.0/16 contains 192.168.1.0/24
 * 	return 2 if net1/prefix_2 is contained by net1/prefix_1
 * 		eg:	192.168.1.0/24 is contained by 192.168.0.0/16
 * 	*/
	//check the lenght of the prefix to know which route is bigger
	if(prefix_1==prefix_2){
		if(get_network_address(net1, prefix_1-1) == get_network_address(net2, prefix_2-1)){
			return 0;
		}
	}
	else if(prefix_1<prefix_2){
		if(get_network_address(net2, prefix_1) == get_network_address(net1, prefix_1)){
			return 1;
		}
	}
	else if(prefix_1>prefix_2){
		if(get_network_address(net1, prefix_2) == get_network_address(net2, prefix_2)){
			return 2;
		}
	}
	return -1;
}


/* This function return the network address of a given ip address and netmask
 * eg: get_network_address(192.168.1.1, 16) will return 192.168.0.0
 * */
unsigned long get_network_address(union olsr_ip_addr ip, uint8_t prefix_len){
	return ((2)^(prefix_len-1))&ip.v4.s_addr; // bitwise AND between ip address and subnet mask
}
