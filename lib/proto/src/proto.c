/*
 * OLSRd proto plugin
 *
 * Copyright (c) 2013 Claudio Pisa <clauz@ninux.org>
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

#include "proto.h"
#include "aggreg.h"

int target_proto_no = -1;
int target_table_no = -1;
int sock = -1;
struct sockaddr_nl nladdr;

void parse_route_entry (struct  nlmsghdr *nlh);

void parse_route_entry (struct  nlmsghdr *nlh)
{
	struct rtmsg *route_entry;
	struct rtattr *route_attribute; 
	int route_attribute_len = 0;
	char destination_address[32];
	char gateway_address[32];
	union olsr_ip_addr proto_hna4_addr;
	uint8_t proto_hna4_netmask_length;
	unsigned char route_protocol = 0;

	route_entry = (struct rtmsg *) NLMSG_DATA(nlh);

	if (target_table_no >= 0 && route_entry->rtm_table != target_table_no)
		return;

	route_protocol = route_entry->rtm_protocol;
	if(target_proto_no >= 0 && route_protocol != target_proto_no)
		return;

	proto_hna4_netmask_length = route_entry->rtm_dst_len;

    route_attribute = (struct rtattr *) RTM_RTA(route_entry);

    /* Get the route atttibutes len */
    route_attribute_len = RTM_PAYLOAD(nlh);

    /* Loop through all attributes */
    for ( ; RTA_OK(route_attribute, route_attribute_len); \
        route_attribute = RTA_NEXT(route_attribute, route_attribute_len))
    {
        /* Get the destination address */
        if (route_attribute->rta_type == RTA_DST)
        {
            inet_ntop(AF_INET, RTA_DATA(route_attribute), \
                    destination_address, sizeof(destination_address));
			memcpy(&proto_hna4_addr.v4.s_addr, RTA_DATA(route_attribute), sizeof(proto_hna4_addr.v4.s_addr));
        }

        /* Get the gateway (Next hop) */
        if (route_attribute->rta_type == RTA_GATEWAY)
        {
            inet_ntop(AF_INET, RTA_DATA(route_attribute), \
                    gateway_address, sizeof(gateway_address));
        }
    }
	olsr_printf(3, "*** PROTO: Adding HNA: %s/%d proto %d and gateway %s\n", \
         destination_address, proto_hna4_netmask_length, route_protocol, gateway_address);

	//ip_prefix_list_add(&olsr_cnf->hna_entries, &proto_hna4_addr, proto_hna4_netmask_length);
	new_route_add(&olsr_cnf->hna_entries, &proto_hna4_addr, proto_hna4_netmask_length);
}

void
existing_routes_hna_injection (void)
{
	/* retrieve the existing routes that match our protocol and table numbers and announce them as HNAs */

	int fd = olsr_cnf->rtnl_s;
	struct sockaddr_nl kernel; /* the remote (kernel space) side of the communication */
	
	struct msghdr rtnl_msg;    /* generic msghdr struct for use with sendmsg */
	struct iovec io;	     /* IO vector for sendmsg */
	struct nl_req_s req;              /* structure that describes the rtnetlink packet itself */
	char reply[BUFFER_SIZE]; /* a large buffer to receive lots of link information */
	
	pid_t pid = getpid();	     /* our process ID to build the correct netlink address */
	int end = 0;		     /* some flag to end loop parsing */


	/* RTNL socket is ready for use, prepare and send request */
	memset(&rtnl_msg, 0, sizeof(rtnl_msg));
	memset(&kernel, 0, sizeof(kernel));
	memset(&req, 0, sizeof(req));

	kernel.nl_family = AF_NETLINK; /* fill-in kernel address (destination of our message) */
	kernel.nl_groups = 0;

	req.hdr.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtgenmsg));
	req.hdr.nlmsg_type = RTM_GETROUTE;
	req.hdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP; 
	req.hdr.nlmsg_seq = 1;
	req.hdr.nlmsg_pid = pid;
	req.gen.rtgen_family = AF_INET; 

	io.iov_base = &req;
	io.iov_len = req.hdr.nlmsg_len;
	rtnl_msg.msg_iov = &io;
	rtnl_msg.msg_iovlen = 1;
	rtnl_msg.msg_name = &kernel;
	rtnl_msg.msg_namelen = sizeof(kernel);

	sendmsg(fd, (struct msghdr *) &rtnl_msg, 0);

	/* parse reply */
	while (!end)
	  {
		unsigned int len;
		struct nlmsghdr *msg_ptr;	/* pointer to current message part */
		struct msghdr rtnl_reply;	/* generic msghdr structure for use with recvmsg */
		struct iovec io_reply;

		memset(&io_reply, 0, sizeof(io_reply));
		memset(&rtnl_reply, 0, sizeof(rtnl_reply));

		io.iov_base = reply;
		io.iov_len = BUFFER_SIZE;
		rtnl_reply.msg_iov = &io;
		rtnl_reply.msg_iovlen = 1;
		rtnl_reply.msg_name = &kernel;
		rtnl_reply.msg_namelen = sizeof(kernel);

		len = recvmsg(fd, &rtnl_reply, 0); /* read as much data as fits in the receive buffer */
		if (len)
		{
			for (msg_ptr = (struct nlmsghdr *) reply; NLMSG_OK(msg_ptr, len); msg_ptr = NLMSG_NEXT(msg_ptr, len))
			{
				switch(msg_ptr->nlmsg_type)
				{
					case 3:		/* this is the special meaning NLMSG_DONE message we asked for by using NLM_F_DUMP flag */
						end++;
						break;
					case 24: 	/* a route entry */
						parse_route_entry(msg_ptr);
						break;
					default:
						break;
				}
			}
		}
		
	  }
}

void
proto_inject_hnas (int fd __attribute__ ((unused)), void *data __attribute__ ((unused)), unsigned int flags __attribute__ ((unused)))
{
	/* monitor the routes that match our protocol and table numbers and announce them as HNAs */
	union olsr_ip_addr proto_hna4_addr;
	uint8_t proto_hna4_netmask_length;

	int     received_bytes = 0;
    struct  nlmsghdr *nlh;
    char    destination_address[32];
    unsigned char    route_protocol = 0;
    char    gateway_address[32];
    struct  rtmsg *route_entry;  /* This struct represent a route entry \
                                    in the routing table */
    struct  rtattr *route_attribute; /* This struct contain route \
                                            attributes (route type) */
    int     route_attribute_len = 0;
    char    buffer[BUFFER_SIZE];

	olsr_printf(7, "*** PROTO: inject HNAs function\n");

    bzero(destination_address, sizeof(destination_address));
    bzero(gateway_address, sizeof(gateway_address));
    bzero(buffer, sizeof(buffer));

    /* Receiving netlink socket data */
    while (1)
    {
        received_bytes = recv(sock, buffer, sizeof(buffer), 0);
        if (received_bytes < 0)
            ERR_RET("recv");
        /* cast the received buffer */
        nlh = (struct nlmsghdr *) buffer;
        /* If we received all data ---> break */
        if (nlh->nlmsg_type == NLMSG_DONE)
            break;
        /* We are just interested in Routing information */
        if (nladdr.nl_groups == RTMGRP_IPV4_ROUTE)
            break;
    }

    /* Reading netlink socket data */
    /* Loop through all entries */
    for ( ; NLMSG_OK(nlh, (unsigned int)received_bytes); \
                    nlh = NLMSG_NEXT(nlh, received_bytes))
    {
        /* Get the route data */
        route_entry = (struct rtmsg *) NLMSG_DATA(nlh);

        /* If we are just interested in one routing table */
        if (target_table_no >= 0 && route_entry->rtm_table != target_table_no)
            continue;

        if (target_proto_no >= 0 && route_entry->rtm_protocol != target_proto_no)
            continue;

		proto_hna4_netmask_length = (uint8_t)route_entry->rtm_dst_len;
		route_protocol = route_entry->rtm_protocol;

        /* Get attributes of route_entry */
        route_attribute = (struct rtattr *) RTM_RTA(route_entry);

        /* Get the route atttibutes len */
        route_attribute_len = RTM_PAYLOAD(nlh);
        /* Loop through all attributes */
        for ( ; RTA_OK(route_attribute, route_attribute_len); \
            route_attribute = RTA_NEXT(route_attribute, route_attribute_len))
        {
            /* Get the destination address */
            if (route_attribute->rta_type == RTA_DST)
            {
                inet_ntop(AF_INET, RTA_DATA(route_attribute), \
                        destination_address, sizeof(destination_address));
				memcpy(&proto_hna4_addr.v4.s_addr, RTA_DATA(route_attribute), sizeof(proto_hna4_addr.v4.s_addr));
            }
            /* Get the gateway (Next hop) */
            if (route_attribute->rta_type == RTA_GATEWAY)
                inet_ntop(AF_INET, RTA_DATA(route_attribute), \
                        gateway_address, sizeof(gateway_address));
        }

        /* Now we can dump the routing attributes */
        if (nlh->nlmsg_type == RTM_DELROUTE)
		{
            olsr_printf(3, "*** PROTO: Deleting HNA: %s/%d proto %d gateway %s\n", \
                destination_address, proto_hna4_netmask_length, route_protocol, gateway_address);
			ip_prefix_list_remove(&olsr_cnf->hna_entries, &proto_hna4_addr, proto_hna4_netmask_length);
		}
        if (nlh->nlmsg_type == RTM_NEWROUTE)
		{
            olsr_printf(3, "*** PROTO: Adding HNA: %s/%d proto %d and gateway %s\n", \
				destination_address, proto_hna4_netmask_length, route_protocol, gateway_address);
			new_route_add(&olsr_cnf->hna_entries, &proto_hna4_addr, proto_hna4_netmask_length);
		}
    }

	return;

}

