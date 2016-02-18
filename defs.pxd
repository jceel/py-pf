#
# Copyright 2015 iXsystems, Inc.
# All rights reserved
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted providing that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
# IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
# STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
# IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#
#####################################################################

from libc.stdint cimport *
from posix.types cimport *

ctypedef int sa_family_t
ctypedef uint32_t in_addr


cdef extern from "sys/param.h":
    enum:
        MAXPATHLEN


cdef extern from "net/if.h":
    enum:
        IFNAMSIZ


cdef extern from "sys/ioctl.h":
    cdef int ioctl(int fd, unsigned long request, ...)


cdef extern from "netinet/in.h":
    ctypedef struct in_addr_t:
        uint32_t s_addr

    cdef struct in6_addr:
        uint8_t s6_addr[16]


cdef extern from "netpfil/pf/pf.h":
    enum:
        PF_INOUT
        PF_IN
        PF_OUT
        PF_FWD

    enum:
        PF_PASS
        PF_DROP
        PF_SCRUB
        PF_NOSCRUB
        PF_NAT
        PF_NONAT
        PF_BINAT
        PF_NOBINAT
        PF_RDR
        PF_NORDR
        PF_SYNPROXY_DROP
        PF_DEFER

    enum:
        PF_RULESET_SCRUB
        PF_RULESET_FILTER
        PF_RULESET_NAT,
        PF_RULESET_BINAT,
        PF_RULESET_RDR
        PF_RULESET_MAX

    enum:
        PF_OP_NONE
        PF_OP_IRG
        PF_OP_EQ
        PF_OP_NE
        PF_OP_LT
        PF_OP_LE
        PF_OP_GT
        PF_OP_GE
        PF_OP_XRG
        PF_OP_RRG

    enum:
        PF_CHANGE_NONE
        PF_CHANGE_ADD_HEAD
        PF_CHANGE_ADD_TAIL
        PF_CHANGE_ADD_BEFORE
        PF_CHANGE_ADD_AFTER
        PF_CHANGE_REMOVE
        PF_CHANGE_GET_TICKET

    enum:
        PF_ADDR_ADDRMASK
        PF_ADDR_NOROUTE
        PF_ADDR_DYNIFTL
        PF_ADDR_TABLE
        PF_ADDR_URPFFAILED
        PF_ADDR_RANGE


cdef extern from "net/pfvar.h":
    enum:
        PF_RULE_LABEL_SIZE
        PF_TABLE_NAME_SIZE
        PF_TAG_NAME_SIZE

    cdef struct pf_addr:
        in_addr_t v4
        in6_addr v6

    cdef struct pf_addr_wrap_a:
        pf_addr addr
        pf_addr mask

    cdef union pf_addr_wrap_v:
        pf_addr_wrap_a a
        char ifname[IFNAMSIZ]
        char tblname[PF_TABLE_NAME_SIZE]

    cdef struct pf_addr_wrap:
        pf_addr_wrap_v v
        uint8_t type
        uint8_t iflags

    cdef struct pf_pooladdr_tailq:
        pf_pooladdr* tqe_next
        pf_pooladdr** tqe_prev

    cdef struct pf_pooladdr:
        pf_pooladdr_tailq entries
        pf_addr_wrap addr
        char ifname[IFNAMSIZ]

    cdef struct pf_rule_addr:
        pf_addr_wrap addr
        uint16_t port[2]
        uint8_t neg
        uint8_t port_op

    cdef struct pf_rule_divert:
        pf_addr addr
        uint16_t port

    cdef struct pf_palist:
        pf_pooladdr* tqh_first
        pf_pooladdr** tqh_last

    cdef struct pf_pool:
        pf_palist list
        pf_pooladdr* cur
        pf_addr counter
        int tblidx
        uint16_t proxy_port[2]
        uint8_t opts

    cdef struct pf_rule:
        pf_rule_addr src
        pf_rule_addr dst
        char label[PF_RULE_LABEL_SIZE]
        char ifname[IFNAMSIZ]
        char tagname[PF_TAG_NAME_SIZE]
        uint8_t rule_flag
        uint8_t action
        uint8_t direction
        uint8_t log
        uint8_t logif
        uint8_t quick
        uint8_t ifnot
        uint8_t match_tag_not
        uint8_t natpass
        uint8_t keep_state
        sa_family_t af
        uint8_t proto
        uint8_t	type
        uint8_t	code
        uint8_t	flags
        uint8_t	flagset
        uint8_t	min_ttl
        uint8_t	allow_opts
        uint8_t	rt
        uint8_t	return_ttl
        uint8_t	tos
        uint8_t	set_tos
        uint8_t	anchor_relative
        uint8_t	anchor_wildcard
        int rtableid
        pf_rule_divert divert
        pf_pool rpool

    cdef struct pfioc_pooladdr:
        uint32_t action
        uint32_t ticket
        uint32_t nr
        uint32_t r_num
        uint8_t r_action
        uint8_t r_last
        uint8_t af
        char anchor[MAXPATHLEN]
        pf_pooladdr addr

    cdef struct pfioc_trans:
        int size
        int esize
        pfioc_trans_e *array

    cdef struct pfioc_trans_e:
        int rs_num
        char anchor[MAXPATHLEN]
        uint32_t ticket

    cdef struct pfioc_table:
        pass

    cdef struct pfioc_rule:
         uint32_t action
         uint32_t ticket
         uint32_t pool_ticket
         uint32_t nr
         char anchor[MAXPATHLEN]
         char anchor_call[MAXPATHLEN]
         pf_rule rule

    cdef struct pfr_addr:
        in_addr pfra_ip4addr
        in6_addr pfra_ip6addr
        uint8_t pfra_af
        uint8_t pfra_net
        uint8_t pfra_not
        uint8_t pfra_fback

    enum:
        DIOCSTART
        DIOCSTOP
        DIOCADDRULE
        DIOCGETRULES
        DIOCGETRULE
        DIOCCLRSTATES
        DIOCGETSTATE
        DIOCSETSTATUSIF
        DIOCGETSTATUS
        DIOCCLRSTATUS
        DIOCNATLOOK
        DIOCSETDEBUG
        DIOCGETSTATES
        DIOCCHANGERULE
        DIOCSETTIMEOUT
        DIOCGETTIMEOUT
        DIOCADDSTATE
        DIOCCLRRULECTRS
        DIOCGETLIMIT
        DIOCSETLIMIT
        DIOCKILLSTATES
        DIOCSTARTALTQ
        DIOCSTOPALTQ
        DIOCADDALTQ
        DIOCGETALTQS
        DIOCGETALTQ
        DIOCCHANGEALTQ
        DIOCGETQSTATS
        DIOCBEGINADDRS
        DIOCADDADDR
        DIOCGETADDRS
        DIOCGETADDR
        DIOCCHANGEADDR
        DIOCGETRULESETS
        DIOCGETRULESET
        DIOCRCLRTABLES
        DIOCRADDTABLES
        DIOCRDELTABLES
        DIOCRGETTABLES
        DIOCRGETTSTATS
        IOCRCLRTSTATS
        DIOCRCLRADDRS
        DIOCRADDADDRS
        DIOCRDELADDRS
        DIOCRSETADDRS
        DIOCRGETADDRS
        DIOCRGETASTATS
        DIOCRCLRASTATS
        DIOCRTSTADDRS
        DIOCRSETTFLAGS
        DIOCRINADEFINE
        DIOCOSFPFLUSH
        DIOCOSFPADD
        DIOCOSFPGET
        DIOCXBEGIN
        DIOCXCOMMIT
        DIOCXROLLBACK
        DIOCGETSRCNODES
        DIOCCLRSRCNODES
        DIOCSETHOSTID
        DIOCIGETIFACES
        DIOCSETIFFLAG
        DIOCCLRIFFLAG
        DIOCKILLSRCNODES
        DIOCGIFSPEED
