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

import os
import enum
import ipaddress
import socket
import cython
cimport defs
from libc.errno cimport *
from libc.stdint cimport *
from libc.string cimport strerror, memcpy, memset


class RulesetType(enum.IntEnum):
    SCRUB = defs.PF_RULESET_SCRUB
    FILTER = defs.PF_RULESET_FILTER
    NAT = defs.PF_RULESET_NAT,
    BINAT = defs.PF_RULESET_BINAT,
    RDR = defs.PF_RULESET_RDR
    MAX = defs.PF_RULESET_MAX


class RuleAction(enum.IntEnum):
    PASS = defs.PF_PASS
    DROP = defs.PF_DROP
    SCRUB = defs.PF_SCRUB
    NOSCRUB = defs.PF_NOSCRUB
    NAT = defs.PF_NAT
    NONAT = defs.PF_NONAT
    BINAT = defs.PF_BINAT
    NOBINAT = defs.PF_NOBINAT
    RDR = defs.PF_RDR
    NORDR = defs.PF_NORDR
    SYNPROXY_DROP = defs.PF_SYNPROXY_DROP
    DEFER = defs.PF_DEFER


class RuleOperator(enum.IntEnum):
    NONE = defs.PF_OP_NONE
    IRG = defs.PF_OP_IRG
    EQ = defs.PF_OP_EQ
    NE = defs.PF_OP_NE
    LT = defs.PF_OP_LT
    LE = defs.PF_OP_LE
    GT = defs.PF_OP_GT
    GE = defs.PF_OP_GE
    XRG = defs.PF_OP_XRG
    RRG = defs.PF_OP_RRG


class RuleAddressType(enum.IntEnum):
    ADDRMASK = defs.PF_ADDR_ADDRMASK
    NOROUTE = defs.PF_ADDR_NOROUTE
    DYNIFTL = defs.PF_ADDR_DYNIFTL
    TABLE = defs.PF_ADDR_TABLE
    URPFFAILED = defs.PF_ADDR_URPFFAILED
    RANGE = defs.PF_ADDR_RANGE


class RuleDirection(enum.IntEnum):
    INOUT = defs.PF_INOUT
    IN = defs.PF_IN
    OUT = defs.PF_OUT
    FWD = defs.PF_FWD


cdef class Address(object):
    cdef defs.pf_addr_wrap wrap

    def __str__(self):
        return "<pf.Address address '{0}' netmask '{1}'>".format(
            self.address,
            self.netmask
        )

    def __repr__(self):
        return str(self)

    def __getstate__(self):
        if self.type == RuleAddressType.ADDRMASK:
            return {
                'type': self.type.name,
                'address': str(self.address),
                'netmask': str(self.netmask),
            }

        if self.type == RuleAddressType.DYNIFTL:
            return {
                'type': self.type.name,
                'ifname': self.ifname
            }

        if self.type == RuleAddressType.TABLE:
            return {
                'type': self.type.name,
                'table': self.table_name
            }

    property type:
        def __get__(self):
            return RuleAddressType(self.wrap.type)

    property address:
        def __get__(self):
            return ipaddress.ip_address(socket.htonl(self.wrap.v.a.addr.v4.s_addr))

    property netmask:
        def __get__(self):
            return ipaddress.ip_address(socket.htonl(self.wrap.v.a.mask.v4.s_addr))

    property table_name:
        def __get__(self):
            return self.wrap.v.tblname

    property ifname:
        def __get__(self):
            return self.wrap.v.ifname


cdef class AddressPool(object):
    cdef PF pf
    cdef defs.pf_pool *pool
    cdef uint32_t ticket
    cdef int action
    cdef int nr

    def __getstate__(self):
        return [i.__getstate__() for i in self.items]

    property items:
        def __get__(self):
            cdef Address addr
            cdef defs.pfioc_pooladdr pp

            memset(&pp, 0, cython.sizeof(defs.pfioc_pooladdr))
            pp.r_action = self.action
            pp.r_num = self.nr
            pp.ticket = self.ticket

            if self.pf.ioctl(defs.DIOCGETADDRS, &pp) != 0:
                raise OSError(errno, strerror(errno))

            for i in range(0, pp.nr):
                memset(&pp, 0, cython.sizeof(defs.pfioc_pooladdr))
                pp.r_action = self.action
                pp.r_num = self.nr
                pp.ticket = self.ticket

                if self.pf.ioctl(defs.DIOCGETADDR, &pp) != 0:
                    raise OSError(errno, strerror(errno))

                addr = Address.__new__(Address)
                memcpy(&addr.wrap, &pp.addr.addr, cython.sizeof(defs.pf_addr_wrap))
                yield addr

    def append(self, address):
        pass

    def remove(self, index):
        pass


cdef class RuleAddress(object):
    cdef defs.pf_rule_addr* addr

    def __str__(self):
        return "<pf.RuleAddress address '{0}' port_range '{1}' port_op '{2}'>".format(
            self.address,
            self.port_range,
            self.port_op
        )

    def __repr__(self):
        return str(self)

    def __getstate__(self):
        return {
            'address': self.address.__getstate__(),
            'port_range': self.port_range,
            'port_op': self.port_op.name
        }

    property address:
        def __get__(self):
            cdef Address addr

            addr = Address.__new__(Address)
            memcpy(&addr.wrap, &self.addr.addr, cython.sizeof(defs.pf_addr_wrap))
            return addr

    property port_range:
        def __get__(self):
            return [socket.ntohs(i) for i in self.addr.port]

        def __set__(self, values):
            self.addr.port = [socket.htons(i) for i in values]

    property port_op:
        def __get__(self):
            return RuleOperator(self.addr.port_op)

        def __set__(self, op):
            self.addr.port_op = op


cdef class Rule(object):
    cdef PF pf
    cdef defs.pf_rule rule
    cdef uint32_t ticket
    cdef int nr

    def __getstate__(self):
        return {
            'src': self.src.__getstate__(),
            'dst': self.dst.__getstate__(),
            'action': self.action.name,
            'type': self.type,
            'ifname': self.ifname,
            'redirect_pool': self.redirect_pool.__getstate__(),
            'proxy_ports': self.proxy_ports
        }

    property src:
        def __get__(self):
            cdef RuleAddress addr

            addr = RuleAddress.__new__(RuleAddress)
            addr.addr = &self.rule.src
            return addr

    property dst:
        def __get__(self):
            cdef RuleAddress addr

            addr = RuleAddress.__new__(RuleAddress)
            addr.addr = &self.rule.dst
            return addr

    property divert_addr:
        def __get__(self):
            return ipaddress.ip_address(self.rule.divert.addr.v4.s_addr)

    property divert_port:
        def __get__(self):
            return self.rule.divert.port

    property action:
        def __get__(self):
            return RuleAction(self.rule.action)

    property type:
        def __get__(self):
            return self.rule.type

    property code:
        def __get__(self):
            return self.rule.code

    property label:
        def __get__(self):
            return self.rule.label

    property ifname:
        def __get__(self):
            return self.rule.ifname

    property redirect_pool:
        def __get__(self):
            cdef AddressPool pool

            pool = AddressPool.__new__(AddressPool)
            pool.pf = self.pf
            pool.pool = &self.rule.rpool
            pool.ticket = self.ticket
            pool.nr = self.nr
            pool.action = self.rule.action
            return pool

    property proxy_ports:
        def __get__(self):
            return self.rule.rpool.proxy_port

        def __set__(self, value):
            self.rule.rpool.proxy_port = value


cdef class PF(object):
    cdef int ioctl(self, uint32_t cmd, void* args):
        cdef int result

        fd = os.open('/dev/pf', os.O_RDWR)
        result = defs.ioctl(fd, cmd, args)
        os.close(fd)
        return result

    def get_rules(self, table):
        cdef Rule r
        cdef defs.pfioc_rule rule

        tables = {
            'scrub': defs.PF_SCRUB,
            'filter': defs.PF_PASS,
            'nat': defs.PF_NAT,
            'binat': defs.PF_BINAT,
            'rdr': defs.PF_RDR
        }

        if table not in tables:
            raise KeyError('Invalid table name')

        rule.rule.action = tables[table]

        if self.ioctl(defs.DIOCGETRULES, &rule) != 0:
            raise OSError(errno, strerror(errno))

        for i in range(0, rule.nr):
            rule.nr = i
            if self.ioctl(defs.DIOCGETRULE, &rule) != 0:
                raise OSError(errno, strerror(errno))

            r = Rule.__new__(Rule)
            r.pf = self
            r.ticket = rule.ticket
            r.nr = rule.nr
            memcpy(&r.rule, &rule.rule, cython.sizeof(rule.rule))
            yield r

    def append_rule(self):
        pass