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
import cython
cimport defs
from libc.errno cimport *
from libc.stdint cimport *
from libc.string cimport strerror, memcpy


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


cdef class RuleAddress(object):
    cdef defs.pf_rule_addr* addr

    def __str__(self):
        return "<pf.RuleAddress address '{0}' netmask '{1}' ifname '{2}' table '{3}'".format(
            self.address,
            self.netmask,
            self.ifname,
            self.table_name
        )

    def __repr__(self):
        return str(self)

    property type:
        def __get__(self):
            return RuleAddressType(self.addr.addr.type)

    property address:
        def __get__(self):
            return ipaddress.ip_address(self.addr.addr.v.a.addr.v4.s_addr)

    property netmask:
        def __get__(self):
            return ipaddress.ip_address(self.addr.addr.v.a.mask.v4.s_addr)

    property ifname:
        def __get__(self):
            return self.addr.addr.v.ifname

    property table_name:
        def __get__(self):
            return self.addr.addr.v.tblname


cdef class Rule(object):
    cdef defs.pf_rule rule

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
            memcpy(&r.rule, &rule.rule, cython.sizeof(rule))
            yield r

    def add_rule(self):
        pass