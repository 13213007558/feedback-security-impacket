# Impacket - Collection of Python classes for working with network protocols.
#
# Copyright Fortra, LLC and its affiliated companies 
#
# All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description:
#   Kerberos Credential Cache format implementation
#   based on file format described at:
#   https://repo.or.cz/w/krb5dissect.git/blob_plain/HEAD:/ccache.txt
#   Pretty lame and quick implementation, not a fun thing to do
#   Contribution is welcome to make it the right way
#
# Author:
#   Alberto Solino (@agsolino)
#
from datetime import datetime, timezone
import os
from struct import pack, unpack, calcsize
from six import b, PY2

from pyasn1.codec.der import decoder, encoder
from pyasn1.type.univ import noValue
from binascii import hexlify

from impacket.structure import Structure
from impacket.krb5 import crypto, constants, types
from impacket.krb5.asn1 import AS_REP, seq_set, TGS_REP, EncTGSRepPart, EncASRepPart, Ticket, KRB_CRED, \
    EncKrbCredPart, KrbCredInfo, seq_set_iter
from impacket.krb5.types import KerberosTime
from impacket import LOG

try:
    FileNotFoundError
except NameError:
    FileNotFoundError = IOError

DELTA_TIME = 1


class CachePolicyError(Exception):
    """
    Raised by strict Kerberos cache selection when no verified credential is
    available for the requested service. It is raised before any
    authentication message (AP_REQ) is built or sent, so a failed cache
    lookup never falls back silently to another service's ticket.
    """
    pass


class KerberosCachePolicy:
    """
    Selects how a CCache entry is picked for a requested SPN.

    Modes
    =====
    - ``legacy``: the historical impacket behaviour. Exact match first, then
      the ``anySPN`` relaxed match (any service name accepted for the same
      host/realm, short-name/FQDN equivalence, machine-account heuristics).
      This is the default when no policy is passed, and can also be requested
      explicitly with :meth:`legacy`.
    - ``strict``: every aspect of the match must be verified. The requested
      service, host and realm must match the cache entry exactly (after the
      configured normalization), and the cache entry's server principal must
      match the principal inside the actual Kerberos ticket it carries, so a
      cache entry whose index was tampered with (e.g. relabelled
      ``cifs/host`` while the ticket is really for ``ldap/host``) is
      rejected. There is no ``anySPN`` fallback: one ticket for a host is
      NOT treated as a credential for every service on that host.

    Trusted configuration entry points (strict mode)
    ================================================
    All relaxation in strict mode is explicit, passed by the caller:

    - ``case_sensitive``: by default service and host names are compared
      case-insensitively (service upper-cased, host lower-cased); realms are
      ALWAYS compared case-insensitively since they are upper-case by
      convention. Set to True only if your KDC issues case-significant
      principal names.
    - ``host_aliases``: dict mapping an alias host name to its canonical
      name (e.g. ``{'fileserver': 'fileserver.example.test'}``). Both the
      requested and the cached host are canonicalized through it. Short
      name vs FQDN is NOT matched automatically; add an alias if you trust
      the equivalence.
    - ``service_aliases``: dict mapping a requested service name to the
      iterable of cached service names accepted for it
      (e.g. ``{'cifs': ['host']}``). Without it, only the exact same
      service name matches. Windows' implicit SPN substitutions
      (cifs/ldap/http -> host) are never applied automatically.
    - ``allowed_realms``: optional iterable of realms the requested SPN is
      allowed to target; anything else is rejected before scanning the
      cache.

    Migrating from legacy mode
    ==========================
    Switching to strict mode surfaces these problems early (as
    :class:`CachePolicyError`, before any packet is sent) instead of
    silently authenticating with the wrong ticket:

    - caches that only worked because of ``anySPN`` cross-service reuse
      (e.g. an ``ldap/`` ticket used for ``cifs/``);
    - short-name vs FQDN mismatches that need an explicit ``host_aliases``
      entry;
    - service substitutions (``cifs`` -> ``host`` and friends) that need an
      explicit ``service_aliases`` entry;
    - cache entries whose embedded ticket does not match their claimed
      server principal (cache index spoofing or corrupted caches);
    - requests for the wrong realm, previously masked by loose matching;
    - missing tickets, which now fail closed instead of silently falling
      back to password-based TGT retrieval.
    """

    MODE_LEGACY = 'legacy'
    MODE_STRICT = 'strict'

    def __init__(self, mode=MODE_LEGACY, case_sensitive=False, host_aliases=None, service_aliases=None,
                 allowed_realms=None):
        if mode not in (self.MODE_LEGACY, self.MODE_STRICT):
            raise ValueError('Unknown Kerberos cache policy mode: %r' % (mode,))
        self.mode = mode
        self.case_sensitive = bool(case_sensitive)
        self.host_aliases = {}
        for alias, canonical in (host_aliases or {}).items():
            self.host_aliases[self.normalizeHost(alias)] = self.normalizeHost(canonical)
        self.service_aliases = {}
        for requested, accepted in (service_aliases or {}).items():
            self.service_aliases[self.normalizeService(requested)] = \
                set(self.normalizeService(service) for service in accepted)
        self.allowed_realms = None
        if allowed_realms is not None:
            self.allowed_realms = set(self.normalizeRealm(realm) for realm in allowed_realms)

    @classmethod
    def strict(cls, **kwargs):
        """Returns a strict-mode policy. All relaxation must be passed explicitly as kwargs."""
        kwargs['mode'] = cls.MODE_STRICT
        return cls(**kwargs)

    @classmethod
    def legacy(cls):
        """Returns a policy explicitly requesting the historical loose matching behaviour."""
        return cls(mode=cls.MODE_LEGACY)

    def normalizeService(self, service):
        return service if self.case_sensitive else service.upper()

    def normalizeHost(self, host):
        # A port or instance suffix (host:445, host:1433) is not part of the host identity
        host = host.split(':', 1)[0].rstrip('.')
        return host if self.case_sensitive else host.lower()

    def normalizeRealm(self, realm):
        # Realms are upper-case by convention and always matched case-insensitively
        return realm.upper()

    def canonicalHost(self, host):
        normalized = self.normalizeHost(host)
        return self.host_aliases.get(normalized, normalized)

    def serviceAccepted(self, requested, cached):
        requested = self.normalizeService(requested)
        cached = self.normalizeService(cached)
        if requested == cached:
            return True
        return cached in self.service_aliases.get(requested, ())

    @staticmethod
    def parseStrictSPN(spn):
        """
        Splits a 'service/host@REALM' SPN. Strict mode only accepts exactly
        two name components; anything else raises CachePolicyError.
        """
        if spn.count('@') != 1:
            raise CachePolicyError('Strict cache policy: malformed SPN %r (expected service/host@REALM)' % spn)
        name, realm = spn.rsplit('@', 1)
        if name.count('/') != 1:
            raise CachePolicyError('Strict cache policy: malformed SPN %r (expected exactly service/host)' % spn)
        service, host = name.split('/', 1)
        if not service or not host or not realm:
            raise CachePolicyError('Strict cache policy: malformed SPN %r (empty component)' % spn)
        return service, host, realm


class Header(Structure):
    structure = (
        ('tag','!H=0'),
        ('taglen','!H=0'),
        ('_tagdata','_-tagdata','self["taglen"]'),
        ('tagdata',':'),
    )

class DeltaTime(Structure):
    structure = (
        ('time_offset','!L=0'),
        ('usec_offset','!L=0'),
    )

class CountedOctetString(Structure):
    structure = (
        ('length','!L=0'),
        ('_data','_-data','self["length"]'),
        ('data',':'),
    )

    def prettyPrint(self, indent=''):
        return "%s%s" % (indent, hexlify(self['data']))


class KeyBlockV3(Structure):
    structure = (
        ('keytype','!H=0'),
        ('etype','!H=0'),
        ('etype2', '!H=0'),  # Version 3 repeats the etype
        ('keylen','!H=0'),
        ('_keyvalue','_-keyvalue','self["keylen"]'),
        ('keyvalue',':'),
    )

    def prettyPrint(self):
        return "Key: (0x%x)%s" % (self['keytype'], hexlify(self['keyvalue']))


class KeyBlockV4(Structure):
    structure = (
        ('keytype','!H=0'),
        ('etype','!H=0'),
        ('keylen','!H=0'),
        ('_keyvalue','_-keyvalue','self["keylen"]'),
        ('keyvalue',':'),
    )

    def prettyPrint(self):
        return "Key: (0x%x)%s" % (self['keytype'], hexlify(self['keyvalue']))

class Times(Structure):
    structure = (
        ('authtime','!L=0'),
        ('starttime','!L=0'),
        ('endtime','!L=0'),
        ('renew_till','!L=0'),
    )
    def prettyPrint(self, indent = ''):
        print(("%sAuth : %s" % (indent, datetime.fromtimestamp(self['authtime']).isoformat())))
        print(("%sStart: %s" % (indent, datetime.fromtimestamp(self['starttime']).isoformat())))
        print(("%sEnd  : %s" % (indent, datetime.fromtimestamp(self['endtime']).isoformat())))
        print(("%sRenew: %s" % (indent, datetime.fromtimestamp(self['renew_till']).isoformat())))

class Address(Structure):
    structure = (
        ('addrtype','!H=0'),
        ('addrdata',':', CountedOctetString),
    )

class AuthData(Structure):
    structure = (
        ('authtype','!H=0'),
        ('authdata',':', CountedOctetString),
    )

class Principal:
    class PrincipalHeader(Structure):
        structure = (
            ('name_type','!L=0'),
            ('num_components','!L=0'),
        )

    def __init__(self, data=None):
        self.components = []
        self.realm = None
        if data is not None:
            self.header = self.PrincipalHeader(data)
            data = data[len(self.header):]
            self.realm = CountedOctetString(data)
            data = data[len(self.realm):]
            self.components = []
            for component in range(self.header['num_components']):
                comp = CountedOctetString(data)
                data = data[len(comp):]
                self.components.append(comp)
        else:
            self.header = self.PrincipalHeader()

    def __len__(self):
        totalLen = len(self.header) + len(self.realm)
        for i in self.components:
            totalLen += len(i)
        return totalLen

    def getData(self):
        data = self.header.getData() + self.realm.getData()
        for component in self.components:
            data += component.getData()
        return data

    def __str__(self):
        return self.getData()

    def prettyPrint(self):
        principal = b''
        for component in self.components:
            if isinstance(component['data'], bytes) is not True:
                component = b(component['data'])
            else:
                component = component['data']
            principal += component + b'/'

        principal = principal[:-1]
        if isinstance(self.realm['data'], bytes):
            realm = self.realm['data']
        else:
            realm = b(self.realm['data'])
        principal += b'@' + realm
        return principal

    def fromPrincipal(self, principal):
        self.header['name_type'] = principal.type
        self.header['num_components'] = len(principal.components)
        octetString = CountedOctetString()
        octetString['length'] = len(principal.realm)
        octetString['data'] = principal.realm
        self.realm = octetString
        self.components = []
        for c in principal.components:
            octetString = CountedOctetString()
            octetString['length'] = len(c)
            octetString['data'] = c
            self.components.append(octetString)

    def toPrincipal(self):
        return types.Principal(self.prettyPrint(), type=self.header['name_type'])

class Credential:
    class CredentialHeaderV3(Structure):
        structure = (
            ('client',':', Principal),
            ('server',':', Principal),
            ('key',':', KeyBlockV3),
            ('time',':', Times),
            ('is_skey','B=0'),
            ('tktflags','!L=0'),
            ('num_address','!L=0'),
        )

    class CredentialHeaderV4(Structure):
        structure = (
            ('client',':', Principal),
            ('server',':', Principal),
            ('key',':', KeyBlockV4),
            ('time',':', Times),
            ('is_skey','B=0'),
            ('tktflags','!L=0'),
            ('num_address','!L=0'),
        )

    def __init__(self, data=None, ccache_version=None):
        self.addresses = []
        self.authData = []
        self.header = None
        self.ticket = None
        self.secondTicket = None

        if data is not None:
            if ccache_version == 3:
                self.header = self.CredentialHeaderV3(data)
            else:
                self.header = self.CredentialHeaderV4(data)

            data = data[len(self.header):]
            for address in range(self.header['num_address']):
                ad = Address(data)
                data = data[len(ad):]
                self.addresses.append(ad)
            num_authdata = unpack('!L', data[:4])[0]
            data = data[calcsize('!L'):]
            for authdata in range(num_authdata):
                ad = AuthData(data)
                data = data[len(ad):]
                self.authData.append(ad)
            self.ticket = CountedOctetString(data)
            data = data[len(self.ticket):]
            self.secondTicket = CountedOctetString(data)
            data = data[len( self.secondTicket):]
        else:
            self.header = self.CredentialHeaderV4()

    def __getitem__(self, key):
        return self.header[key]

    def __setitem__(self, item, value):
        self.header[item] = value

    def getServerPrincipal(self):
        return self.header['server'].prettyPrint()

    def __len__(self):
        totalLen = len(self.header)
        for i in self.addresses:
            totalLen += len(i)
        totalLen += calcsize('!L')
        for i in self.authData:
            totalLen += len(i)
        totalLen += len(self.ticket)
        totalLen += len(self.secondTicket)
        return totalLen

    def dump(self):
        self.header.dump()

    def getData(self):
        data = self.header.getData()
        for i in self.addresses:
            data += i.getData()
        data += pack('!L', len(self.authData))
        for i in self.authData:
            data += i.getData()
        data += self.ticket.getData()
        data += self.secondTicket.getData()
        return data

    def __str__(self):
        return self.getData()

    def prettyPrint(self, indent=''):
        print(("%sClient: %s" % (indent, self.header['client'].prettyPrint())))
        print(("%sServer: %s" % (indent, self.header['server'].prettyPrint())))
        print(("%s%s" % (indent, self.header['key'].prettyPrint())))
        print(("%sTimes: " % indent))
        self.header['time'].prettyPrint('\t\t')
        print(("%sSubKey: %s" % (indent, self.header['is_skey'])))
        print(("%sFlags: 0x%x" % (indent, self.header['tktflags'])))
        print(("%sAddresses: %d" % (indent, self.header['num_address'])))
        for address in self.addresses:
            address.prettyPrint('\t\t')
        print(("%sAuth Data: %d" % (indent, len(self.authData))))
        for ad in self.authData:
            ad.prettyPrint('\t\t')
        print(("%sTicket: %s" % (indent, self.ticket.prettyPrint())))
        print(("%sSecond Ticket: %s" % (indent, self.secondTicket.prettyPrint())))

    def toTGT(self):
        tgt_rep = AS_REP()
        tgt_rep['pvno'] = 5
        tgt_rep['msg-type'] = int(constants.ApplicationTagNumbers.AS_REP.value)
        tgt_rep['crealm'] = self['server'].realm['data']

        # Fake EncryptedData
        tgt_rep['enc-part'] = noValue
        tgt_rep['enc-part']['etype'] = 1
        tgt_rep['enc-part']['cipher'] = ''
        seq_set(tgt_rep, 'cname', self['client'].toPrincipal().components_to_asn1)
        ticket = types.Ticket()
        ticket.from_asn1(self.ticket['data'])
        seq_set(tgt_rep,'ticket', ticket.to_asn1)

        cipher = crypto._enctype_table[self['key']['keytype']]()

        tgt = dict()
        tgt['KDC_REP'] = encoder.encode(tgt_rep)
        tgt['cipher'] = cipher
        tgt['sessionKey'] = crypto.Key(cipher.enctype, self['key']['keyvalue'])
        tgt['client'] = self['client']
        return tgt

    def toTGS(self, newSPN=None):
        tgs_rep = TGS_REP()
        tgs_rep['pvno'] = 5
        tgs_rep['msg-type'] = int(constants.ApplicationTagNumbers.TGS_REP.value)
        tgs_rep['crealm'] = self['server'].realm['data']

        # Fake EncryptedData
        tgs_rep['enc-part'] = noValue
        tgs_rep['enc-part']['etype'] = 1
        tgs_rep['enc-part']['cipher'] = ''
        seq_set(tgs_rep, 'cname', self['client'].toPrincipal().components_to_asn1)
        ticket = types.Ticket()
        ticket.from_asn1(self.ticket['data'])
        if newSPN is not None:
            if newSPN.upper() != str(ticket.service_principal).upper():
                LOG.debug('Changing sname from %s to %s and hoping for the best' % (ticket.service_principal, newSPN) )
                ticket.service_principal = types.Principal(newSPN, type=int(ticket.service_principal.type))
        seq_set(tgs_rep,'ticket', ticket.to_asn1)

        cipher = crypto._enctype_table[self['key']['keytype']]()

        tgs = dict()
        tgs['KDC_REP'] = encoder.encode(tgs_rep)
        tgs['cipher'] = cipher
        tgs['sessionKey'] = crypto.Key(cipher.enctype, self['key']['keyvalue'])
        return tgs


class CCache:
    # https://web.mit.edu/kerberos/krb5-devel/doc/formats/ccache_file_format.html

    class MiniHeader(Structure):
        structure = (
            ('file_format_version','!H=0x0504'),
            ('headerlen','!H=12'),
        )

    def __init__(self, data = None):
        self.headers = None
        self.principal = None
        self.credentials = []
        self.miniHeader = None

        if data is not None:
            if PY2:
                ccache_version = unpack('>B', data[1])[0]
            else:
                ccache_version = data[1]

            # Versions 1 and 2 are not implemented yet
            if ccache_version == 1 or ccache_version == 2:
                raise NotImplementedError('Not Implemented!')

            # Only Version 4 contains a header
            if ccache_version == 4:
                miniHeader = self.MiniHeader(data)
                data = data[len(miniHeader.getData()):]

                headerLen = miniHeader['headerlen']

                self.headers = []
                while headerLen > 0:
                    header = Header(data)
                    self.headers.append(header)
                    headerLen -= len(header)
                    data = data[len(header):]
            else:
                # Skip over the version bytes
                data = data[2:]

            # Now the primary_principal
            self.principal = Principal(data)

            data = data[len(self.principal):]

            # Now let's parse the credentials
            self.credentials = []
            while len(data) > 0:
                cred = Credential(data, ccache_version)
                if cred['server'].prettyPrint().find(b'krb5_ccache_conf_data') < 0:
                    self.credentials.append(cred)
                data = data[len(cred.getData()):]

    def getData(self):
        data = self.MiniHeader().getData()
        for header in self.headers:
            data += header.getData()
        data += self.principal.getData()
        for credential in self.credentials:
            data += credential.getData()
        return data

    def getCredential(self, server, anySPN=True):
        for c in self.credentials:
            if c['server'].prettyPrint().upper() == b(server.upper()) or c['server'].prettyPrint().upper().split(b'@')[0] == b(server.upper())\
                    or c['server'].prettyPrint().upper().split(b'@')[0] == b(server.upper().split('@')[0]):
                LOG.debug('Returning cached credential for %s' % c['server'].prettyPrint().upper().decode('utf-8'))
                return c
        LOG.debug('SPN %s not found in cache' % server.upper())
        if anySPN is True:
            LOG.debug('AnySPN is True, looking for another suitable SPN')
            for c in self.credentials:
                # Let's search for any TGT/TGS that matches the server w/o the SPN's service type/port, returns
                # the first one
                # If server has no '/' we assume it's a ST from S4U2Self without a service type
                if c['server'].prettyPrint().find(b'/') >= 0:
                    # Match both service/host@REALM and service/host/domain@REALM.
                    # Seen when a service ticket is dumped from LSASS memory (e.g. via
                    # Rubeus' `dump` command) rather than requested fresh - Windows caches
                    # such tickets with the domain suffix appended as an extra SPN
                    # component, e.g. LDAP/dc.domain.local/domain.local@REALM
                    cachedParts = c['server'].prettyPrint().upper().split(b'/')
                    cachedHost = cachedParts[1].split(b'@')[0].split(b':', 1)[0]
                    cachedRealm = cachedParts[-1].split(b'@')[-1]

                    serverParts = server.upper().split('/')
                    searchHost = b(serverParts[1].split('@')[0].split(':', 1)[0])
                    searchRealm = b(serverParts[-1].split('@')[-1])

                    hostsMatch = cachedHost == searchHost

                    # Allow short-name/FQDN matching only when at least one
                    # side is actually an unqualified hostname.
                    if not hostsMatch and (b'.' not in cachedHost or b'.' not in searchHost):
                        hostsMatch = cachedHost.split(b'.', 1)[0] == searchHost.split(b'.', 1)[0]

                    if hostsMatch and cachedRealm == searchRealm:
                        LOG.debug('Returning cached credential for %s' % c['server'].prettyPrint().upper().decode('utf-8'))
                        return c
                else:
                    # Should be of form 'hostname$@REALM'
                    cachedSPN = (c['server'].prettyPrint().upper().split(b'@')[0].split(b':')[0] + b'@' + c['server'].prettyPrint().upper().split(b'@')[1])
                    searchSPN = f"{server.upper().split('/')[1].split('@')[0].split(':')[0].split('.')[0]}$@{server.upper().split('/')[1].split('@')[1]}"
                    if cachedSPN == b(searchSPN):
                        LOG.debug('Returning cached credential for %s' % c['server'].prettyPrint().upper().decode('utf-8'))
                        return c

        return None

    @staticmethod
    def _strictCredentialSPN(credential):
        """
        Returns the (service, host, realm) of a cache entry, or None if the
        entry's server principal is not exactly a two-component
        'service/host@REALM' name (strict mode never guesses how to map
        extra components such as LSASS-style service/host/domain names).
        """
        server = credential['server']
        if len(server.components) != 2:
            return None
        service = server.components[0]['data']
        host = server.components[1]['data']
        realm = server.realm['data']
        if isinstance(service, bytes):
            service = service.decode('utf-8', 'replace')
        if isinstance(host, bytes):
            host = host.decode('utf-8', 'replace')
        if isinstance(realm, bytes):
            realm = realm.decode('utf-8', 'replace')
        return service, host, realm

    @staticmethod
    def _credentialTicketMatches(credential, policy):
        """
        Verifies that the server principal claimed by the cache entry index
        matches the principal inside the actual Kerberos ticket the entry
        carries. A cache entry can be relabelled (cache index spoofing) so
        that a loose lookup returns a ticket for a different service or
        host; strict mode rejects any entry that fails this check, as well
        as entries whose ticket cannot be decoded at all.
        """
        parsed = CCache._strictCredentialSPN(credential)
        if parsed is None:
            return False
        service, host, realm = parsed
        try:
            ticket = types.Ticket()
            ticket.from_asn1(credential.ticket['data'])
        except Exception:
            LOG.debug('Strict cache policy: cannot decode ticket of cache entry %s/%s@%s, rejecting it'
                      % (service, host, realm))
            return False
        serverPrincipal = ticket.service_principal
        if serverPrincipal is None or len(serverPrincipal.components) != 2:
            LOG.warning('Strict cache policy: ticket of cache entry %s/%s@%s has an unexpected sname, rejecting it'
                        % (service, host, realm))
            return False
        if policy.normalizeService(serverPrincipal.components[0]) != policy.normalizeService(service):
            return False
        if policy.normalizeHost(serverPrincipal.components[1]) != policy.normalizeHost(host):
            return False
        if policy.normalizeRealm(serverPrincipal.realm) != policy.normalizeRealm(realm):
            return False
        return True

    def getCredentialStrict(self, server, policy):
        """
        Strict-mode counterpart of getCredential(). Returns the cache entry
        for 'service/host@REALM' only if the service, host and realm match
        exactly (after the policy's configured normalization and explicit
        alias configuration) AND the entry's embedded ticket really is for
        that principal. There is deliberately no anySPN-style fallback: a
        ticket for one service on a host is never reused for another
        service unless the caller explicitly trusted that substitution via
        the policy's service_aliases.

        :param server: the requested SPN, 'service/host@REALM'
        :param policy: a KerberosCachePolicy with mode MODE_STRICT
        :return: the matching Credential, or None (the reason is logged)
        """
        service, host, realm = KerberosCachePolicy.parseStrictSPN(server)

        if policy.allowed_realms is not None and policy.normalizeRealm(realm) not in policy.allowed_realms:
            LOG.debug('Strict cache policy: realm %s is not in the allowed realms' % policy.normalizeRealm(realm))
            return None

        for c in self.credentials:
            parsed = self._strictCredentialSPN(c)
            if parsed is None:
                continue
            cachedService, cachedHost, cachedRealm = parsed
            if policy.normalizeRealm(cachedRealm) != policy.normalizeRealm(realm):
                continue
            if not policy.serviceAccepted(service, cachedService):
                continue
            if policy.canonicalHost(host) != policy.canonicalHost(cachedHost):
                continue
            if not self._credentialTicketMatches(c, policy):
                LOG.warning('Strict cache policy: cache entry %s/%s@%s does not match its embedded ticket, '
                            'ignoring it (possible cache index spoofing)' % (cachedService, cachedHost, cachedRealm))
                continue
            LOG.debug('Strict cache policy: returning verified credential for %s' % c['server'].prettyPrint()
                      .decode('utf-8', 'replace'))
            return c

        LOG.debug('Strict cache policy: no verified credential for %s in cache' % server)
        return None

    def getInterRealmTGT(self, domain, targetRealm=None):
        """
        Returns an inter-realm (referral) TGT issued by domain, that is a
        krbtgt/<otherRealm>@<domain> credential. Such a TGT is only usable against
        <otherRealm>'s KDC, which getKerberosTGS() takes care of.

        :param domain: the realm that issued the referral TGT
        :param targetRealm: preferred <otherRealm>, to choose when the cache holds several

        :return: the matching Credential, or None
        """
        domain = domain.upper()
        targetRealm = targetRealm.upper() if targetRealm else None

        tgts = {}
        for c in self.credentials:
            server = c['server'].prettyPrint().decode('utf-8', 'replace').upper()
            if server.count('/') != 1 or server.count('@') != 1 or not server.startswith('KRBTGT/'):
                continue
            serviceRealm, ticketRealm = server[len('KRBTGT/'):].split('@')
            if ticketRealm == domain and serviceRealm != domain:
                tgts.setdefault(serviceRealm, c)

        if not tgts:
            return None

        serviceRealm = targetRealm if targetRealm in tgts else sorted(tgts)[0]
        LOG.debug('Returning inter-realm TGT krbtgt/%s@%s' % (serviceRealm, domain))
        return tgts[serviceRealm]

    def toTimeStamp(self, dt, epoch=datetime(1970,1,1)):
        td = dt - epoch
        # return td.total_seconds()
        return int((td.microseconds + (td.seconds + td.days * 24 * 3600) * 10**6) // 1e6)

    def reverseFlags(self, flags):
        # If passed as a string representation (e.g., "'010100...'B"), clean it up
        if isinstance(flags, str):
            bit_str = flags.replace("'", "").replace("B", "")
        else:
            # Standard pyasn1 BitString handling: join the bits into a string
            bit_str = "".join(str(bit) for bit in flags)

        # Ensure it's exactly 32 bits by padding with zeros on the right
        bit_str = bit_str.ljust(32, '0')[:32]

        # Convert the base-2 binary string back to an integer
        return int(bit_str, 2)

    def fromTGT(self, tgt, oldSessionKey, sessionKey):
        self.headers = []
        header = Header()
        header['tag'] = 1
        header['taglen'] = 8
        header['tagdata'] = b'\xff\xff\xff\xff\x00\x00\x00\x00'
        self.headers.append(header)

        decodedTGT = decoder.decode(tgt, asn1Spec = AS_REP())[0]

        tmpPrincipal = types.Principal()
        tmpPrincipal.from_asn1(decodedTGT, 'crealm', 'cname')
        self.principal = Principal()
        self.principal.fromPrincipal(tmpPrincipal)

        # Now let's add the credential
        cipherText = decodedTGT['enc-part']['cipher']

        cipher = crypto._enctype_table[decodedTGT['enc-part']['etype']]

        # Key Usage 3
        # AS-REP encrypted part (includes TGS session key or
        # application session key), encrypted with the client key
        # (Section 5.4.2)
        plainText = cipher.decrypt(oldSessionKey, 3, cipherText)

        encASRepPart = decoder.decode(plainText, asn1Spec = EncASRepPart())[0]
        credential = Credential()
        server = types.Principal()
        server.from_asn1(encASRepPart, 'srealm', 'sname')
        tmpServer = Principal()
        tmpServer.fromPrincipal(server)

        credential['client'] = self.principal
        credential['server'] = tmpServer
        credential['is_skey'] = 0

        credential['key'] = KeyBlockV4()
        credential['key']['keytype'] = int(encASRepPart['key']['keytype'])
        credential['key']['keyvalue'] = encASRepPart['key']['keyvalue'].asOctets()
        credential['key']['keylen'] = len(credential['key']['keyvalue'])

        credential['time'] = Times()
        credential['time']['authtime'] = self.toTimeStamp(types.KerberosTime.from_asn1(encASRepPart['authtime']))
        credential['time']['starttime'] = self.toTimeStamp(types.KerberosTime.from_asn1(encASRepPart['starttime']))
        credential['time']['endtime'] = self.toTimeStamp(types.KerberosTime.from_asn1(encASRepPart['endtime']))
        # After KB4586793 for CVE-2020-17049 this timestamp may be omitted
        if encASRepPart['renew-till'].hasValue():
            credential['time']['renew_till'] = self.toTimeStamp(types.KerberosTime.from_asn1(encASRepPart['renew-till']))
        flags = self.reverseFlags(encASRepPart['flags'])
        credential['tktflags'] = flags

        credential['num_address'] = 0
        credential.ticket = CountedOctetString()
        credential.ticket['data'] = encoder.encode(decodedTGT['ticket'].clone(tagSet=Ticket.tagSet, cloneValueFlag=True))
        credential.ticket['length'] = len(credential.ticket['data'])
        credential.secondTicket = CountedOctetString()
        credential.secondTicket['data'] = b''
        credential.secondTicket['length'] = 0
        self.credentials.append(credential)

    def fromTGS(self, tgs, oldSessionKey, sessionKey):
        self.headers = []
        header = Header()
        header['tag'] = 1
        header['taglen'] = 8
        header['tagdata'] = b'\xff\xff\xff\xff\x00\x00\x00\x00'
        self.headers.append(header)

        decodedTGS = decoder.decode(tgs, asn1Spec = TGS_REP())[0]

        tmpPrincipal = types.Principal()
        tmpPrincipal.from_asn1(decodedTGS, 'crealm', 'cname')
        self.principal = Principal()
        self.principal.fromPrincipal(tmpPrincipal)

        # Now let's add the credential
        cipherText = decodedTGS['enc-part']['cipher']

        cipher = crypto._enctype_table[decodedTGS['enc-part']['etype']]

        # Key Usage 8
        # TGS-REP encrypted part (includes application session
        # key), encrypted with the TGS session key (Section 5.4.2)
        plainText = cipher.decrypt(oldSessionKey, 8, cipherText)

        encTGSRepPart = decoder.decode(plainText, asn1Spec = EncTGSRepPart())[0]

        credential = Credential()
        server = types.Principal()
        server.from_asn1(encTGSRepPart, 'srealm', 'sname')
        tmpServer = Principal()
        tmpServer.fromPrincipal(server)

        credential['client'] = self.principal
        credential['server'] = tmpServer
        credential['is_skey'] = 0

        credential['key'] = KeyBlockV4()
        credential['key']['keytype'] = int(encTGSRepPart['key']['keytype'])
        credential['key']['keyvalue'] = encTGSRepPart['key']['keyvalue'].asOctets()
        credential['key']['keylen'] = len(credential['key']['keyvalue'])

        credential['time'] = Times()
        credential['time']['authtime'] = self.toTimeStamp(types.KerberosTime.from_asn1(encTGSRepPart['authtime']))
        credential['time']['starttime'] = self.toTimeStamp(types.KerberosTime.from_asn1(encTGSRepPart['starttime']))
        credential['time']['endtime'] = self.toTimeStamp(types.KerberosTime.from_asn1(encTGSRepPart['endtime']))
        # After KB4586793 for CVE-2020-17049 this timestamp may be omitted
        if encTGSRepPart['renew-till'].hasValue():
            credential['time']['renew_till'] = self.toTimeStamp(types.KerberosTime.from_asn1(encTGSRepPart['renew-till']))

        flags = self.reverseFlags(encTGSRepPart['flags'])
        credential['tktflags'] = flags

        credential['num_address'] = 0

        credential.ticket = CountedOctetString()
        credential.ticket['data'] = encoder.encode(decodedTGS['ticket'].clone(tagSet=Ticket.tagSet, cloneValueFlag=True))
        credential.ticket['length'] = len(credential.ticket['data'])
        credential.secondTicket = CountedOctetString()
        credential.secondTicket['data'] = b''
        credential.secondTicket['length'] = 0
        self.credentials.append(credential)

    @classmethod
    def loadFile(cls, fileName):
        if fileName is None:
            LOG.critical('CCache file is not found. Skipping...')
            LOG.debug('The specified path is not correct or the KRB5CCNAME environment variable is not defined')
            return None

        try:
            f = open(fileName, 'rb')
            data = f.read()
            f.close()
            return cls(data)
        except FileNotFoundError as e:
            raise e

    def saveFile(self, fileName):
        f = open(fileName, 'wb+')
        f.write(self.getData())
        f.close()

    @classmethod
    def parseFile(cls, domain='', username='', target='', cachePolicy=None):
        """
        parses the CCache file specified in the KRB5CCNAME environment variable

        :param domain: an optional domain name of a user
        :param username: an optional username of a user
        :param target: an optional SPN of a target system
        :param cachePolicy: an optional KerberosCachePolicy. When it is a
                            strict-mode policy, cache selection verifies the
                            requested service/host/realm and the ticket
                            inside each cache entry, and raises
                            CachePolicyError when nothing verifies. When
                            None (or KerberosCachePolicy.legacy()), the
                            historical loose matching is used.

        :return: domain, username, TGT, TGS
        """

        ccache = cls.loadFile(os.getenv('KRB5CCNAME'))
        if ccache is None:
            if cachePolicy is not None and cachePolicy.mode == KerberosCachePolicy.MODE_STRICT:
                raise CachePolicyError('Strict Kerberos cache policy: no credential cache available '
                                       '(KRB5CCNAME is not set or not readable)')
            return domain, username, None, None

        LOG.debug('Using Kerberos Cache: %s' % os.getenv('KRB5CCNAME'))

        if cachePolicy is not None and cachePolicy.mode == KerberosCachePolicy.MODE_STRICT:
            return cls._parseFileStrict(ccache, domain, username, target, cachePolicy)

        if domain == '':
            domain = ccache.principal.realm['data'].decode('utf-8')
            LOG.debug('Domain retrieved from CCache: %s' % domain)

        creds = None
        if target != '':
            principal = '%s@%s' % (target.upper(), domain.upper())
            creds = ccache.getCredential(principal)

        TGT = None
        TGS = None
        if creds is None:
            principal = 'krbtgt/%s@%s' % (domain.upper(), domain.upper())
            creds = ccache.getCredential(principal)
            if creds is None:
                targetHost = target.split('/')[-1].split('@')[0].split(':', 1)[0]
                # the target's DNS suffix is only a hint, used to choose between several referral TGTs
                targetRealm = targetHost.split('.', 1)[1] if '.' in targetHost else None
                creds = ccache.getInterRealmTGT(domain, targetRealm)
            if creds is not None:
                LOG.debug('Using TGT from cache')
                TGT = creds.toTGT()
            else:
                LOG.debug('No valid credentials found in cache')
        else:
            LOG.debug('Using TGS from cache')
            TGS = creds.toTGS(principal)

        if username == '' and creds is not None:
            username = creds['client'].prettyPrint().split(b'@')[0].decode('utf-8')
            LOG.debug('Username retrieved from CCache: %s' % username)
        elif username == '' and len(ccache.principal.components) > 0:
            username = ccache.principal.components[0]['data'].decode('utf-8')
            LOG.debug('Username retrieved from CCache: %s' % username)

        return domain, username, TGT, TGS

    @classmethod
    def _parseFileStrict(cls, ccache, domain, username, target, policy):
        """
        Strict-mode cache selection used by parseFile(). Either returns a
        verified (domain, username, TGT, TGS) tuple or raises
        CachePolicyError before any authentication message is built. Unlike
        the legacy path it never falls back silently: no anySPN reuse, no
        unverified ticket, no password-based retry is implied by a miss.
        """
        if domain == '':
            domain = ccache.principal.realm['data']
            if isinstance(domain, bytes):
                domain = domain.decode('utf-8')
            LOG.debug('Domain retrieved from CCache: %s' % domain)

        creds = None
        principal = None
        if target != '':
            principal = '%s@%s' % (target.upper(), domain.upper())
            creds = ccache.getCredentialStrict(principal, policy)

        TGT = None
        TGS = None
        if creds is not None:
            LOG.debug('Using strictly verified TGS from cache')
            TGS = creds.toTGS(principal)
        else:
            # A TGT is realm-bound, not service-bound, so falling back to a
            # verified one is still strict: the KDC decides the rest.
            tgtPrincipal = 'krbtgt/%s@%s' % (domain.upper(), domain.upper())
            creds = ccache.getCredentialStrict(tgtPrincipal, policy)
            if creds is None:
                targetHost = target.split('/')[-1].split('@')[0].split(':', 1)[0]
                # the target's DNS suffix is only a hint, used to choose between several referral TGTs
                targetRealm = targetHost.split('.', 1)[1] if '.' in targetHost else None
                referral = ccache.getInterRealmTGT(domain, targetRealm)
                if referral is not None and ccache._credentialTicketMatches(referral, policy):
                    creds = referral
            if creds is not None:
                LOG.debug('Using strictly verified TGT from cache')
                TGT = creds.toTGT()
            else:
                requested = principal if principal is not None else 'krbtgt/%s@%s' % (domain.upper(), domain.upper())
                raise CachePolicyError('Strict Kerberos cache policy: no verified credential in cache for %s. '
                                       'Not building an authentication message; request a ticket for this exact '
                                       'SPN, or pass a KerberosCachePolicy with explicit host_aliases/'
                                       'service_aliases if the substitution is trusted.' % requested)

        if username == '':
            username = creds['client'].prettyPrint().split(b'@')[0].decode('utf-8')
            LOG.debug('Username retrieved from CCache: %s' % username)

        return domain, username, TGT, TGS

    def prettyPrint(self):
        print(("Primary Principal: %s" % self.principal.prettyPrint()))
        print("Credentials: ")
        for i, credential in enumerate(self.credentials):
            print(("[%d]" % i))
            credential.prettyPrint('\t')

    @classmethod
    def loadKirbiFile(cls, fileName):
        f = open(fileName, 'rb')
        data = f.read()
        f.close()
        ccache = cls()
        ccache.fromKRBCRED(data)
        return ccache

    def saveKirbiFile(self, fileName):
        f = open(fileName, 'wb+')
        f.write(self.toKRBCRED())
        f.close()

    def fromKRBCRED(self, encodedKrbCred):
        krbCred = decoder.decode(encodedKrbCred, asn1Spec=KRB_CRED())[0]
        encKrbCredPart = decoder.decode(
            krbCred["enc-part"]["cipher"], asn1Spec=EncKrbCredPart()
        )[0]

        self.setDefaultHeader()

        # Loop through all ticket-info entries
        for i, krbCredInfo in enumerate(encKrbCredPart["ticket-info"]):
            tmpPrincipal = types.Principal()
            tmpPrincipal.from_asn1(krbCredInfo, "prealm", "pname")
            principal = Principal()
            principal.fromPrincipal(tmpPrincipal)
            # Set the ccache principal from the first entry
            if i == 0:
                self.principal = principal

            credential = Credential()
            server = types.Principal()
            server.from_asn1(krbCredInfo, "srealm", "sname")
            tmpServer = Principal()
            tmpServer.fromPrincipal(server)

            credential["client"] = principal
            credential["server"] = tmpServer
            credential["is_skey"] = 0

            credential["key"] = KeyBlockV4()
            credential["key"]["keytype"] = int(krbCredInfo["key"]["keytype"])
            credential["key"]["keyvalue"] = krbCredInfo["key"]["keyvalue"].asOctets()
            credential["key"]["keylen"] = len(credential["key"]["keyvalue"])

            credential["time"] = Times()

            credential["time"]["authtime"] = self.toTimeStamp(
                types.KerberosTime.from_asn1(krbCredInfo["starttime"])
            )
            credential["time"]["starttime"] = self.toTimeStamp(
                types.KerberosTime.from_asn1(krbCredInfo["starttime"])
            )
            credential["time"]["endtime"] = self.toTimeStamp(
                types.KerberosTime.from_asn1(krbCredInfo["endtime"])
            )
            # After KB4586793 for CVE-2020-17049 this timestamp may be omitted
            if krbCredInfo["renew-till"].hasValue():
                credential["time"]["renew_till"] = self.toTimeStamp(
                    types.KerberosTime.from_asn1(krbCredInfo["renew-till"])
                )

            flags = self.reverseFlags(krbCredInfo["flags"])
            credential["tktflags"] = flags

            credential["num_address"] = 0
            credential.ticket = CountedOctetString()
            credential.ticket["data"] = encoder.encode(
                krbCred["tickets"][i].clone(tagSet=Ticket.tagSet, cloneValueFlag=True)
            )
            credential.ticket["length"] = len(credential.ticket["data"])
            credential.secondTicket = CountedOctetString()
            credential.secondTicket["data"] = b""
            credential.secondTicket["length"] = 0

            self.credentials.append(credential)

    def toKRBCRED(self):
        principal = self.principal

        krbCredInfos = []
        tickets = []

        for credential in self.credentials:
            krbCredInfo = KrbCredInfo()

            krbCredInfo["key"] = noValue
            krbCredInfo["key"]["keytype"] = credential["key"]["keytype"]
            krbCredInfo["key"]["keyvalue"] = credential["key"]["keyvalue"]

            krbCredInfo["prealm"] = credential['client'].realm.fields["data"]

            krbCredInfo["pname"] = noValue
            krbCredInfo["pname"]["name-type"] = credential['client'].header["name_type"]
            seq_set_iter(
                krbCredInfo["pname"],
                "name-string",
                tuple(c.fields["data"] for c in credential['client'].components),
            )

            # Force the 32 bit representation to avoid any precision loss due to ASN1 conversion
            krbCredInfo["flags"] = f"{int(credential['tktflags']):032b}"

            krbCredInfo["starttime"] = KerberosTime.to_asn1(
                datetime.fromtimestamp(credential["time"]["starttime"], tz=timezone.utc)
            )
            krbCredInfo["endtime"] = KerberosTime.to_asn1(
                datetime.fromtimestamp(credential["time"]["endtime"], tz=timezone.utc)
            )
            if credential["time"]["renew_till"] != 0:
                krbCredInfo["renew-till"] = KerberosTime.to_asn1(
                    datetime.fromtimestamp(
                        credential["time"]["renew_till"], tz=timezone.utc
                    )
                )

            krbCredInfo["srealm"] = credential["server"].realm.fields["data"]

            krbCredInfo["sname"] = noValue
            krbCredInfo["sname"]["name-type"] = credential["server"].header["name_type"]
            seq_set_iter(
                krbCredInfo["sname"],
                "name-string",
                tuple(c.fields["data"] for c in credential["server"].components),
            )

            krbCredInfos.append(krbCredInfo)

            ticket = decoder.decode(credential.ticket["data"], asn1Spec=Ticket())[0]
            tickets.append(ticket)

        encKrbCredPart = EncKrbCredPart()
        seq_set_iter(encKrbCredPart, "ticket-info", krbCredInfos)

        krbCred = KRB_CRED()
        krbCred["pvno"] = 5
        krbCred["msg-type"] = 22

        krbCred["enc-part"] = noValue
        krbCred["enc-part"]["etype"] = 0
        krbCred["enc-part"]["cipher"] = encoder.encode(encKrbCredPart)

        seq_set_iter(krbCred, "tickets", tickets)

        encodedKrbCred = encoder.encode(krbCred)

        return encodedKrbCred

    def setDefaultHeader(self):
        self.headers = []
        header = Header()
        header['tag'] = 1
        header['taglen'] = 8
        header['tagdata'] = b'\xff\xff\xff\xff\x00\x00\x00\x00'
        self.headers.append(header)


if __name__ == '__main__':
    ccache = CCache.loadFile(os.getenv('KRB5CCNAME'))
    ccache.prettyPrint()
