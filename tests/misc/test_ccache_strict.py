#!/usr/bin/env python
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
#   Strict Kerberos ccache selection tests.
#
#   Exercises the strict cache policy from the three call entry points
#   (SMB, LDAP and RPC) with wrong service, wrong realm, cache index
#   spoofing and legitimate matches. Transports are replaced by recording
#   stand-ins so the tests can assert whether an authentication message
#   was actually sent.
#
import os
import time
import unittest

import pytest
from six import PY2

if PY2:
    mock = None
else:
    from unittest import mock

from pyasn1.codec.der import encoder

from impacket.krb5 import asn1, constants, types
from impacket.krb5.ccache import (CachePolicyError, CCache, CountedOctetString, Credential, KerberosCachePolicy,
                                  KeyBlockV4, Principal, Times)

REALM = "EXAMPLE.TEST"
CLIENT = "user01@{}".format(REALM)
SRV_FQDN = "srv01.example.test"
SRV_SHORT = "srv01"
DC_FQDN = "dc01.example.test"


def _der_ticket(spn):
    ticket = types.Ticket()
    ticket.service_principal = types.Principal(spn, type=constants.PrincipalNameType.NT_SRV_INST.value)
    enc_part = types.EncryptedData()
    enc_part.etype = constants.EncryptionTypes.rc4_hmac.value
    enc_part.kvno = False
    enc_part.ciphertext = b"\x00" * 16
    ticket.encrypted_part = enc_part
    asn1_ticket = asn1.Ticket()
    ticket.to_asn1(asn1_ticket)
    return encoder.encode(asn1_ticket)


def _make_credential(server_spn, ticket_spn=None, client_spn=CLIENT):
    """Builds a cache credential whose embedded ticket is a real DER Ticket.

    ticket_spn controls what the ticket inside actually says; when it
    differs from server_spn the cache entry index is lying (cache index
    spoofing).
    """
    cred = Credential()

    client = Principal()
    client.fromPrincipal(types.Principal(client_spn, type=constants.PrincipalNameType.NT_PRINCIPAL.value))
    cred["client"] = client

    server = Principal()
    server.fromPrincipal(types.Principal(server_spn, type=constants.PrincipalNameType.NT_SRV_INST.value))
    cred["server"] = server

    key = KeyBlockV4()
    key["keytype"] = constants.EncryptionTypes.rc4_hmac.value
    key["keyvalue"] = b"\x01" * 16
    key["keylen"] = len(key["keyvalue"])
    cred["key"] = key

    now = int(time.time())
    times = Times()
    times["authtime"] = now
    times["starttime"] = now
    times["endtime"] = now + 3600
    times["renew_till"] = now + 3600
    cred["time"] = times

    cred["is_skey"] = 0
    cred["tktflags"] = 0
    cred["num_address"] = 0

    ticket = CountedOctetString()
    ticket["data"] = _der_ticket(ticket_spn or server_spn)
    ticket["length"] = len(ticket["data"])
    cred.ticket = ticket

    second = CountedOctetString()
    second["data"] = b""
    second["length"] = 0
    cred.secondTicket = second

    return cred


def _make_ccache(*credentials):
    ccache = CCache()
    ccache.principal = Principal()
    ccache.principal.fromPrincipal(types.Principal(CLIENT, type=constants.PrincipalNameType.NT_PRINCIPAL.value))
    ccache.credentials = list(credentials)
    return ccache


def _tgt_credential(realm=REALM, ticket_realm=None):
    """A same-realm TGT cache entry; ticket_realm fakes the ticket's realm."""
    server_spn = "krbtgt/{}@{}".format(realm, realm)
    ticket_spn = "krbtgt/{}@{}".format(ticket_realm or realm, ticket_realm or realm)
    return _make_credential(server_spn, ticket_spn)


class StrictSelectionTests(unittest.TestCase):
    """Unit-level strict matching behaviour."""

    def setUp(self):
        self.policy = KerberosCachePolicy.strict()

    def test_legit_match(self):
        cred = _make_credential("cifs/{}@{}".format(SRV_FQDN, REALM))
        ccache = _make_ccache(cred)
        self.assertIs(ccache.getCredentialStrict("CIFS/{}@{}".format(SRV_FQDN.upper(), REALM), self.policy), cred)

    def test_wrong_service_rejected(self):
        ccache = _make_ccache(_make_credential("ldap/{}@{}".format(SRV_FQDN, REALM)))
        self.assertIsNone(ccache.getCredentialStrict("CIFS/{}@{}".format(SRV_FQDN, REALM), self.policy))

    def test_wrong_realm_rejected(self):
        ccache = _make_ccache(_make_credential("cifs/{}@OTHER.TEST".format(SRV_FQDN)))
        self.assertIsNone(ccache.getCredentialStrict("CIFS/{}@{}".format(SRV_FQDN, REALM), self.policy))

    def test_wrong_host_rejected(self):
        ccache = _make_ccache(_make_credential("cifs/other.example.test@{}".format(REALM)))
        self.assertIsNone(ccache.getCredentialStrict("CIFS/{}@{}".format(SRV_FQDN, REALM), self.policy))

    def test_short_name_not_matched_by_default(self):
        ccache = _make_ccache(_make_credential("cifs/{}@{}".format(SRV_FQDN, REALM)))
        self.assertIsNone(ccache.getCredentialStrict("CIFS/{}@{}".format(SRV_SHORT.upper(), REALM), self.policy))

    def test_host_alias_is_a_trusted_entry_point(self):
        policy = KerberosCachePolicy.strict(host_aliases={SRV_SHORT: SRV_FQDN})
        cred = _make_credential("cifs/{}@{}".format(SRV_FQDN, REALM))
        ccache = _make_ccache(cred)
        self.assertIs(ccache.getCredentialStrict("CIFS/{}@{}".format(SRV_SHORT.upper(), REALM), policy), cred)

    def test_service_alias_is_a_trusted_entry_point(self):
        cred = _make_credential("host/{}@{}".format(SRV_FQDN, REALM))
        ccache = _make_ccache(cred)
        # No implicit cifs -> host substitution in strict mode
        self.assertIsNone(ccache.getCredentialStrict("CIFS/{}@{}".format(SRV_FQDN, REALM), self.policy))
        policy = KerberosCachePolicy.strict(service_aliases={"cifs": ["host"]})
        self.assertIs(ccache.getCredentialStrict("CIFS/{}@{}".format(SRV_FQDN, REALM), policy), cred)

    def test_allowed_realms_entry_point(self):
        cred = _make_credential("cifs/{}@TRUSTED.TEST".format(SRV_FQDN))
        ccache = _make_ccache(cred)
        policy = KerberosCachePolicy.strict(allowed_realms=["TRUSTED.TEST"])
        self.assertIs(ccache.getCredentialStrict("CIFS/{}@TRUSTED.TEST".format(SRV_FQDN), policy), cred)
        self.assertIsNone(ccache.getCredentialStrict("CIFS/{}@{}".format(SRV_FQDN, REALM), policy))

    def test_case_sensitivity_entry_point(self):
        cred = _make_credential("CIFS/SRV01@{}".format(REALM))
        ccache = _make_ccache(cred)
        # Default: case-insensitive service/host matching
        self.assertIs(ccache.getCredentialStrict("cifs/srv01@{}".format(REALM), self.policy), cred)
        # Opt-in case sensitivity rejects different-case service names
        policy = KerberosCachePolicy.strict(case_sensitive=True)
        self.assertIsNone(ccache.getCredentialStrict("cifs/srv01@{}".format(REALM), policy))

    def test_cache_index_spoofing_rejected(self):
        # The cache index claims cifs/srv01 but the ticket is really for ldap/srv01
        spoofed = _make_credential("cifs/{}@{}".format(SRV_FQDN, REALM),
                                   ticket_spn="ldap/{}@{}".format(SRV_FQDN, REALM))
        ccache = _make_ccache(spoofed)
        self.assertIsNone(ccache.getCredentialStrict("CIFS/{}@{}".format(SRV_FQDN, REALM), self.policy))
        # The legacy lookup trusts the index and would have returned it
        self.assertIs(ccache.getCredential("CIFS/{}@{}".format(SRV_FQDN, REALM), anySPN=False), spoofed)

    def test_undecodable_ticket_rejected(self):
        cred = _make_credential("cifs/{}@{}".format(SRV_FQDN, REALM))
        cred.ticket["data"] = b"\xde\xad\xbe\xef"
        ccache = _make_ccache(cred)
        self.assertIsNone(ccache.getCredentialStrict("CIFS/{}@{}".format(SRV_FQDN, REALM), self.policy))

    def test_malformed_spn_raises(self):
        ccache = _make_ccache()
        for bad in ("cifs/srv01", "cifs/srv01/extra@{}".format(REALM), "@{}".format(REALM), "cifs/@"):
            with self.assertRaises(CachePolicyError):
                ccache.getCredentialStrict(bad, self.policy)


@pytest.mark.skipif(PY2, reason="requires python 3.3 or higher")
class StrictParseFileTests(unittest.TestCase):

    def setUp(self):
        self.policy = KerberosCachePolicy.strict()

    def _parse(self, ccache, domain=REALM, username="user01", target="", policy=None):
        with mock.patch.dict(os.environ, {"KRB5CCNAME": "test-cache"}), \
                mock.patch.object(CCache, "loadFile", return_value=ccache):
            return CCache.parseFile(domain, username, target,
                                    cachePolicy=self.policy if policy is None else policy)

    def test_tgs_returned_on_exact_match(self):
        ccache = _make_ccache(_make_credential("cifs/{}@{}".format(SRV_FQDN, REALM)))
        domain, username, TGT, TGS = self._parse(ccache, target="cifs/{}".format(SRV_FQDN))
        self.assertEqual(domain, REALM)
        self.assertEqual(username, "user01")
        self.assertIsNone(TGT)
        self.assertIsNotNone(TGS)

    def test_verified_tgt_fallback(self):
        ccache = _make_ccache(_tgt_credential())
        _, _, TGT, TGS = self._parse(ccache, target="cifs/{}".format(SRV_FQDN))
        self.assertIsNotNone(TGT)
        self.assertIsNone(TGS)

    def test_spoofed_tgt_rejected(self):
        # Index says krbtgt/EXAMPLE.TEST@EXAMPLE.TEST, ticket is for another realm
        ccache = _make_ccache(_tgt_credential(ticket_realm="OTHER.TEST"))
        with self.assertRaises(CachePolicyError):
            self._parse(ccache, target="cifs/{}".format(SRV_FQDN))

    def test_no_match_raises_before_auth_message(self):
        ccache = _make_ccache(_make_credential("ldap/{}@{}".format(SRV_FQDN, REALM)))
        with self.assertRaises(CachePolicyError):
            self._parse(ccache, target="cifs/{}".format(SRV_FQDN))

    def test_missing_cache_file_raises(self):
        with mock.patch.dict(os.environ, {}, clear=True), \
                mock.patch.object(CCache, "loadFile", return_value=None):
            with self.assertRaises(CachePolicyError):
                CCache.parseFile(REALM, "user01", "cifs/{}".format(SRV_FQDN), cachePolicy=self.policy)

    def test_inter_realm_tgt_verified(self):
        referral = _make_credential("krbtgt/FOREST.TEST@{}".format(REALM))
        ccache = _make_ccache(referral)
        _, _, TGT, TGS = self._parse(ccache, target="cifs/file01.forest.test")
        self.assertIsNotNone(TGT)
        self.assertIsNone(TGS)

    def test_legacy_policy_keeps_loose_matching(self):
        # Cross-service reuse still works when the old mode is requested explicitly
        ccache = _make_ccache(_make_credential("host/{}@{}".format(SRV_FQDN, REALM)))
        _, _, TGT, TGS = self._parse(ccache, target="cifs/{}".format(SRV_FQDN),
                                     policy=KerberosCachePolicy.legacy())
        self.assertIsNone(TGT)
        self.assertIsNotNone(TGS)


@pytest.mark.skipif(PY2, reason="requires python 3.3 or higher")
class SMBEntryPointTests(unittest.TestCase):
    """Strict policy through SMBConnection.kerberosLogin."""

    def _connection(self):
        from impacket.smbconnection import SMBConnection
        conn = SMBConnection.__new__(SMBConnection)
        conn._SMBConnection = mock.Mock()
        conn._SMBConnection.get_remote_name.return_value = SRV_SHORT
        conn._SMBConnection.getDialect.return_value = 0x0311
        return conn

    def _login(self, conn, ccache, policy):
        with mock.patch.dict(os.environ, {"KRB5CCNAME": "test-cache"}), \
                mock.patch.object(CCache, "loadFile", return_value=ccache):
            conn.kerberosLogin("user01", "", REALM, cachePolicy=policy)
        return conn

    def test_wrong_service_not_sent(self):
        ccache = _make_ccache(_make_credential("ldap/{}@{}".format(SRV_SHORT, REALM)))
        conn = self._connection()
        with self.assertRaises(CachePolicyError):
            self._login(conn, ccache, KerberosCachePolicy.strict())
        conn._SMBConnection.kerberosLogin.assert_not_called()

    def test_wrong_realm_not_sent(self):
        ccache = _make_ccache(_make_credential("cifs/{}@OTHER.TEST".format(SRV_SHORT)))
        conn = self._connection()
        with self.assertRaises(CachePolicyError):
            self._login(conn, ccache, KerberosCachePolicy.strict())
        conn._SMBConnection.kerberosLogin.assert_not_called()

    def test_cache_index_spoofing_not_sent(self):
        ccache = _make_ccache(_make_credential("cifs/{}@{}".format(SRV_SHORT, REALM),
                                               ticket_spn="ldap/{}@{}".format(SRV_SHORT, REALM)))
        conn = self._connection()
        with self.assertRaises(CachePolicyError):
            self._login(conn, ccache, KerberosCachePolicy.strict())
        conn._SMBConnection.kerberosLogin.assert_not_called()

    def test_legit_match_sent(self):
        ccache = _make_ccache(_make_credential("cifs/{}@{}".format(SRV_SHORT, REALM)))
        conn = self._login(self._connection(), ccache, KerberosCachePolicy.strict())
        conn._SMBConnection.kerberosLogin.assert_called_once()
        # The TGS from the verified cache entry is what gets sent
        self.assertIsNotNone(conn._SMBConnection.kerberosLogin.call_args[0][8])


@pytest.mark.skipif(PY2, reason="requires python 3.3 or higher")
class LDAPEntryPointTests(unittest.TestCase):
    """Strict policy through LDAPConnection.kerberosLogin."""

    def _connection(self):
        from impacket.ldap.ldap import LDAPConnection
        from impacket.ldap.ldapasn1 import BindResponse, LDAPMessage, ResultCode
        conn = LDAPConnection.__new__(LDAPConnection)
        conn._dstHost = DC_FQDN
        conn._SSL = False
        conn._LDAPConnection__signing = False
        bind_response = BindResponse()
        bind_response["resultCode"] = ResultCode("success")
        bind_response["matchedDN"] = ""
        bind_response["diagnosticMessage"] = ""
        message = LDAPMessage()
        message["protocolOp"].setComponentByName("bindResponse", bind_response)
        conn.sendReceive = mock.Mock(return_value=[message])
        return conn

    def _login(self, conn, ccache, policy):
        with mock.patch.dict(os.environ, {"KRB5CCNAME": "test-cache"}), \
                mock.patch.object(CCache, "loadFile", return_value=ccache):
            return conn.kerberosLogin("user01", "", REALM, cachePolicy=policy)

    def test_wrong_service_not_sent(self):
        ccache = _make_ccache(_make_credential("cifs/{}@{}".format(DC_FQDN, REALM)))
        conn = self._connection()
        with self.assertRaises(CachePolicyError):
            self._login(conn, ccache, KerberosCachePolicy.strict())
        conn.sendReceive.assert_not_called()

    def test_wrong_realm_not_sent(self):
        ccache = _make_ccache(_make_credential("ldap/{}@OTHER.TEST".format(DC_FQDN)))
        conn = self._connection()
        with self.assertRaises(CachePolicyError):
            self._login(conn, ccache, KerberosCachePolicy.strict())
        conn.sendReceive.assert_not_called()

    def test_cache_index_spoofing_not_sent(self):
        ccache = _make_ccache(_make_credential("ldap/{}@{}".format(DC_FQDN, REALM),
                                               ticket_spn="cifs/{}@{}".format(DC_FQDN, REALM)))
        conn = self._connection()
        with self.assertRaises(CachePolicyError):
            self._login(conn, ccache, KerberosCachePolicy.strict())
        conn.sendReceive.assert_not_called()

    def test_legit_match_sent(self):
        ccache = _make_ccache(_make_credential("ldap/{}@{}".format(DC_FQDN, REALM)))
        conn = self._connection()
        self.assertTrue(self._login(conn, ccache, KerberosCachePolicy.strict()))
        conn.sendReceive.assert_called_once()


@pytest.mark.skipif(PY2, reason="requires python 3.3 or higher")
class RPCEntryPointTests(unittest.TestCase):
    """Strict policy through DCERPC_v5.bind with RPC_C_AUTHN_GSS_NEGOTIATE."""

    IFACE_UUID = ("12345678-1234-abcd-ef00-0123456789ab", "1.0")

    def _bind(self, transport, ccache, policy):
        from impacket.dcerpc.v5.rpcrt import DCERPC_v5, RPC_C_AUTHN_GSS_NEGOTIATE, RPC_C_AUTHN_LEVEL_CONNECT
        from impacket.uuid import uuidtup_to_bin

        transport.get_credentials.return_value = ("user01", "", REALM, "", "", "", None, None)
        transport.getRemoteName.return_value = SRV_SHORT
        transport.get_kdcHost.return_value = None
        transport.recv.return_value = 0

        dce = DCERPC_v5(transport)
        dce.set_auth_type(RPC_C_AUTHN_GSS_NEGOTIATE)
        dce.set_auth_level(RPC_C_AUTHN_LEVEL_CONNECT)
        dce.set_cache_policy(policy)

        with mock.patch.dict(os.environ, {"KRB5CCNAME": "test-cache"}), \
                mock.patch.object(CCache, "loadFile", return_value=ccache):
            dce.bind(uuidtup_to_bin(self.IFACE_UUID))

    def test_wrong_service_not_sent(self):
        ccache = _make_ccache(_make_credential("cifs/{}@{}".format(SRV_SHORT, REALM)))
        transport = mock.Mock()
        with self.assertRaises(CachePolicyError):
            self._bind(transport, ccache, KerberosCachePolicy.strict())
        transport.send.assert_not_called()

    def test_wrong_realm_not_sent(self):
        ccache = _make_ccache(_make_credential("host/{}@OTHER.TEST".format(SRV_SHORT)))
        transport = mock.Mock()
        with self.assertRaises(CachePolicyError):
            self._bind(transport, ccache, KerberosCachePolicy.strict())
        transport.send.assert_not_called()

    def test_cache_index_spoofing_not_sent(self):
        ccache = _make_ccache(_make_credential("host/{}@{}".format(SRV_SHORT, REALM),
                                               ticket_spn="cifs/{}@{}".format(SRV_SHORT, REALM)))
        transport = mock.Mock()
        with self.assertRaises(CachePolicyError):
            self._bind(transport, ccache, KerberosCachePolicy.strict())
        transport.send.assert_not_called()

    def test_legit_match_sent(self):
        ccache = _make_ccache(_make_credential("host/{}@{}".format(SRV_SHORT, REALM)))
        transport = mock.Mock()
        self._bind(transport, ccache, KerberosCachePolicy.strict())
        transport.send.assert_called_once()


if __name__ == "__main__":
    unittest.main(verbosity=1)
