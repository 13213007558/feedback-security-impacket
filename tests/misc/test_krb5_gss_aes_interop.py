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
# Offline interoperability regression for the Kerberos AES (RFC 4121) GSS
# wrap/unwrap receiver.
#
# The vectors in tests/data/krb5-gss-aes/gss-aes-vectors.json were produced by
# an independent cryptographic stack (pyca/cryptography, not impacket.krb5),
# so these tests prove the receiver accepts spec-compliant tokens and rejects
# malformed/mis-directed ones -- not merely that impacket can read back its own
# output.  Every negative vector records the byte offset at which the strict
# receiver must fail.
#
import binascii
import json
import os
import struct
import unittest

from impacket.krb5.crypto import InvalidChecksum, Key, _AES128CTS, _AES256CTS
from impacket.krb5.gssapi import (
    GSSAPI_AES128,
    GSSAPI_AES256,
    GSSAPITokenError,
)
from impacket.dcerpc.v5.rpcrt import SEC_TRAILER

CORPUS_PATH = os.path.join(
    os.path.dirname(__file__), os.pardir, 'data', 'krb5-gss-aes', 'gss-aes-vectors.json')

with open(CORPUS_PATH) as _fh:
    CORPUS = json.load(_fh)

KEYS = {int(k): binascii.unhexlify(v) for k, v in CORPUS['keys_hex'].items()}
KEY_USAGE = CORPUS['key_usages']


def _unhex(value):
    return binascii.unhexlify(value) if value else b''


def _gss(etype):
    return GSSAPI_AES256() if etype == 18 else GSSAPI_AES128()


def _cipher(etype):
    return _AES256CTS if etype == 18 else _AES128CTS


def _receiver_direction(sender_direction):
    # The local role is the peer of whoever sent the token.
    return 'accept' if sender_direction == 'init' else 'init'


def _rpc_unwrap(gss, key, vector):
    """Reassemble the DCE/RPC framing (SEC_TRAILER + header + middle in the
    auth verifier, remaining bytes as the PDU body) and unwrap."""
    header = _unhex(vector['header_hex'])
    middle = _unhex(vector.get('middle_hex', ''))
    body = _unhex(vector.get('body_hex', ''))
    auth_data = SEC_TRAILER().getData() + header + middle
    sealed = vector['mode'] == 'sealed'
    plaintext, _ = gss.GSS_Unwrap(
        key, body, vector['seq'], direction=_receiver_direction(vector['direction']),
        encrypt=sealed, authData=auth_data)
    return plaintext


def _ldap_unwrap(gss, key, vector):
    """LDAP carries the whole wrap token contiguously after the 4-byte length."""
    token = (_unhex(vector['header_hex']) + _unhex(vector.get('middle_hex', ''))
             + _unhex(vector.get('body_hex', '')))
    plaintext, _ = gss.GSS_Unwrap_LDAP(
        key, token, vector['seq'], direction=_receiver_direction(vector['direction']))
    return plaintext


class AesGssPositiveVectors(unittest.TestCase):
    """Spec-compliant tokens from the independent stack must unwrap to the
    recorded plaintext on both the RPC and LDAP receive paths."""

    def _check(self, vector):
        gss = _gss(vector['etype'])
        key = Key(vector['etype'], KEYS[vector['etype']])
        expected = _unhex(vector['plaintext_hex'])
        if vector['mode'] == 'sealed':
            self.assertEqual(_rpc_unwrap(gss, key, vector), expected,
                             'RPC path: ' + vector['name'])
            self.assertEqual(_ldap_unwrap(gss, key, vector), expected,
                             'LDAP path: ' + vector['name'])
        else:
            token = (_unhex(vector['header_hex']) + _unhex(vector['checksum_hex'])
                     + expected)
            sender = vector['direction']
            plaintext, seq, sealed = gss._unwrap_token(
                key, token, sender, expect_sealed=False)
            self.assertEqual(plaintext, expected, 'sign-only: ' + vector['name'])
            self.assertFalse(sealed)
            self.assertEqual(seq, vector['seq'])

    def test_all_positive_vectors(self):
        self.assertGreater(len(CORPUS['positive']), 0)
        for vector in CORPUS['positive']:
            with self.subTest(vector=vector['name']):
                self._check(vector)

    def test_corpus_covers_required_matrix(self):
        modes = {(v['etype'], v['direction'], v['mode']) for v in CORPUS['positive']}
        for etype in (17, 18):
            for direction in ('init', 'accept'):
                for mode in ('sealed', 'sign-only'):
                    self.assertIn((etype, direction, mode), modes,
                                  'missing coverage for %s/%s/%s' % (etype, direction, mode))
        # EC (extra count) values across the padding range must be exercised.
        ecs = {v['ec'] for v in CORPUS['positive'] if v['mode'] == 'sealed'}
        self.assertIn(0, ecs)
        self.assertTrue(any(ec > 0 for ec in ecs))
        # 64-bit sequence numbers must be exercised (high bit set).
        self.assertTrue(any(v['seq'] > 0xFFFFFFFF for v in CORPUS['positive']))


class AesGssNegativeVectors(unittest.TestCase):
    """Tampered or mis-directed tokens must be rejected, at the recorded
    failure offset for structural problems."""

    STRUCTURAL = {
        'direction-mismatch': 2,
        'sealed-flag-mismatch': 2,
        'bad-tok-id': 0,
        'bad-filler': 3,
        'bad-rrc': 6,
    }

    def _assert_rejected(self, vector):
        gss = _gss(vector['etype'])
        key = Key(vector['etype'], KEYS[vector['etype']])
        reason = vector['expect_reject']
        # Every negative vector must be rejected one way or another.
        with self.assertRaises((GSSAPITokenError, InvalidChecksum, ValueError),
                               msg='not rejected: ' + vector['name']) as ctx:
            _rpc_unwrap(gss, key, vector)
        exc = ctx.exception
        if reason in self.STRUCTURAL:
            # Single-field structural mutations must be caught by the structural
            # parser at the exact documented offset, not later by the MAC check.
            self.assertIsInstance(exc, GSSAPITokenError,
                                  '%s should fail structurally' % vector['name'])
            self.assertEqual(exc.offset, self.STRUCTURAL[reason],
                             '%s failed at wrong offset' % vector['name'])
            self.assertEqual(exc.offset, vector['fail_offset'])

    def test_all_negative_vectors(self):
        self.assertGreater(len(CORPUS['negative']), 0)
        for vector in CORPUS['negative']:
            with self.subTest(vector=vector['name']):
                self._assert_rejected(vector)

    def test_wrong_direction_rejected_on_both_paths(self):
        # Take a valid initiator token and present it to an initiator receiver
        # (i.e. claim the local role is the sender's own role).
        vector = next(v for v in CORPUS['positive']
                      if v['mode'] == 'sealed' and v['direction'] == 'init')
        gss = _gss(vector['etype'])
        key = Key(vector['etype'], KEYS[vector['etype']])
        header = _unhex(vector['header_hex'])
        middle = _unhex(vector['middle_hex'])
        body = _unhex(vector['body_hex'])
        auth_data = SEC_TRAILER().getData() + header + middle
        # direction='init' means "I am the initiator", so an initiator-sent
        # token must be rejected as a direction mismatch.
        with self.assertRaises(GSSAPITokenError):
            gss.GSS_Unwrap(key, body, vector['seq'], direction='init', authData=auth_data)
        with self.assertRaises(GSSAPITokenError):
            gss.GSS_Unwrap_LDAP(key, header + middle + body, vector['seq'], direction='init')


class AesGssMutualBug(unittest.TestCase):
    """Counter-example: both peers share the SAME wrong rotation rule (RRC
    without EC).  A decoder making the identical mistake accepts the token, but
    the strict receiver must reject it -- proving the test catches the case
    where the two wrong ends interoperate with each other."""

    def setUp(self):
        self.vector = CORPUS['mutual_bug']
        self.key = Key(self.vector['etype'], KEYS[self.vector['etype']])
        self.gss = _gss(self.vector['etype'])

    def test_buggy_decoder_accepts_matching_buggy_token(self):
        # A peer that repeats the same mistake (unrotate by RRC only, ignoring
        # EC) and uses the correct sender key usage recovers the plaintext.
        v = self.vector
        token = self.gss.WRAP(_unhex(v['header_hex']))
        rotated = _unhex(v['middle_hex']) + _unhex(v['body_hex'])
        buggy_ciphertext = self.gss.unrotate(rotated, token['RRC'])  # same bug
        sender = v['direction']
        usage = (KEY_USAGE['initiator_seal'] if sender == 'init'
                 else KEY_USAGE['acceptor_seal'])
        plaintext = _cipher(v['etype']).decrypt(self.key, usage, buggy_ciphertext)
        recovered = plaintext[:-(token['EC'] + len(self.gss.WRAP()))]
        self.assertEqual(recovered, _unhex(v['plaintext_hex']),
                         'the two wrong ends should interoperate with each other')

    def test_strict_receiver_rejects_mutual_bug_token(self):
        with self.assertRaises((GSSAPITokenError, InvalidChecksum)):
            _rpc_unwrap(self.gss, self.key, self.vector)
        with self.assertRaises((GSSAPITokenError, InvalidChecksum)):
            _ldap_unwrap(self.gss, self.key, self.vector)


class AesGssRoundTripAndStructure(unittest.TestCase):
    """The hardened implementation must round-trip across roles and enforce
    direction, sealed flag, EC, RRC and the 64-bit sequence number."""

    def _roundtrip(self, gss, key, data, seq, direction, sealed):
        if sealed:
            body, token = gss.GSS_Wrap(key, data, seq, direction=direction)
            auth_data = SEC_TRAILER().getData() + token
            out, _ = gss.GSS_Unwrap(key, body, seq,
                                    direction=_receiver_direction(direction),
                                    authData=auth_data)
            self.assertEqual(out, data)
            ct, hdr = gss.GSS_Wrap_LDAP(key, data, seq, direction=direction)
            out, _ = gss.GSS_Unwrap_LDAP(key, hdr + ct, seq,
                                         direction=_receiver_direction(direction))
            self.assertEqual(out, data)
        else:
            mic = gss.GSS_GetMIC(key, data, seq, direction=direction)
            got_seq = gss.GSS_VerifyMIC(key, data, mic, seq,
                                        direction=_receiver_direction(direction))
            self.assertEqual(got_seq, seq)

    def test_roundtrip_matrix(self):
        for gss, etype in ((GSSAPI_AES256(), 18), (GSSAPI_AES128(), 17)):
            key = Key(etype, bytes(range(1, 33 if etype == 18 else 17)))
            for dlen in (0, 1, 15, 16, 17, 19, 48, 100):
                data = bytes((i * 7 + dlen) & 0xFF for i in range(dlen))
                for direction in ('init', 'accept'):
                    for sealed in (True, False):
                        with self.subTest(etype=etype, dlen=dlen,
                                          direction=direction, sealed=sealed):
                            self._roundtrip(gss, key, data, 0x0123456789ABCDEF,
                                            direction, sealed)

    def test_unwrap_strips_exactly_ec_plus_header(self):
        # The rotated trailer (EC padding + 16-byte inner header) must not leak
        # into the application payload.
        gss = GSSAPI_AES256()
        key = Key(18, bytes(range(1, 33)))
        data = b'payload-with-padding'
        body, token = gss.GSS_Wrap(key, data, 3, direction='init')
        auth_data = SEC_TRAILER().getData() + token
        out, _ = gss.GSS_Unwrap(key, body, 3, direction='accept', authData=auth_data)
        self.assertEqual(out, data)
        self.assertEqual(len(out), len(data))

    def test_sequence_number_is_64_bit(self):
        gss = GSSAPI_AES256()
        key = Key(18, bytes(range(1, 33)))
        seq = 0xFFFFFFFFFFFFFFFF
        body, token = gss.GSS_Wrap(key, b'x', seq, direction='init')
        parsed = gss.WRAP(token[:16])
        self.assertEqual(struct.unpack('>Q', parsed['SND_SEQ'])[0], seq)
        auth_data = SEC_TRAILER().getData() + token
        out, _ = gss.GSS_Unwrap(key, body, seq, direction='accept', authData=auth_data)
        self.assertEqual(out, b'x')

    def test_key_usage_separates_directions(self):
        # A token sealed for one direction must not verify under the other
        # direction's key usage.
        gss = GSSAPI_AES256()
        key = Key(18, bytes(range(1, 33)))
        data = b'direction-binding'
        body, token = gss.GSS_Wrap(key, data, 4, direction='init')
        auth_data = SEC_TRAILER().getData() + token
        # Correct peer role unwraps fine.
        out, _ = gss.GSS_Unwrap(key, body, 4, direction='accept', authData=auth_data)
        self.assertEqual(out, data)
        # Same role (wrong direction) is rejected before/while using the wrong
        # key usage.
        with self.assertRaises(GSSAPITokenError):
            gss.GSS_Unwrap(key, body, 4, direction='init', authData=auth_data)


if __name__ == '__main__':
    unittest.main(verbosity=1)
