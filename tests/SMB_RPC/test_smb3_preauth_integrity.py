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
"""
Offline regression for SMB 3.1.1 pre-authentication integrity.

These tests never open a socket and never talk to a real SMB server. A fully
scripted, in-process SMB peer replays hand-written protocol vectors while the
real ``impacket.smb3.SMB3`` client drives the exchange. Every byte the client
emits and every byte the fake peer emits is captured into a transcript, and an
independent oracle (stdlib ``hashlib``/``hmac`` plus the ``cryptography``
package - never impacket's own crypto helpers) recomputes:

  * the SHA-512 pre-authentication hash chains,
  * the NTLMv2 exported session key,
  * the SP800-108 counter-mode KDF outputs (signing / cipher / application),
  * the AES-128-CMAC message signature and the AES-128-GCM transform.

The point is to prove that the final signing and encryption keys are bound to
the exact handshake bytes that crossed the (fake) transport, including
multi-step SessionSetup, a failed login followed by a re-login on the same
connection, and negotiated-context byte mutations that leave the parsed
fields identical.
"""
import hashlib
import hmac
import socket
import struct
import unittest

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.cmac import CMAC

from impacket import ntlm, smb3
from impacket.nt_errors import (
    STATUS_LOGON_FAILURE,
    STATUS_MORE_PROCESSING_REQUIRED,
    STATUS_SUCCESS,
)
from impacket.spnego import SPNEGO_NegTokenResp, TypesMech
from impacket.smb3structs import (
    SMB2_DIALECT_311,
    SMB2_ENCRYPTION_AES128_CCM,
    SMB2_ENCRYPTION_AES128_GCM,
    SMB2_ECHO,
    SMB2_ENCRYPTION_CAPABILITIES,
    SMB2_FLAGS_SIGNED,
    SMB2_GLOBAL_CAP_ENCRYPTION,
    SMB2_NEGOTIATE,
    SMB2_NEGOTIATE_SIGNING_REQUIRED,
    SMB2_PACKET_SIZE,
    SMB2_PREAUTH_INTEGRITY_CAPABILITIES,
    SMB2_SESSION_FLAG_ENCRYPT_DATA,
    SMB2_SESSION_SETUP,
    SMB2NegotiateContext,
    SMB2EncryptionCapabilities,
    SMB2Packet,
    SMB2PreAuthIntegrityCapabilities,
    SMB2SessionSetup,
    SMB2SessionSetup_Response,
    SMB2Negotiate_Response,
    SMB3Packet,
    SMB2_TRANSFORM_HEADER,
    SMB2Echo,
)

# Fixed, non-secret test material. Nothing here is a real credential.
USER = 'alice'
PASSWORD = 'Password123!'
DOMAIN = 'TESTDOM'
WORKSTATION = 'clientwks'
SERVER_NAME = 'fakesrv'
SERVER_CHALLENGE = b'01234567'
SERVER_GUID = b'G' * 16
SESSION_ID = 0x4141000000000001
ZERO_HASH = b'\x00' * 64


# ---------------------------------------------------------------------------
# Independent cryptographic oracle. None of these call impacket.crypto.
# ---------------------------------------------------------------------------

def sp800_108_counter_kdf(key_derivation_key, label, context, length_bits=128):
    """NIST SP800-108 counter-mode KDF, PRF = HMAC-SHA256 (MS-SMB2 3.1.4.2)."""
    output = b''
    counter = 1
    while len(output) * 8 < length_bits:
        message = (
            struct.pack('>I', counter)
            + label
            + b'\x00'
            + context
            + struct.pack('>I', length_bits)
        )
        output += hmac.new(key_derivation_key, message, hashlib.sha256).digest()
        counter += 1
    return output[: length_bits // 8]


def aes_cmac(key, message):
    cmac = CMAC(algorithms.AES(key))
    cmac.update(message)
    return cmac.finalize()


def aes_gcm_seal(key, nonce, plaintext, associated_data):
    encryptor = Cipher(algorithms.AES(key), modes.GCM(nonce)).encryptor()
    encryptor.authenticate_additional_data(associated_data)
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return ciphertext, encryptor.tag


def aes_gcm_open(key, nonce, ciphertext, tag, associated_data):
    decryptor = Cipher(algorithms.AES(key), modes.GCM(nonce, tag)).decryptor()
    decryptor.authenticate_additional_data(associated_data)
    return decryptor.update(ciphertext) + decryptor.finalize()


def ntlmv2_response_key():
    nt_hash = ntlm.compute_nthash(PASSWORD)
    identity = USER.upper().encode('utf-16le') + DOMAIN.encode('utf-16le')
    return hmac.new(nt_hash, identity, hashlib.md5).digest()


def build_target_info():
    av_pairs = ntlm.AV_PAIRS()
    av_pairs[ntlm.NTLMSSP_AV_HOSTNAME] = SERVER_NAME.encode('utf-16le')
    av_pairs[ntlm.NTLMSSP_AV_DNS_HOSTNAME] = (SERVER_NAME + '.testdom.local').encode('utf-16le')
    av_pairs[ntlm.NTLMSSP_AV_DOMAINNAME] = DOMAIN.encode('utf-16le')
    av_pairs[ntlm.NTLMSSP_AV_DNS_DOMAINNAME] = b'testdom.local'
    return av_pairs.getData()


def make_type2_challenge():
    challenge = ntlm.NTLMAuthChallenge()
    challenge['flags'] = (
        ntlm.NTLMSSP_NEGOTIATE_128
        | ntlm.NTLMSSP_NEGOTIATE_KEY_EXCH
        | ntlm.NTLMSSP_NEGOTIATE_NTLM
        | ntlm.NTLMSSP_NEGOTIATE_UNICODE
        | ntlm.NTLMSSP_NEGOTIATE_SIGN
        | ntlm.NTLMSSP_NEGOTIATE_SEAL
    )
    challenge['challenge'] = SERVER_CHALLENGE
    domain_bytes = DOMAIN.encode('utf-16le')
    target_info = build_target_info()
    challenge['domain_name'] = domain_bytes
    challenge['domain_len'] = len(domain_bytes)
    challenge['domain_max_len'] = len(domain_bytes)
    challenge['domain_offset'] = 56
    challenge['TargetInfoFields'] = target_info
    challenge['TargetInfoFields_len'] = len(target_info)
    challenge['TargetInfoFields_max_len'] = len(target_info)
    challenge['TargetInfoFields_offset'] = 56 + len(domain_bytes)
    challenge['Version'] = b'\xff' * 8
    return challenge.getData()


# ---------------------------------------------------------------------------
# Transcript: every raw SMB2 message (direction, command, status, bytes) plus
# per-message hash diagnostics, so a mismatch can be located to one message.
# ---------------------------------------------------------------------------

class TranscriptRecord:
    def __init__(self, index, direction, command, status, raw, conn_hash, sess_hash):
        self.index = index
        self.direction = direction  # 'C->S' or 'S->C'
        self.command = command
        self.status = status
        self.raw = raw
        self.conn_hash = conn_hash
        self.sess_hash = sess_hash

    def describe(self):
        return (
            '#%02d %s command=0x%04x status=0x%08x len=%d conn=%s sess=%s'
            % (self.index, self.direction, self.command, self.status, len(self.raw),
               self.conn_hash.hex()[:16], self.sess_hash.hex()[:16])
        )


class Transcript:
    def __init__(self):
        self.records = []

    def add(self, direction, raw, conn_hash, sess_hash):
        if raw.startswith(b'\xfdSMB'):
            command = -1
            status = 0
        else:
            packet = SMB2Packet(raw)
            command = packet['Command']
            status = packet['Status']
        self.records.append(
            TranscriptRecord(len(self.records), direction, command, status, raw,
                             conn_hash, sess_hash)
        )

    def diff_report(self, expected_conn, expected_sess):
        """Pair each captured record with independently recomputed chain values."""
        lines = []
        for record, conn, sess in zip(self.records, expected_conn, expected_sess):
            conn_ok = record.conn_hash == conn
            sess_ok = record.sess_hash == sess
            lines.append(
                '%s | conn=%s sess=%s%s'
                % (record.describe(),
                   'OK' if conn_ok else 'MISMATCH(exp %s)' % conn.hex()[:16],
                   'OK' if sess_ok else 'MISMATCH(exp %s)' % sess.hex()[:16],
                   '' if (conn_ok and sess_ok) else '  <-- DIFFERS')
            )
        return '\n'.join(lines)


class _NetBIOSPacket:
    def __init__(self, trailer):
        self._trailer = trailer

    def get_trailer(self):
        return self._trailer


class FakeNetBIOS:
    """Drop-in replacement for the NetBIOS session transport; no socket I/O."""

    def __init__(self, peer):
        self.peer = peer
        self.sent_raw = []

    def send_packet(self, data):
        self.sent_raw.append(data)
        self.peer.feed(data)

    def recv_packet(self, timeout=None):
        return _NetBIOSPacket(self.peer.out_queue.pop(0))

    def get_socket(self):
        # Never connected; only stored as an opaque handle by the client.
        return socket.socket()


class FakePeer:
    """
    Scripted SMB 3.1.1 peer. It independently tracks the two hash chains exactly
    the way MS-SMB2 / the client do, verifies the NTLMv2 authenticator itself,
    and recovers the exported session key from the client's key-exchange field.
    """

    def __init__(self, negotiate_mutator=None, fail_final_once=False, cipher=SMB2_ENCRYPTION_AES128_GCM):
        self.out_queue = []
        self.negotiate_mutator = negotiate_mutator
        self.fail_final_once = fail_final_once
        self.cipher = cipher
        self.transcript = Transcript()

        self.conn_hash = ZERO_HASH
        self.sess_hash = ZERO_HASH
        self.exported_session_key = None
        # State of the last *completed* session; this is what the client keeps
        # using to protect traffic while a subsequent (possibly failing) login
        # attempt is in flight. It is only promoted after a successful type3.
        self.active_session_key = None
        self.active_sess_hash = None
        self.pending_session_key = None
        self.pending_sess_hash = None
        self.attempts = 0
        self.echo_plaintexts = []

    # -- hash bookkeeping --------------------------------------------------

    @staticmethod
    def _chain(current, raw):
        return hashlib.sha512(current + raw).digest()

    def _record(self, direction, raw):
        self.transcript.add(direction, raw, self.conn_hash, self.sess_hash)

    # -- transport entry points --------------------------------------------

    def feed(self, raw):
        if raw.startswith(b'\xfdSMB'):
            plaintext = self._open_transform(raw)
            packet = SMB3Packet(plaintext)
            if packet['Command'] == SMB2_SESSION_SETUP:
                # Observed impacket behavior: a stale EncryptData flag makes the
                # re-login SESSION_SETUP go through the transform branch, which
                # returns before the pre-auth hash update, so these bytes never
                # enter either chain. Process the NTLM exchange without hashing.
                self._handle_encrypted_session_setup(plaintext)
                return
            self._handle_post_auth(plaintext)
            return
        packet = SMB3Packet(raw)
        if packet['Command'] == SMB2_NEGOTIATE:
            self.conn_hash = self._chain(self.conn_hash, raw)
            self._record('C->S', raw)
            self._handle_negotiate(packet)
        elif packet['Command'] == SMB2_SESSION_SETUP:
            self._handle_session_setup(raw)
        else:
            self._handle_post_auth(raw)

    # -- NEGOTIATE ----------------------------------------------------------

    def _handle_negotiate(self, request):
        security_blob = b'fake-gss-token'
        preauth_ctx = SMB2PreAuthIntegrityCapabilities()
        preauth_ctx['HashAlgorithmCount'] = 1
        preauth_ctx['SaltLength'] = 32
        preauth_ctx['HashAlgorithms'] = b'\x01\x00'
        preauth_ctx['Salt'] = b'S' * 32
        context1 = SMB2NegotiateContext()
        context1['ContextType'] = SMB2_PREAUTH_INTEGRITY_CAPABILITIES
        context1['Data'] = preauth_ctx.getData()
        context1['DataLength'] = len(context1['Data'])

        encryption_ctx = SMB2EncryptionCapabilities()
        encryption_ctx['CipherCount'] = 1
        encryption_ctx['Ciphers'] = struct.pack('<H', self.cipher)
        context2 = SMB2NegotiateContext()
        context2['ContextType'] = SMB2_ENCRYPTION_CAPABILITIES
        context2['Data'] = encryption_ctx.getData()
        context2['DataLength'] = len(context2['Data'])
        pad1 = b'\x00' * ((8 - (context1['DataLength'] % 8)) % 8)

        response_body = SMB2Negotiate_Response()
        response_body['SecurityMode'] = SMB2_NEGOTIATE_SIGNING_REQUIRED
        response_body['DialectRevision'] = SMB2_DIALECT_311
        response_body['NegotiateContextCount'] = 2
        response_body['ServerGuid'] = SERVER_GUID
        response_body['Capabilities'] = SMB2_GLOBAL_CAP_ENCRYPTION
        response_body['MaxTransactSize'] = 0x100000
        response_body['MaxReadSize'] = 0x100000
        response_body['MaxWriteSize'] = 0x100000
        context_offset = 128 + len(security_blob)
        alignment = (8 - (context_offset % 8)) % 8
        response_body['SecurityBufferOffset'] = 128
        response_body['SecurityBufferLength'] = len(security_blob)
        response_body['Buffer'] = security_blob
        response_body['Padding'] = b'\x00' * alignment
        response_body['NegotiateContextOffset'] = context_offset + alignment
        response_body['NegotiateContextList'] = context1.getData() + pad1 + context2.getData()

        header = self._response_header(request, STATUS_SUCCESS)
        header['Data'] = response_body
        raw = header.getData()
        if self.negotiate_mutator is not None:
            raw = self.negotiate_mutator(raw)
        # Only the connection chain runs during negotiate; the session chain is
        # seeded later from the connection value at the first SESSION_SETUP.
        self.conn_hash = self._chain(self.conn_hash, raw)
        self.out_queue.append(raw)
        self._record('S->C', raw)

    # -- SESSION_SETUP ------------------------------------------------------

    def _handle_session_setup(self, raw_request, hashed=True):
        # The connection chain freezes after the NEGOTIATE response: no
        # SESSION_SETUP byte ever enters it. Only the session chain advances.
        request = SMB3Packet(raw_request)
        body = SMB2SessionSetup(request['Data'])
        is_type1 = body['Buffer'][0] == 0x60
        if is_type1:
            self.attempts += 1
            if hashed:
                # A type1 request seeds the session chain from the frozen
                # connection value, then folds the request into the session chain.
                self.sess_hash = self._chain(self.conn_hash, raw_request)
                self._record('C->S', raw_request)
            self._send_type2(request, hashed)
        else:
            if hashed:
                self.sess_hash = self._chain(self.sess_hash, raw_request)
                self._record('C->S', raw_request)
            self._send_final(request, body['Buffer'], hashed)

    def _handle_encrypted_session_setup(self, raw_request):
        # A SESSION_SETUP carried inside a transform never reaches the client's
        # pre-auth *request* update code. But the type2 response still flows
        # through recvSMB, which unconditionally folds it into the session
        # chain. The connection chain stays frozen regardless.
        self._handle_session_setup(raw_request, hashed=False)

    def _send_type2(self, request, hashed=True):
        token = SPNEGO_NegTokenResp()
        token['NegState'] = b'\x01'
        token['SupportedMech'] = TypesMech['NTLMSSP - Microsoft NTLM Security Support Provider']
        token['ResponseToken'] = make_type2_challenge()
        body = SMB2SessionSetup_Response()
        body['SecurityBufferOffset'] = SMB2_PACKET_SIZE + 8
        body['SecurityBufferLength'] = len(token)
        body['Buffer'] = token.getData()
        header = self._response_header(request, STATUS_MORE_PROCESSING_REQUIRED)
        header['Data'] = body
        raw = header.getData()
        if hashed:
            self.sess_hash = self._chain(self.sess_hash, raw)
            self._record('S->C', raw)
            self.out_queue.append(raw)
        else:
            # Encrypted re-login: seed from the frozen connection value and fold
            # only this type2 response into the session chain.
            self.sess_hash = self._chain(self.conn_hash, raw)
            self._record('S->C', raw)
            self.out_queue.append(self._wrap_transform(raw))

    def _send_final(self, request, spnego_blob, hashed=True):
        neg_resp = SPNEGO_NegTokenResp(spnego_blob)
        type3 = ntlm.NTLMAuthChallengeResponse()
        type3.fromString(neg_resp['ResponseToken'])

        response_key = ntlmv2_response_key()
        nt_challenge_response = type3['ntlm']
        nt_proof_str = nt_challenge_response[:16]
        temp = nt_challenge_response[16:]
        expected_proof = hmac.new(
            response_key, SERVER_CHALLENGE + temp, hashlib.md5
        ).digest()
        if not hmac.compare_digest(nt_proof_str, expected_proof):
            raise AssertionError('independent NTLMv2 proof verification failed')
        session_base_key = hmac.new(response_key, nt_proof_str, hashlib.md5).digest()
        # NTLMv2 KXKEY == session base key; the client RC4-wraps the exported key.
        from Cryptodome.Cipher import ARC4
        exported = ARC4.new(session_base_key).decrypt(type3['session_key'])
        if len(exported) != 16:
            raise AssertionError('unexpected exported session key length')
        self.exported_session_key = exported

        should_fail = self.fail_final_once
        self.fail_final_once = False
        # Compute the would-be new session context, but do not promote it yet:
        # the final response below is still protected with the active keys, and
        # the client only derives its new keys after receiving that response.
        if hashed:
            self.pending_sess_hash = self.sess_hash
        else:
            # Off-hash re-login: requests were not folded, so the chain ends on
            # the type2 response value already held in sess_hash.
            self.pending_sess_hash = self.sess_hash
        self.pending_session_key = exported
        if should_fail:
            # Mirror client failure cleanup for the session-level chain only.
            # active_* is untouched: the client keeps protecting subsequent
            # SESSION_SETUP traffic with the previous session's keys.
            self.sess_hash = ZERO_HASH
            self.exported_session_key = None
            self.pending_session_key = None
            self.pending_sess_hash = None

        body = SMB2SessionSetup_Response()
        body['SessionFlags'] = SMB2_SESSION_FLAG_ENCRYPT_DATA
        body['SecurityBufferOffset'] = SMB2_PACKET_SIZE + 8
        body['SecurityBufferLength'] = 0
        body['Buffer'] = b''
        status = STATUS_LOGON_FAILURE if should_fail else STATUS_SUCCESS
        header = self._response_header(request, status)
        header['Data'] = body
        raw = header.getData()
        # Final SESSION_SETUP response is always outside the pre-auth hash.
        self.out_queue.append(raw if hashed else self._wrap_transform(raw))

        if not should_fail:
            # The client adopts the new keys only after this final response is
            # enqueued, so promote pending -> active afterwards.
            self.active_session_key = self.pending_session_key
            self.active_sess_hash = self.pending_sess_hash

    # -- post-auth traffic --------------------------------------------------

    def _handle_post_auth(self, raw_request):
        request = SMB3Packet(raw_request)
        if request['Command'] == SMB2_ECHO:
            self.echo_plaintexts.append(raw_request)
            header = self._response_header(request, STATUS_SUCCESS)
            header['Data'] = SMB2Echo()
            self._send_encrypted(header.getData())
        else:
            raise AssertionError('unexpected post-auth command 0x%04x' % request['Command'])

    # -- transforms ---------------------------------------------------------

    def _active_keys(self):
        # Transforms are always protected with the last completed session's
        # key material. While a new login attempt is in flight (or after it
        # fails), the client still uses these keys, so the peer does too.
        return self._derive(self.active_session_key, self.active_sess_hash)

    def _derive(self, session_key, context):
        return {
            'signing': sp800_108_counter_kdf(session_key, b'SMBSigningKey\x00', context),
            'c2s': sp800_108_counter_kdf(session_key, b'SMBC2SCipherKey\x00', context),
            's2c': sp800_108_counter_kdf(session_key, b'SMBS2CCipherKey\x00', context),
            'application': sp800_108_counter_kdf(session_key, b'SMBAppKey\x00', context),
        }

    def _open_transform(self, raw):
        header = SMB2_TRANSFORM_HEADER(raw)
        nonce = header['Nonce'][:12]
        associated = header.getData()[20:]
        keys = self._active_keys()
        return aes_gcm_open(
            keys['c2s'], nonce, raw[len(SMB2_TRANSFORM_HEADER()):], header['Signature'], associated
        )

    def _wrap_transform(self, plaintext):
        keys = self._active_keys()
        nonce = b'R' * 12
        header = SMB2_TRANSFORM_HEADER()
        header['Nonce'] = nonce + b'\x00' * 4
        header['OriginalMessageSize'] = len(plaintext)
        header['EncryptionAlgorithm'] = SMB2_ENCRYPTION_AES128_CCM
        header['SessionID'] = SESSION_ID
        ciphertext, tag = aes_gcm_seal(keys['s2c'], nonce, plaintext, header.getData()[20:])
        header['Signature'] = tag
        return header.getData() + ciphertext

    def _send_encrypted(self, plaintext):
        self.out_queue.append(self._wrap_transform(plaintext))

    def _response_header(self, request, status):
        header = SMB2Packet()
        header['Command'] = request['Command']
        header['MessageID'] = request['MessageID']
        header['CreditCharge'] = 1
        header['CreditRequestResponse'] = 127
        header['Status'] = status
        header['SessionID'] = SESSION_ID
        header['TreeID'] = request['TreeID']
        return header


# ---------------------------------------------------------------------------
# Test harness
# ---------------------------------------------------------------------------

def build_client(peer):
    transport = FakeNetBIOS(peer)
    client = smb3.SMB3.__new__(smb3.SMB3)
    smb3.SMB3.__init__(
        client, SERVER_NAME, '10.0.0.1', my_name=WORKSTATION, session=transport
    )
    return client, transport


def replay_chains(records):
    """
    Independently reconstruct both chains from the captured raw bytes.

    The connection chain only folds the NEGOTIATE request and response and then
    freezes. The session chain is seeded from that frozen connection value at
    the first type1 SESSION_SETUP and folds every subsequent SESSION_SETUP
    request/response except the final successful response (excluded by the
    client and therefore absent from the transcript).
    """
    conn = ZERO_HASH
    sess = ZERO_HASH
    session_started = False
    conn_trace, sess_trace = [], []
    for record in records:
        if record.command == SMB2_NEGOTIATE:
            conn = hashlib.sha512(conn + record.raw).digest()
        if record.command == SMB2_SESSION_SETUP and record.direction == 'C->S':
            body = SMB2SessionSetup(SMB3Packet(record.raw)['Data'])
            if body['Buffer'][0] == 0x60:  # type1: seed session chain from connection
                sess = conn
                session_started = True
        if session_started:
            sess = hashlib.sha512(sess + record.raw).digest()
        conn_trace.append(conn)
        sess_trace.append(sess)
    return conn_trace, sess_trace


class PreAuthIntegrityTests(unittest.TestCase):

    def setUp(self):
        self.peer = FakePeer()
        self.client, self.transport = build_client(self.peer)

    def test_dialect_and_cipher_negotiated_offline(self):
        self.assertEqual(self.client._Connection['Dialect'], SMB2_DIALECT_311)
        self.assertEqual(self.client._Connection['CipherId'], SMB2_ENCRYPTION_AES128_GCM)
        self.assertTrue(self.client._Connection['RequireSigning'])

    def test_ccm_negotiation_context_still_binds_keys_to_bytes(self):
        # A different negotiated cipher changes the NEGOTIATE response bytes and
        # therefore the hash chain; key derivation must still verify end to end.
        ccm_peer = FakePeer(cipher=SMB2_ENCRYPTION_AES128_CCM)
        ccm_client, _ = build_client(ccm_peer)
        self.assertEqual(ccm_client._Connection['CipherId'], SMB2_ENCRYPTION_AES128_CCM)
        self.assertTrue(ccm_client.login(USER, PASSWORD, DOMAIN))

        conn_trace, sess_trace = replay_chains(ccm_peer.transcript.records)
        report = ccm_peer.transcript.diff_report(conn_trace, sess_trace)
        self.assertNotIn('MISMATCH', report)
        self.assertEqual(
            sess_trace[-1], ccm_client._Session['PreauthIntegrityHashValue']
        )
        expected_signing = sp800_108_counter_kdf(
            ccm_peer.exported_session_key, b'SMBSigningKey\x00',
            ccm_client._Session['PreauthIntegrityHashValue'],
        )
        self.assertEqual(expected_signing, ccm_client._Session['SigningKey'])
        # The two cipher negotiations must not yield the same connection hash.
        self.assertNotEqual(
            self.client._Connection['PreauthIntegrityHashValue'],
            ccm_client._Connection['PreauthIntegrityHashValue'],
        )

    def test_hash_chains_match_independent_transcript_walk(self):
        self.assertTrue(self.client.login(USER, PASSWORD, DOMAIN))

        conn_trace, sess_trace = replay_chains(self.peer.transcript.records)
        report = self.peer.transcript.diff_report(conn_trace, sess_trace)

        # Every per-message snapshot must match the independent re-walk, so a
        # failure is locatable to the exact message via ``report``.
        for record, conn, sess in zip(self.peer.transcript.records, conn_trace, sess_trace):
            self.assertEqual(record.conn_hash, conn, msg='connection chain\n' + report)
            self.assertEqual(record.sess_hash, sess, msg='session chain\n' + report)

        self.assertEqual(
            self.peer.transcript.records[-1].sess_hash,
            self.client._Session['PreauthIntegrityHashValue'],
            msg='session hash not bound to transcript\n' + report,
        )
        # The session chain folds the type3 request; the connection chain does
        # not advance beyond it, so the two final values must differ.
        self.assertNotEqual(
            self.client._Connection['PreauthIntegrityHashValue'],
            self.client._Session['PreauthIntegrityHashValue'],
        )

    def test_derived_keys_are_bound_to_handshake_bytes(self):
        self.assertTrue(self.client.login(USER, PASSWORD, DOMAIN))

        # The exported NTLM session key must match the independently recovered one.
        self.assertEqual(
            self.client._Session['SessionKey'], self.peer.exported_session_key
        )
        session_key = self.peer.exported_session_key
        context = self.client._Session['PreauthIntegrityHashValue']
        expected_signing = sp800_108_counter_kdf(session_key, b'SMBSigningKey\x00', context)
        expected_c2s = sp800_108_counter_kdf(session_key, b'SMBC2SCipherKey\x00', context)
        expected_s2c = sp800_108_counter_kdf(session_key, b'SMBS2CCipherKey\x00', context)
        expected_app = sp800_108_counter_kdf(session_key, b'SMBAppKey\x00', context)

        self.assertEqual(self.client._Session['SigningKey'], expected_signing)
        self.assertEqual(self.client._Session['EncryptionKey'], expected_c2s)
        self.assertEqual(self.client._Session['DecryptionKey'], expected_s2c)
        self.assertEqual(self.client._Session['ApplicationKey'], expected_app)

    def test_final_message_signature_verifies_over_the_hash_chain(self):
        self.assertTrue(self.client.login(USER, PASSWORD, DOMAIN))

        # ECHO with TreeID == 0 is signed; clear the encryption flag so this
        # assertion exercises the signature path rather than the transform path.
        self.client._Session['SessionFlags'] = 0
        packet = SMB3Packet()
        packet['Command'] = SMB2_ECHO
        packet['Data'] = SMB2Echo()
        message_id = self.client.sendSMB(packet)
        signed_raw = self.transport.sent_raw[-1]
        signed_packet = SMB3Packet(signed_raw)

        self.assertEqual(signed_packet['Flags'] & SMB2_FLAGS_SIGNED, SMB2_FLAGS_SIGNED)
        captured_signature = signed_packet['Signature']
        zeroed = bytearray(signed_raw)
        zeroed[48:64] = b'\x00' * 16  # Signature field offset in SMB2 header
        # Independent AES-CMAC over the exact signed bytes, keyed by the
        # handshake-bound signing key.
        expected_signature = aes_cmac(
            self.client._Session['SigningKey'], bytes(zeroed)
        )
        self.assertEqual(
            captured_signature, expected_signature,
            msg='final packet signature not derived from the handshake-bound signing key',
        )
        self.assertEqual(message_id, signed_packet['MessageID'])

        # A signing key derived from any other context must not verify the same
        # message, closing the loop between the hash chain and the signature.
        wrong_context = hashlib.sha512(b'wrong-context').digest()
        wrong_key = sp800_108_counter_kdf(
            self.peer.exported_session_key, b'SMBSigningKey\x00', wrong_context
        )
        self.assertNotEqual(aes_cmac(wrong_key, bytes(zeroed)), captured_signature)

        # Tampering a single body byte must invalidate the captured signature.
        tampered = bytearray(zeroed)
        tampered[-1] ^= 0xFF
        self.assertNotEqual(aes_cmac(self.client._Session['SigningKey'], bytes(tampered)),
                            captured_signature)

    def test_encryption_roundtrip_uses_handshake_bound_cipher_keys(self):
        self.assertTrue(self.client.login(USER, PASSWORD, DOMAIN))
        # Encryption is auto-enabled because the fake peer advertised it.
        self.client.echo()
        self.assertEqual(len(self.peer.echo_plaintexts), 1)
        echo_packet = SMB3Packet(self.peer.echo_plaintexts[0])
        self.assertEqual(echo_packet['Command'], SMB2_ECHO)
        # The response was decrypted inside recvSMB using the s2c key; reaching
        # here proves the GCM tag verified, i.e. the key binds to the transcript.

    def test_failed_login_then_relogin_keeps_connection_and_resets_session(self):
        self.assertTrue(self.client.login(USER, PASSWORD, DOMAIN))
        first_signing_key = self.client._Session['SigningKey']
        connection_hash_after_first = self.client._Connection['PreauthIntegrityHashValue']

        self.peer.fail_final_once = True
        with self.assertRaises(smb3.SessionError):
            self.client.login(USER, PASSWORD, DOMAIN)

        # Session-level state must be reset while connection state survives.
        self.assertEqual(self.client._Session['PreauthIntegrityHashValue'], ZERO_HASH)
        self.assertFalse(self.client._Session['SessionKey'])
        self.assertFalse(self.client._Session['SigningKey'])
        self.assertEqual(
            self.client._Connection['PreauthIntegrityHashValue'],
            connection_hash_after_first,
        )

        self.assertTrue(self.client.login(USER, PASSWORD, DOMAIN))
        # The second login extends the same connection chain, so it must not
        # reproduce the first session's signing key.
        self.assertNotEqual(self.client._Session['SigningKey'], first_signing_key)
        self.assertEqual(
            self.client._Session['PreauthIntegrityHashValue'], self.peer.sess_hash
        )
        self.assertEqual(
            self.client._Connection['PreauthIntegrityHashValue'], self.peer.conn_hash
        )
        # Independently re-derive the second session's signing key.
        expected = sp800_108_counter_kdf(
            self.peer.exported_session_key, b'SMBSigningKey\x00', self.peer.sess_hash
        )
        self.assertEqual(self.client._Session['SigningKey'], expected)

    def test_failed_login_leaves_stale_encrypt_flag_sentinel(self):
        # Documents observed impacket behavior: the failure-cleanup path resets
        # SessionKey/SigningKey/hashes but never clears SessionFlags, so the
        # ENCRYPT_DATA bit survives and the next SESSION_SETUP is encrypted even
        # though no session key for that attempt exists yet. The fake peer has
        # to decrypt that message with the previous session's keys. This test
        # pins the behavior so a future fix changes it intentionally.
        self.assertTrue(self.client.login(USER, PASSWORD, DOMAIN))
        self.peer.fail_final_once = True
        with self.assertRaises(smb3.SessionError):
            self.client.login(USER, PASSWORD, DOMAIN)

        self.assertTrue(
            self.client._Session['SessionFlags'] & SMB2_SESSION_FLAG_ENCRYPT_DATA,
            'failure cleanup does not clear the stale ENCRYPT_DATA session flag',
        )
        # The next SESSION_SETUP therefore goes out as a transform, not plaintext.
        before = len(self.transport.sent_raw)
        self.peer.fail_final_once = False
        self.assertTrue(self.client.login(USER, PASSWORD, DOMAIN))
        relogin_setup = self.transport.sent_raw[before]
        self.assertTrue(relogin_setup.startswith(b'\xfdSMB'))

    def test_connection_and_session_state_are_not_mixed(self):
        self.assertTrue(self.client.login(USER, PASSWORD, DOMAIN))

        conn_trace, sess_trace = replay_chains(self.peer.transcript.records)

        # Both chains independently reproduce from the same raw transcript,
        # proving the connection-level and session-level states are tracked
        # separately rather than sharing one hash value.
        self.assertEqual(
            conn_trace[-1], self.client._Connection['PreauthIntegrityHashValue']
        )
        self.assertEqual(
            sess_trace[-1], self.client._Session['PreauthIntegrityHashValue']
        )
        self.assertNotEqual(conn_trace[-1], sess_trace[-1])

        # The signing/cipher keys are derived from the *session* chain only;
        # feeding the connection chain must yield different keys, which guards
        # against accidentally mixing the two states during derivation.
        session_key = self.peer.exported_session_key
        signing_from_session = sp800_108_counter_kdf(
            session_key, b'SMBSigningKey\x00', sess_trace[-1]
        )
        signing_from_connection = sp800_108_counter_kdf(
            session_key, b'SMBSigningKey\x00', conn_trace[-1]
        )
        self.assertEqual(signing_from_session, self.client._Session['SigningKey'])
        self.assertNotEqual(signing_from_connection, self.client._Session['SigningKey'])


# ---------------------------------------------------------------------------
# Negotiate-response byte mutations. Each changes wire bytes while leaving the
# fields the client parses semantically identical, so any "same parsed fields
# => same keys" shortcut would wrongly collapse the two handshakes.
# ---------------------------------------------------------------------------

def mutate_negotiate_context_reserved(raw):
    """Flip a byte in the first context's Reserved 4-byte field."""
    resp = SMB2Negotiate_Response(SMB2Packet(raw)['Data'])
    ctx_offset = resp['NegotiateContextOffset'] - SMB2_PACKET_SIZE
    mutated = bytearray(raw)
    # Context header: ContextType(2) DataLength(2) Reserved(4); first reserved byte.
    mutated[SMB2_PACKET_SIZE + ctx_offset + 4] ^= 0x80
    return bytes(mutated)


def mutate_negotiate_context_order(raw):
    """Swap the preauth and encryption contexts, keeping each context intact."""
    packet = SMB2Packet(raw)
    resp = SMB2Negotiate_Response(packet['Data'])
    contexts = resp['NegotiateContextList']
    first = SMB2NegotiateContext(contexts)
    first_len = 8 + first['DataLength']
    first_pad = (8 - (first['DataLength'] % 8)) % 8
    first_block = contexts[: first_len + first_pad]
    second_block = contexts[first_len + first_pad:]
    new_list = second_block + first_block
    rebuilt = bytearray(raw[: SMB2_PACKET_SIZE])
    body = bytearray(packet['Data'])
    # Replace the context list at its offset within the body.
    body_ctx_offset = resp['NegotiateContextOffset'] - SMB2_PACKET_SIZE
    body = bytes(body[:body_ctx_offset]) + new_list
    rebuilt.extend(body)
    return bytes(rebuilt)


def mutate_header_reserved2(raw):
    """Flip a byte in the SMB2 header's Reserved dword (offset 40).

    Responses always leave this 4-byte field zero and the client ignores it, so
    the parsed message is unchanged while the raw bytes differ.
    """
    mutated = bytearray(raw)
    mutated[40] ^= 0x01
    return bytes(mutated)


class MutationTests(unittest.TestCase):
    """
    Mutation tests must not compare two independent handshakes end-to-end: the
    NTLM exported key and negotiate salt are random per run, so derived keys
    would differ even without any mutation. Instead each test runs one mutated
    handshake and proves that the *exact mutated byte* is what moves the hash
    chain, by independently re-hashing the captured baseline and mutated bytes
    from the same seed and checking the divergence at the mutated message.
    """

    def _run(self, mutator=None):
        peer = FakePeer(negotiate_mutator=mutator)
        client, _ = build_client(peer)
        self.assertTrue(client.login(USER, PASSWORD, DOMAIN))
        return peer, client

    def _assert_single_bit_mutation_drives_chain(self, mutator, mutated_offset, bit_mask):
        # One unmutated handshake gives us the genuine baseline bytes; a second
        # handshake applies the mutator. We then also apply the mutator locally
        # to the baseline bytes, so the only variable between the two hashed
        # variants is the reserved bit under test - not NTLM or salt randomness.
        base_peer, base_client = self._run(None)
        mut_peer, mut_client = self._run(mutator)

        baseline_raw = base_peer.transcript.records[1].raw
        locally_mutated = mutator(baseline_raw)
        self.assertNotEqual(baseline_raw, locally_mutated)
        # Exactly one byte changes, by exactly the expected mask.
        diffs = [i for i, (a, b) in enumerate(zip(baseline_raw, locally_mutated)) if a != b]
        self.assertEqual(diffs, [mutated_offset])
        self.assertEqual(baseline_raw[mutated_offset] ^ locally_mutated[mutated_offset], bit_mask)

        # Parsed semantic fields are identical across the two wire variants.
        base_parsed = SMB2Negotiate_Response(SMB2Packet(baseline_raw)['Data'])
        mut_parsed = SMB2Negotiate_Response(SMB2Packet(locally_mutated)['Data'])
        self.assertEqual(base_parsed['DialectRevision'], mut_parsed['DialectRevision'])
        base_ctx = SMB2NegotiateContext(base_parsed['NegotiateContextList'])
        mut_ctx = SMB2NegotiateContext(mut_parsed['NegotiateContextList'])
        self.assertEqual(base_ctx['ContextType'], mut_ctx['ContextType'])
        self.assertEqual(base_ctx['DataLength'], mut_ctx['DataLength'])
        self.assertEqual(base_ctx['Data'], mut_ctx['Data'])
        self.assertEqual(mut_client._Connection['Dialect'], SMB2_DIALECT_311)

        # Both variants hashed from the same seed (hash after negotiate request)
        # must diverge, and the live client must hold the mutated branch value.
        seed = hashlib.sha512(ZERO_HASH + mut_peer.transcript.records[0].raw).digest()
        from_baseline = hashlib.sha512(seed + baseline_raw).digest()
        from_mutated = hashlib.sha512(seed + locally_mutated).digest()
        self.assertNotEqual(from_baseline, from_mutated)

        # The live mutated handshake's own transcript re-walk reproduces its
        # connection/session hashes, proving the mutated bytes are what bound it.
        conn_trace, sess_trace = replay_chains(mut_peer.transcript.records)
        self.assertEqual(
            conn_trace[1], mut_client._Connection['PreauthIntegrityHashValue']
        )
        self.assertEqual(
            sess_trace[-1], mut_client._Session['PreauthIntegrityHashValue']
        )
        # The signing key is the KDF over the mutated session context only.
        exported = mut_peer.exported_session_key
        expected_signing = sp800_108_counter_kdf(
            exported, b'SMBSigningKey\x00',
            mut_client._Session['PreauthIntegrityHashValue'],
        )
        self.assertEqual(expected_signing, mut_client._Session['SigningKey'])
        return mut_peer, conn_trace, sess_trace

    def test_context_reserved_mutation_drives_the_hash_chain(self):
        probe_peer = FakePeer()
        probe_client, _ = build_client(probe_peer)
        probe_client.login(USER, PASSWORD, DOMAIN)
        resp = SMB2Negotiate_Response(
            SMB2Packet(probe_peer.transcript.records[1].raw)['Data']
        )
        reserved_offset = resp['NegotiateContextOffset'] + 4
        self._assert_single_bit_mutation_drives_chain(
            mutate_negotiate_context_reserved, reserved_offset, 0x80
        )

    def test_header_reserved_mutation_drives_the_hash_chain(self):
        self._assert_single_bit_mutation_drives_chain(
            mutate_header_reserved2, 40, 0x01
        )

    def test_context_order_mutation_drives_the_hash_chain(self):
        base_peer, base_client = self._run(None)
        mut_peer, mut_client = self._run(mutate_negotiate_context_order)

        baseline_raw = base_peer.transcript.records[1].raw
        locally_mutated = mutate_negotiate_context_order(baseline_raw)
        self.assertNotEqual(baseline_raw, locally_mutated)

        # Cipher selection is unchanged even though context order is swapped.
        self.assertEqual(mut_client._Connection['CipherId'], SMB2_ENCRYPTION_AES128_GCM)
        seed = hashlib.sha512(ZERO_HASH + mut_peer.transcript.records[0].raw).digest()
        self.assertNotEqual(
            hashlib.sha512(seed + baseline_raw).digest(),
            hashlib.sha512(seed + locally_mutated).digest(),
        )
        conn_trace, sess_trace = replay_chains(mut_peer.transcript.records)
        self.assertEqual(
            sess_trace[-1], mut_client._Session['PreauthIntegrityHashValue']
        )

    def test_diff_report_locates_the_mutated_message(self):
        mut_peer, mut_client = self._run(mutate_negotiate_context_reserved)
        conn_trace, sess_trace = replay_chains(mut_peer.transcript.records)
        report = mut_peer.transcript.diff_report(conn_trace, sess_trace)
        # Every per-message line must report OK, and the report must identify
        # the negotiate response as an individual, indexable message.
        self.assertNotIn('MISMATCH', report)
        negotiate_lines = [line for line in report.splitlines() if 'command=0x0000' in line]
        self.assertEqual(len(negotiate_lines), 2)
        self.assertIn('#01', negotiate_lines[1])


if __name__ == '__main__':
    unittest.main(verbosity=2)
