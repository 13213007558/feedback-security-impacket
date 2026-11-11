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
import unittest

from Cryptodome.Cipher import AES

from impacket.nt_errors import STATUS_DECRYPTION_FAILED, STATUS_CS_ENCRYPTION_INVALID_SERVER_RESPONSE
from impacket.smb3 import SMB3, SessionError
from impacket.smb3structs import SMB2_DIALECT_30, SMB2_DIALECT_311, SMB2_READ, SMB2Packet, SMB3Packet, \
    SMB2_TRANSFORM_HEADER, SMB2_ENCRYPTION_AES128_CCM, SMB2_ENCRYPTION_AES128_GCM, \
    SMB2_SESSION_FLAG_ENCRYPT_DATA
from impacket.nt_errors import STATUS_PENDING, STATUS_SUCCESS

SESSION_ID = 0x0000000040000005
KEY = b'\x11' * 16
NONCE = b'\x22' * 16


class _FakePacket(object):
    def __init__(self, trailer):
        self._trailer = trailer

    def get_trailer(self):
        return self._trailer


class _FakeTransport(object):
    """Feeds pre-built packets into SMB3.recvSMB and records what sendSMB emits."""

    def __init__(self, packets=()):
        self.received = list(packets)
        self.sent = []

    def recv_packet(self, timeout):
        if not self.received:
            raise AssertionError('recvSMB asked for more packets than queued')
        return _FakePacket(self.received.pop(0))

    def send_packet(self, data):
        self.sent.append(data)


def _smb2_response(message_id, tree_id=1, session_id=SESSION_ID, status=STATUS_SUCCESS, credit_charge=1):
    packet = SMB2Packet()
    packet['Command'] = SMB2_READ
    packet['Status'] = status
    packet['MessageID'] = message_id
    packet['TreeID'] = tree_id
    packet['SessionID'] = session_id
    packet['CreditCharge'] = credit_charge
    packet['Flags'] = 1  # SMB2_FLAGS_SERVER_TO_REDIR
    return packet.getData()


def _transform_message(payload, key=KEY, session_id=SESSION_ID, cipher_id=SMB2_ENCRYPTION_AES128_CCM,
                       original_size=None, reserved=0, algorithm=SMB2_ENCRYPTION_AES128_CCM):
    transformHeader = SMB2_TRANSFORM_HEADER()
    transformHeader['Nonce'] = NONCE
    transformHeader['OriginalMessageSize'] = len(payload) if original_size is None else original_size
    transformHeader['Reserved'] = reserved
    transformHeader['EncryptionAlgorithm'] = algorithm
    transformHeader['SessionID'] = session_id
    if cipher_id == SMB2_ENCRYPTION_AES128_GCM:
        cipher = AES.new(key, AES.MODE_GCM, NONCE[:12])
    else:
        cipher = AES.new(key, AES.MODE_CCM, NONCE[:11])
    cipher.update(transformHeader.getData()[20:])
    cipherText = cipher.encrypt(payload)
    transformHeader['Signature'] = cipher.digest()
    return transformHeader.getData() + cipherText


class SMB3RecvTransformTests(unittest.TestCase):

    @staticmethod
    def create_client(packets=(), session_flags=0, cipher_id=0, dialect=SMB2_DIALECT_30):
        client = object.__new__(SMB3)
        client._Connection = {
            'Dialect': dialect,
            'CipherId': cipher_id,
            'OutstandingRequests': {},
            'OutstandingResponses': {},
            'SequenceWindow': 10,
        }
        client._Session = {
            'SessionID': SESSION_ID,
            'SessionFlags': session_flags,
            'TreeConnectTable': {
                1: {'EncryptData': True},
                2: {'EncryptData': False},
            },
            'EncryptionKey': KEY,
            'DecryptionKey': KEY,
            'SigningActivated': False,
            'CalculatePreAuthHash': False,
        }
        client.SMB_PACKET = SMB3Packet
        client._timeout = 1
        client._NetBIOSSession = _FakeTransport(packets)
        return client

    def assert_decryption_failed(self, client, packet_id=1):
        with self.assertRaises(SessionError) as ctx:
            client.recvSMB(packet_id)
        self.assertEqual(ctx.exception.error, STATUS_DECRYPTION_FAILED)
        # The failed packet must not be dispatched or leave stale request state
        self.assertEqual(client._Connection['OutstandingResponses'], {})
        self.assertNotIn(packet_id, client._Connection['OutstandingRequests'])

    def test_valid_ccm_encrypted_response(self):
        client = self.create_client([_transform_message(_smb2_response(1))])
        client._Connection['OutstandingRequests'][1] = {'EncryptData': True}

        packet = client.recvSMB(1)

        self.assertEqual(packet['Status'], STATUS_SUCCESS)
        self.assertEqual(packet['MessageID'], 1)
        self.assertEqual(client._Connection['OutstandingRequests'], {})
        self.assertEqual(client._Connection['OutstandingResponses'], {})

    def test_valid_gcm_encrypted_response(self):
        client = self.create_client(
            [_transform_message(_smb2_response(1), cipher_id=SMB2_ENCRYPTION_AES128_GCM)],
            cipher_id=SMB2_ENCRYPTION_AES128_GCM, dialect=SMB2_DIALECT_311)
        client._Connection['OutstandingRequests'][1] = {'EncryptData': True}

        packet = client.recvSMB(1)

        self.assertEqual(packet['Status'], STATUS_SUCCESS)
        self.assertEqual(packet['MessageID'], 1)

    def test_wrong_session_id_rejected(self):
        client = self.create_client([_transform_message(_smb2_response(1), session_id=SESSION_ID + 1)])
        client._Connection['OutstandingRequests'][1] = {'EncryptData': True}
        self.assert_decryption_failed(client)

    def test_original_message_size_mismatch_rejected(self):
        client = self.create_client(
            [_transform_message(_smb2_response(1), original_size=len(_smb2_response(1)) + 1)])
        client._Connection['OutstandingRequests'][1] = {'EncryptData': True}
        self.assert_decryption_failed(client)

    def test_reserved_field_rejected(self):
        client = self.create_client([_transform_message(_smb2_response(1), reserved=1)])
        client._Connection['OutstandingRequests'][1] = {'EncryptData': True}
        self.assert_decryption_failed(client)

    def test_unexpected_algorithm_field_rejected(self):
        client = self.create_client(
            [_transform_message(_smb2_response(1), algorithm=SMB2_ENCRYPTION_AES128_GCM)])
        client._Connection['OutstandingRequests'][1] = {'EncryptData': True}
        self.assert_decryption_failed(client)

    def test_truncated_header_and_tag_rejected(self):
        full = _transform_message(_smb2_response(1))
        # Cut inside the 16-byte Signature (tag) field of the transform header
        truncated = full[:10]
        self.assertTrue(truncated.startswith(b'\xfdSMB'))
        client = self.create_client([truncated])
        client._Connection['OutstandingRequests'][1] = {'EncryptData': True}
        self.assert_decryption_failed(client)

    def test_truncated_ciphertext_rejected(self):
        full = _transform_message(_smb2_response(1))
        client = self.create_client([full[:-4]])
        client._Connection['OutstandingRequests'][1] = {'EncryptData': True}
        self.assert_decryption_failed(client)

    def test_tampered_ciphertext_fails_authentication(self):
        full = bytearray(_transform_message(_smb2_response(1)))
        full[-1] ^= 0xFF
        client = self.create_client([bytes(full)])
        client._Connection['OutstandingRequests'][1] = {'EncryptData': True}
        self.assert_decryption_failed(client)

    def test_tampered_tag_fails_authentication(self):
        full = bytearray(_transform_message(_smb2_response(1)))
        full[6] ^= 0xFF  # inside the Signature field
        client = self.create_client([bytes(full)])
        client._Connection['OutstandingRequests'][1] = {'EncryptData': True}
        self.assert_decryption_failed(client)

    def test_unauthenticated_packet_is_not_dispatched(self):
        # A tampered packet (whose forged inner MessageID can never be trusted)
        # arrives before the valid answer: it must fail, not be stashed.
        tampered = bytearray(_transform_message(_smb2_response(5)))
        tampered[-1] ^= 0xFF
        client = self.create_client([bytes(tampered), _transform_message(_smb2_response(1))])
        client._Connection['OutstandingRequests'][1] = {'EncryptData': True}

        self.assert_decryption_failed(client, packet_id=1)
        self.assertNotIn(5, client._Connection['OutstandingResponses'])

    def test_pending_loop_validates_every_packet(self):
        client = self.create_client([
            _transform_message(_smb2_response(1, status=STATUS_PENDING)),
            _transform_message(_smb2_response(1)),
        ])
        client._Connection['OutstandingRequests'][1] = {'EncryptData': True}

        packet = client.recvSMB(1)

        self.assertEqual(packet['Status'], STATUS_SUCCESS)
        self.assertEqual(client._Connection['OutstandingRequests'], {})

    def test_pending_loop_rejects_tampered_final_response(self):
        tampered = bytearray(_transform_message(_smb2_response(1)))
        tampered[-1] ^= 0xFF
        client = self.create_client([
            _transform_message(_smb2_response(1, status=STATUS_PENDING)),
            bytes(tampered),
        ])
        client._Connection['OutstandingRequests'][1] = {'EncryptData': True}
        self.assert_decryption_failed(client)

    def test_plaintext_rejected_when_session_requires_encryption(self):
        client = self.create_client([_smb2_response(1, tree_id=2)],
                                    session_flags=SMB2_SESSION_FLAG_ENCRYPT_DATA)
        client._Connection['OutstandingRequests'][1] = {'EncryptData': True}

        with self.assertRaises(SessionError) as ctx:
            client.recvSMB(1)
        self.assertEqual(ctx.exception.error, STATUS_CS_ENCRYPTION_INVALID_SERVER_RESPONSE)
        self.assertEqual(client._Connection['OutstandingResponses'], {})
        self.assertNotIn(1, client._Connection['OutstandingRequests'])

    def test_plaintext_rejected_for_share_requiring_encryption(self):
        # The request went to an encrypted share (recorded at send time); a
        # plaintext answer must not be accepted even though it parses fine.
        client = self.create_client([_smb2_response(1, tree_id=1)])
        client._Connection['OutstandingRequests'][1] = {'EncryptData': True}

        with self.assertRaises(SessionError) as ctx:
            client.recvSMB(1)
        self.assertEqual(ctx.exception.error, STATUS_CS_ENCRYPTION_INVALID_SERVER_RESPONSE)

    def test_plaintext_rejected_for_encrypted_tree_id(self):
        # Defense in depth: even without per-request state, a plaintext packet
        # claiming a TreeID whose share requires encryption is rejected.
        client = self.create_client([_smb2_response(1, tree_id=1)])

        with self.assertRaises(SessionError) as ctx:
            client.recvSMB(1)
        self.assertEqual(ctx.exception.error, STATUS_CS_ENCRYPTION_INVALID_SERVER_RESPONSE)

    def test_plaintext_allowed_for_normal_share(self):
        client = self.create_client([_smb2_response(1, tree_id=2)])
        client._Connection['OutstandingRequests'][1] = {'EncryptData': False}

        packet = client.recvSMB(1)

        self.assertEqual(packet['Status'], STATUS_SUCCESS)
        self.assertEqual(packet['TreeID'], 2)
        self.assertEqual(client._Connection['OutstandingRequests'], {})

    def test_send_marks_request_encryption_state(self):
        client = self.create_client()

        packet = SMB3Packet()
        packet['Command'] = SMB2_READ
        packet['TreeID'] = 1
        message_id = client.sendSMB(packet)

        sent = client._NetBIOSSession.sent[0]
        self.assertTrue(sent.startswith(b'\xfdSMB'))
        self.assertEqual(client._Connection['OutstandingRequests'][message_id], {'EncryptData': True})

        packet = SMB3Packet()
        packet['Command'] = SMB2_READ
        packet['TreeID'] = 2
        message_id = client.sendSMB(packet)

        sent = client._NetBIOSSession.sent[1]
        self.assertTrue(sent.startswith(b'\xfeSMB'))
        self.assertEqual(client._Connection['OutstandingRequests'][message_id], {'EncryptData': False})


if __name__ == '__main__':
    unittest.main(verbosity=1)
