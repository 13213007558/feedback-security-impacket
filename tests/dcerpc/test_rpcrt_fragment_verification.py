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
#   Local, fully offline tests proving that the DCE/RPC v5 receive path
#   authenticates every fragment of a multi-fragment call independently.
#   Legitimate packet integrity and packet privacy traffic is produced by the
#   real DCERPC_v5.send() fragmentation/sealing path with deterministic local
#   test keys, then driven through the real DCERPC_v5.recv() reassembly path via
#   an in-memory controllable transport (no sockets, no remote endpoint).
#
import struct

import pytest
from Cryptodome.Cipher import ARC4

from impacket import ntlm
from impacket.dcerpc.v5.rpcrt import (
    DCERPC_v5,
    DCERPC_RawCall,
    DCERPCVerificationError,
    MSRPCRespHeader,
    PFC_FIRST_FRAG,
    PFC_LAST_FRAG,
    RPC_C_AUTHN_LEVEL_PKT_INTEGRITY,
    RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
    RPC_C_AUTHN_WINNT,
    SEC_TRAILER,
)

# NTLMv2 (extended session security) session security negotiation flags.
NTLM2_FLAGS = (
    ntlm.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY
    | ntlm.NTLMSSP_NEGOTIATE_128
    | ntlm.NTLMSSP_NEGOTIATE_KEY_EXCH
    | ntlm.NTLMSSP_NEGOTIATE_NTLM
    | ntlm.NTLMSSP_NEGOTIATE_SIGN
    | ntlm.NTLMSSP_NEGOTIATE_SEAL
)
# Deterministic local test key; never used outside this module.
SESSION_KEY = b"0123456789abcdef"
OP_NUM = 7
PAYLOAD = b"".join(bytes((i,)) * 17 for i in range(256))[:358]
# 358-byte payload at a 120-byte user fragment size yields exactly 3 fragments;
# the last fragment carries 2 bytes of auth padding, which lets us prove padding
# never leaks into the delivered stub.
FRAGMENT_SIZE = 120
# 122 is not a multiple of 4, so every fragment (including middle ones) carries
# auth padding; used by the auth-padding tampering test.
PADDED_FRAGMENT_SIZE = 122
EXPECTED_FRAGMENTS = 3


class RecordingTransport:
    """Transport that keeps every wire fragment the sender emits."""

    def __init__(self):
        self.sent = []

    def send(self, data, forceWriteAndx=0, forceRecv=0):
        self.sent.append(bytes(data))

    def recv(self, forceRecv=0, count=0):
        raise RuntimeError("recording transport never receives")


class ControlledTransport:
    """
    Transport feeding pre-queued, discrete PDU fragments to the real recv()
    path, mirroring how the TCP/SMB transports return at least a full fragment
    per read. It records how many fragments were handed to the receiver so
    tests can prove a rejection stopped consumption at the offending fragment.
    """

    def __init__(self, chunks=None):
        self._chunks = list(chunks) if chunks is not None else []
        self.delivered = 0
        self.read_calls = 0

    def queue(self, chunks):
        self._chunks.extend(chunks)

    def send(self, data=0, forceWriteAndx=0, forceRecv=0):
        pass

    def recv(self, forceRecv=0, count=0):
        if not self._chunks:
            raise RuntimeError("controlled transport exhausted")
        self.read_calls += 1
        chunk = self._chunks.pop(0)
        self.delivered += len(chunk)
        return chunk


class ByteStreamTransport:
    """
    Transport that serves the queued stream in arbitrary-sized chunks,
    exercising the partial-read reassembly loop of the real recv() path. It
    buffers surplus bytes like a real TCP socket would, so recv(count) always
    returns at most count octets while preserving the full byte stream.
    """

    def __init__(self, stream, chunk_size):
        self._stream = bytearray(stream)
        self._chunk_size = chunk_size
        self._buffer = bytearray()
        self.delivered = 0

    def send(self, data=0, forceWriteAndx=0, forceRecv=0):
        pass

    def recv(self, forceRecv=0, count=0):
        while not self._buffer or (count and len(self._buffer) < count):
            if not self._stream:
                break
            size = min(self._chunk_size, len(self._stream))
            self._buffer.extend(self._stream[:size])
            del self._stream[:size]
        if not self._buffer:
            raise RuntimeError("byte stream transport exhausted")
        size = len(self._buffer) if not count else min(count, len(self._buffer))
        chunk = bytes(self._buffer[:size])
        del self._buffer[:size]
        self.delivered += len(chunk)
        return chunk


def _new_dce(transport, auth_level):
    dce = DCERPC_v5(transport)
    dce.set_auth_type(RPC_C_AUTHN_WINNT)
    dce.set_auth_level(auth_level)
    dce._ctx = 0
    return dce


def _install_client_material(dce):
    dce._DCERPC_v5__flags = NTLM2_FLAGS
    dce._DCERPC_v5__sessionKey = SESSION_KEY
    dce._DCERPC_v5__clientSigningKey = ntlm.SIGNKEY(NTLM2_FLAGS, SESSION_KEY)
    dce._DCERPC_v5__clientSealingKey = ntlm.SEALKEY(NTLM2_FLAGS, SESSION_KEY)
    dce._DCERPC_v5__clientSealingHandle = ARC4.new(
        dce._DCERPC_v5__clientSealingKey
    ).encrypt
    dce._DCERPC_v5__max_xmit_size = 4280
    dce._DCERPC_v5__callid = 1


def build_fragments(auth_level, payload=PAYLOAD, call_id=1,
                    fragment_size=FRAGMENT_SIZE, start_sequence=0):
    """Runs the genuine send() fragmentation/signing path and returns wire bytes.

    start_sequence mirrors MS-RPCE connection-level sequence numbering: each
    authenticated PDU consumes one sequence number across the whole association,
    so later calls start where the previous call ended.
    """
    transport = RecordingTransport()
    sender = _new_dce(transport, auth_level)
    _install_client_material(sender)
    sender._DCERPC_v5__callid = call_id
    sender._DCERPC_v5__sequence = start_sequence
    sender.set_max_fragment_size(fragment_size)
    sender.send(DCERPC_RawCall(OP_NUM, payload))
    assert len(transport.sent) == EXPECTED_FRAGMENTS
    return transport.sent


def build_connection_sender(auth_level, fragment_size=FRAGMENT_SIZE):
    """
    A single long-lived DCERPC_v5 sender, exactly as a real client uses one
    across many calls. Its RC4 sealing stream and sequence counter therefore
    evolve continuously across every emitted fragment and call.
    """
    transport = RecordingTransport()
    sender = _new_dce(transport, auth_level)
    _install_client_material(sender)
    sender.set_max_fragment_size(fragment_size)
    return sender, transport


def emit_call(sender, transport, payload, call_id):
    transport.sent.clear()
    sender._DCERPC_v5__callid = call_id
    sender.send(DCERPC_RawCall(OP_NUM, payload))
    assert len(transport.sent) == EXPECTED_FRAGMENTS
    return list(transport.sent)


def build_receiver(auth_level, chunks=None):
    transport = ControlledTransport(chunks)
    receiver = _new_dce(transport, auth_level)
    receiver.configure_inbound_ntlm_session(NTLM2_FLAGS, SESSION_KEY)
    receiver.set_inbound_verification(True)
    return receiver, transport


def fragment_views(fragments):
    """Parsed (header, sec_trailer offsets) helpers for each wire fragment."""
    views = []
    for fragment in fragments:
        header = MSRPCRespHeader(fragment)
        header_size = header.get_header_size()
        auth_total = header["auth_len"] + 8
        trailer_offset = len(fragment) - auth_total
        views.append(
            {
                "header": header,
                "header_size": header_size,
                "auth_total": auth_total,
                "trailer_offset": trailer_offset,
                "signature_offset": trailer_offset + 8,
            }
        )
    return views


def resign_fragment(fragment, auth_level, sequence, seal_offset=0):
    """
    Re-signs an otherwise-modified fragment with the local test key, so tests
    can target structural/state-machine checks that must sit in front of the
    MAC comparison instead of being masked by an inevitable signature failure.
    seal_offset is the fragment's position in the continuous RC4 sealing stream.
    """
    header = MSRPCRespHeader(fragment)
    auth_total = header["auth_len"] + 8
    sealing_key = ntlm.SEALKEY(NTLM2_FLAGS, SESSION_KEY)
    signing_key = ntlm.SIGNKEY(NTLM2_FLAGS, SESSION_KEY)
    sign_handle = ARC4.new(sealing_key).encrypt

    if auth_level == RPC_C_AUTHN_LEVEL_PKT_INTEGRITY:
        signed_blob = fragment[: len(fragment) - auth_total] + fragment[
            len(fragment) - auth_total: len(fragment) - auth_total + 8
        ]
        signature = ntlm.SIGN(
            NTLM2_FLAGS, signing_key, signed_blob, sequence, sign_handle,
        )
    else:
        header_size = header.get_header_size()
        sealed = fragment[header_size: len(fragment) - auth_total]
        decrypt_handle = ARC4.new(sealing_key).encrypt
        decrypt_handle(b"\x00" * seal_offset)
        plaintext = decrypt_handle(sealed)
        signed_blob = (
            fragment[:header_size]
            + plaintext
            + fragment[
                len(fragment) - auth_total: len(fragment) - auth_total + 8
            ]
        )
        signature = ntlm.SIGN(
            NTLM2_FLAGS, signing_key, signed_blob, sequence, sign_handle,
        )
    return fragment[: len(fragment) - 16] + signature.getData()


AUTH_LEVELS = (
    pytest.param(RPC_C_AUTHN_LEVEL_PKT_INTEGRITY, id="integrity"),
    pytest.param(RPC_C_AUTHN_LEVEL_PKT_PRIVACY, id="privacy"),
)


@pytest.mark.parametrize("auth_level", AUTH_LEVELS)
class TestFragmentedCallVerification:
    def test_legitimate_call_reassembles_exact_plaintext(self, auth_level):
        fragments = build_fragments(auth_level)
        receiver, transport = build_receiver(auth_level, fragments)
        plaintext = receiver.recv()
        assert plaintext == PAYLOAD
        # Every queued byte belongs to this single call and was consumed once.
        assert transport.delivered == sum(len(f) for f in fragments)

    def test_each_fragment_carries_its_own_verifier(self, auth_level):
        fragments = build_fragments(auth_level)
        views = fragment_views(fragments)
        for index, view in enumerate(views):
            header = view["header"]
            assert header["auth_len"] == 16
            trailer = SEC_TRAILER(
                data=fragments[index][view["trailer_offset"]:]
            )
            assert trailer["auth_type"] == RPC_C_AUTHN_WINNT
            assert trailer["auth_level"] == auth_level
        # FIRST only on fragment 0, LAST only on the final fragment.
        assert views[0]["header"]["flags"] & PFC_FIRST_FRAG
        assert not (views[1]["header"]["flags"] & PFC_FIRST_FRAG)
        assert not (views[1]["header"]["flags"] & PFC_LAST_FRAG)
        assert views[-1]["header"]["flags"] & PFC_LAST_FRAG
        assert not (views[0]["header"]["flags"] & PFC_LAST_FRAG)

    def test_auth_padding_never_reaches_stub(self, auth_level):
        fragments = build_fragments(auth_level)
        views = fragment_views(fragments)
        trailer = SEC_TRAILER(
            data=fragments[-1][views[-1]["trailer_offset"]:]
        )
        assert trailer["auth_pad_len"] == 2
        receiver, _ = build_receiver(auth_level, fragments)
        plaintext = receiver.recv()
        assert len(plaintext) == len(PAYLOAD)
        assert plaintext == PAYLOAD
        # The padding bytes themselves must not be part of the stub.
        assert not plaintext.endswith(b"\xbb\xbb")

    @pytest.mark.parametrize(
        "tamper",
        [
            "signature",
            "auth_padding",
            "call_id",
            "context_id",
            "first_flag",
            "last_flag",
        ],
    )
    def test_middle_fragment_tampering_is_rejected(self, auth_level, tamper):
        fragments = list(build_fragments(auth_level))
        views = fragment_views(fragments)
        middle = bytearray(fragments[1])
        resign = False

        if tamper == "signature":
            middle[views[1]["signature_offset"]] ^= 0xFF
        elif tamper == "auth_padding":
            # A non-4-aligned fragment size forces auth padding onto the middle
            # fragment; flipping a padding byte must invalidate its MAC.
            fragments = list(build_fragments(
                auth_level, fragment_size=PADDED_FRAGMENT_SIZE))
            views = fragment_views(fragments)
            middle = bytearray(fragments[1])
            pad_len = SEC_TRAILER(
                data=fragments[1][views[1]["trailer_offset"]:]
            )["auth_pad_len"]
            assert pad_len > 0
            padding_start = views[1]["trailer_offset"] - pad_len
            middle[padding_start] ^= 0xFF
        elif tamper == "call_id":
            struct.pack_into("<I", middle, 12, views[1]["header"]["call_id"] + 99)
            resign = True
        elif tamper == "context_id":
            struct.pack_into("<H", middle, 20, views[1]["header"]["ctx_id"] + 1)
            resign = True
        elif tamper == "first_flag":
            middle[3] |= PFC_FIRST_FRAG
            resign = True
        elif tamper == "last_flag":
            # Marking a middle fragment LAST terminates reassembly early: the
            # call ends after only two fragments and its short plaintext cannot
            # match the expected stub. No exception is raised, but the delivered
            # data must be provably wrong and incomplete.
            middle[3] |= PFC_LAST_FRAG
            resign = True

        if resign:
            # Fragment #1 starts after fragment #0's sealed body in the
            # continuous RC4 stream (only relevant for packet privacy).
            first_sealed_len = (views[0]["trailer_offset"]
                                - views[0]["header_size"])
            seal_offset = (first_sealed_len
                           if auth_level == RPC_C_AUTHN_LEVEL_PKT_PRIVACY else 0)
            fragments[1] = resign_fragment(
                bytes(middle), auth_level, 1, seal_offset)
        else:
            fragments[1] = bytes(middle)

        if tamper == "last_flag":
            receiver, transport = build_receiver(auth_level, fragments)
            delivered = receiver.recv()
            assert len(delivered) < len(PAYLOAD)
            assert delivered != PAYLOAD
            # The real final fragment was never consumed.
            assert len(transport._chunks) == 1
            return

        receiver, transport = build_receiver(auth_level, fragments)
        with pytest.raises(DCERPCVerificationError) as excinfo:
            receiver.recv()
        error = excinfo.value
        # The rejection must name fragment #1, never an earlier or later one.
        assert error.fragment_index == 1
        assert error.reason
        # No stub is delivered by recv(); only fragments 0 and 1 were consumed.
        assert transport.delivered == len(fragments[0]) + len(fragments[1])
        # Fragment #2 was never read, so its bytes remain queued on the wire.
        assert sum(len(f) for f in fragments[2:]) > 0

    def test_valid_final_fragment_cannot_launder_failed_middle(self, auth_level):
        fragments = list(build_fragments(auth_level))
        views = fragment_views(fragments)
        corrupted = bytearray(fragments[1])
        corrupted[views[1]["signature_offset"] + 4] ^= 0x01
        fragments[1] = bytes(corrupted)

        receiver, transport = build_receiver(auth_level, fragments)
        with pytest.raises(DCERPCVerificationError) as excinfo:
            receiver.recv()
        assert excinfo.value.fragment_index == 1
        assert transport.delivered == len(fragments[0]) + len(fragments[1])
        # A second recv() must not return the remainder of the broken call.
        with pytest.raises(DCERPCVerificationError):
            receiver.recv()

    def test_distinct_calls_are_never_concatenated(self, auth_level):
        first_payload = bytes((i * 7) % 256 for i in range(358))
        second_payload = bytes((i * 13 + 5) % 256 for i in range(358))
        assert len(first_payload) == len(PAYLOAD)
        # One real sender instance: continuous RC4 stream and sequence numbers
        # across both calls, exactly like a long-lived client connection.
        sender, transport = build_connection_sender(auth_level)
        first = emit_call(sender, transport, first_payload, call_id=1)
        second = emit_call(sender, transport, second_payload, call_id=2)

        receiver, recv_transport = build_receiver(
            auth_level, list(first) + list(second))
        first_plain = receiver.recv()
        second_plain = receiver.recv()
        assert first_plain == first_payload
        assert second_plain == second_payload
        assert first_plain != second_plain
        assert second_payload not in first_plain
        assert first_payload not in second_plain
        assert recv_transport.delivered == sum(map(len, first + second))

    def test_call_id_swap_between_calls_is_rejected(self, auth_level):
        sender, transport = build_connection_sender(auth_level)
        first = emit_call(sender, transport, PAYLOAD, call_id=1)
        second = emit_call(sender, transport, PAYLOAD, call_id=2)
        # Reuse the first call's id on the second call without re-signing.
        for index, fragment in enumerate(second):
            edited = bytearray(fragment)
            struct.pack_into("<I", edited, 12, 1)
            second[index] = bytes(edited)

        receiver, _ = build_receiver(auth_level, list(first) + second)
        assert receiver.recv() == PAYLOAD
        with pytest.raises(DCERPCVerificationError) as excinfo:
            receiver.recv()
        # The tampered call_id changes the signed blob, so fragment #0 of the
        # new call fails its MAC before the state machine even advances.
        assert excinfo.value.fragment_index == 0

    def test_connection_serves_next_call_after_a_rejected_call(self, auth_level):
        # A long-lived sender and receiver share one continuous sequence/RC4
        # association. Corrupt the FIRST fragment of call one: the rejection
        # happens before any sequence number or RC4 byte is consumed, so the
        # association stays at its initial state and a conforming retry (same
        # starting sequence, fresh stream) is accepted on the same connection.
        sender, transport = build_connection_sender(auth_level)
        first = list(emit_call(sender, transport, PAYLOAD, call_id=1))
        views = fragment_views(first)
        corrupted = bytearray(first[0])
        corrupted[views[0]["signature_offset"]] ^= 0xAA
        first[0] = bytes(corrupted)

        receiver, recv_transport = build_receiver(auth_level, first)
        with pytest.raises(DCERPCVerificationError) as excinfo:
            receiver.recv()
        assert excinfo.value.fragment_index == 0
        assert recv_transport.delivered == len(first[0])
        # Drain the dead call's unread fragments per the wire contract.
        del recv_transport._chunks[:]
        assert receiver._DCERPC_v5__recv_sequence == 0

        # The sender retries using the unconsumed sequence range; for privacy
        # the RC4 stream is likewise rebuilt from offset zero.
        sender._DCERPC_v5__sequence = 0
        if auth_level == RPC_C_AUTHN_LEVEL_PKT_PRIVACY:
            sender._DCERPC_v5__clientSealingHandle = ARC4.new(
                sender._DCERPC_v5__clientSealingKey).encrypt
        second = emit_call(sender, transport, PAYLOAD, call_id=2)
        recv_transport.queue(second)
        assert receiver.recv() == PAYLOAD

    def test_rejected_fragment_does_not_consume_crypto_state(self, auth_level):
        # The rejected fragment must not burn its sequence number or advance
        # the RC4 stream: a pristine retry built at the same starting sequence
        # (and, for privacy, stream offset zero) authenticates successfully.
        fragments = list(build_fragments(auth_level))
        views = fragment_views(fragments)
        corrupted = bytearray(fragments[0])
        corrupted[views[0]["signature_offset"]] ^= 0xAA
        fragments[0] = bytes(corrupted)

        receiver, _ = build_receiver(auth_level, fragments)
        with pytest.raises(DCERPCVerificationError):
            receiver.recv()
        assert receiver._DCERPC_v5__recv_sequence == 0

        retry = build_fragments(auth_level, call_id=2, start_sequence=0)
        receiver._transport = ControlledTransport(retry)
        assert receiver.recv() == PAYLOAD
        assert receiver._DCERPC_v5__recv_sequence == EXPECTED_FRAGMENTS

    def test_missing_verifier_is_rejected(self, auth_level):
        fragments = list(build_fragments(auth_level))
        stripped = bytearray(fragments[0])
        struct.pack_into("<H", stripped, 10, 0)  # auth_len = 0
        fragments[0] = bytes(stripped)
        receiver, _ = build_receiver(auth_level, fragments)
        with pytest.raises(DCERPCVerificationError) as excinfo:
            receiver.recv()
        assert excinfo.value.fragment_index == 0
        assert "verifier" in excinfo.value.reason

    def test_byte_stream_splitting_does_not_bypass_checks(self, auth_level):
        fragments = build_fragments(auth_level)
        stream = b"".join(fragments)
        # Serve one byte per read to exercise the partial-read reassembly loop.
        transport = ByteStreamTransport(stream, chunk_size=1)
        receiver = _new_dce(transport, auth_level)
        receiver.configure_inbound_ntlm_session(NTLM2_FLAGS, SESSION_KEY)
        receiver.set_inbound_verification(True)
        assert receiver.recv() == PAYLOAD
        assert transport.delivered == len(stream)

    def test_partial_header_reads_still_verify_each_fragment(self, auth_level):
        fragments = build_fragments(auth_level)
        stream = b"".join(fragments)
        # Seven-byte reads split even the 16/24-byte common headers in half.
        transport = ByteStreamTransport(stream, chunk_size=7)
        receiver = _new_dce(transport, auth_level)
        receiver.configure_inbound_ntlm_session(NTLM2_FLAGS, SESSION_KEY)
        receiver.set_inbound_verification(True)
        assert receiver.recv() == PAYLOAD
        assert transport.delivered == len(stream)

    def test_declared_frag_len_shrink_is_rejected(self, auth_level):
        # Re-sign so the MAC itself stays valid: the length check must fire
        # independently, proving defense in depth ahead of signature handling.
        # A shrunk frag_len means the fragment actually received is larger than
        # declared, which the receiver detects before touching the verifier.
        fragments = list(build_fragments(auth_level))
        views = fragment_views(fragments)
        middle = bytearray(fragments[1])
        struct.pack_into("<H", middle, 8, views[1]["header"]["frag_len"] - 4)
        first_sealed_len = (views[0]["trailer_offset"]
                            - views[0]["header_size"])
        seal_offset = (first_sealed_len
                       if auth_level == RPC_C_AUTHN_LEVEL_PKT_PRIVACY else 0)
        fragments[1] = resign_fragment(
            bytes(middle), auth_level, 1, seal_offset)

        receiver, transport = build_receiver(auth_level, fragments)
        with pytest.raises(DCERPCVerificationError) as excinfo:
            receiver.recv()
        assert excinfo.value.fragment_index == 1
        assert "frag_len" in excinfo.value.reason
        assert transport.delivered == len(fragments[0]) + len(fragments[1])

    def test_legacy_path_remains_unchanged_by_default(self, auth_level):
        # With verification disabled, recv() keeps its historical behavior:
        # tampered fragments are reassembled without raising.
        fragments = list(build_fragments(auth_level))
        views = fragment_views(fragments)
        corrupted = bytearray(fragments[1])
        corrupted[views[1]["signature_offset"]] ^= 0xFF
        fragments[1] = bytes(corrupted)

        transport = ControlledTransport(fragments)
        receiver = _new_dce(transport, auth_level)
        receiver.configure_inbound_ntlm_session(NTLM2_FLAGS, SESSION_KEY)
        # Deliberately do NOT call set_inbound_verification(True).
        result = receiver.recv()
        assert isinstance(result, bytes)
