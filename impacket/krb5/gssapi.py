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
#   RFC 1964 Partial Implementation
#   RFC 4757 Partial Implementation
#   RFC 4121 Partial Implementation
#   RFC 3962 Partial Implementation
#
# Author:
#   Alberto Solino (@agsolino)
#
import struct
import random
import string
from six import b

from Cryptodome.Hash import HMAC, MD5
from Cryptodome.Cipher import ARC4

from impacket.structure import Structure
from impacket.krb5 import constants, crypto

# Our random number generator
try:
    rand = random.SystemRandom()
except NotImplementedError:
    rand = random
    pass

# Constants
GSS_C_DCE_STYLE     = 0x1000
GSS_C_DELEG_FLAG    = 1
GSS_C_MUTUAL_FLAG   = 2
GSS_C_REPLAY_FLAG   = 4
GSS_C_SEQUENCE_FLAG = 8
GSS_C_CONF_FLAG     = 0x10
GSS_C_INTEG_FLAG    = 0x20

# Mic Semantics
GSS_HMAC = 0x11
# Wrap Semantics
GSS_RC4  = 0x10

# 2.  Key Derivation for Per-Message Tokens
KG_USAGE_ACCEPTOR_SEAL  = 22
KG_USAGE_ACCEPTOR_SIGN  = 23
KG_USAGE_INITIATOR_SEAL = 24
KG_USAGE_INITIATOR_SIGN = 25

KRB5_AP_REQ = struct.pack('<H', 0x1)

# Kerberos OID: 1.2.840.113554.1.2.2
KRB_OID = b'\x06\t*\x86H\x86\xf7\x12\x01\x02\x02'

def _calculateMICPad(data):
    # Let's pad the data
    pad = (4 - (len(data) % 4)) & 0x3
    padbuffer = struct.pack("<B",pad) * pad
    return padbuffer

class MechIndepToken():
    
    def __init__(self, data=None, oid=KRB_OID):
        self.data = data
        self.token_oid = oid
    
    @staticmethod
    def from_bytes(data=None):
        if data[0:1] != b'\x60':
            raise Exception('Incorrect token data!')
        data = data[1:]
        length, data = MechIndepToken.get_length(data)
        token_data = data[0:length]
        oid_length, data = MechIndepToken.get_length(token_data[1:])
        token_oid = token_data[0:oid_length+2]
        data = token_data[oid_length+2:]
        return MechIndepToken(data, token_oid)

    @staticmethod
    def get_length(data):
        if data[0] < 128:
            return data[0], data[1:]
        else:
            bytes_count = data[0] - 128
            return int.from_bytes(data[1:1+bytes_count], byteorder='big', signed=False), data[1+bytes_count:]

    @staticmethod
    def encode_length(length):
        if length < 128:
            return length.to_bytes(1, byteorder = 'big', signed = False)
        else:
            lb = length.to_bytes((length.bit_length() + 7) // 8, 'big')
            return (128+len(lb)).to_bytes(1, byteorder = 'big', signed = False) + lb

    def to_bytes(self):
        temp = self.token_oid + self.data
        temp = b'\x60' + self.encode_length(len(temp)) + temp
        return temp[:-len(self.data)], self.data

# 1.1.1. Initial Token - Checksum field
class CheckSumField(Structure):
    structure = (
        ('Lgth','<L=16'),
        ('Bnd','16s=b""'),
        ('Flags','<L=0'),
    )

def GSSAPI(cipher):
    if cipher.enctype == constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value:
        return GSSAPI_AES256()
    if cipher.enctype == constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value:
        return GSSAPI_AES128()
    elif cipher.enctype == constants.EncryptionTypes.rc4_hmac.value:
        return GSSAPI_RC4()
    else:
        raise Exception('Unsupported etype 0x%x' % cipher.enctype)

# 7.2.   GSS-API MIC Semantics
class GSSAPI_RC4:
    # 1.2.1. Per-message Tokens - MIC
    class MIC(Structure):
        structure = (
            ('TOK_ID','<H=0x0101'),
            ('SGN_ALG','<H=0'),
            ('Filler','<L=0xffffffff'),
            ('SND_SEQ','8s=b""'),
            ('SGN_CKSUM','8s=b""'),
        )

    # 1.2.2. Per-message Tokens - Wrap
    class WRAP(Structure):
        structure = (
            ('TOK_ID','<H=0x0102'),
            ('SGN_ALG','<H=0'),
            ('SEAL_ALG','<H=0'),
            ('Filler','<H=0xffff'),
            ('SND_SEQ','8s=b""'),
            ('SGN_CKSUM','8s=b""'),
            ('Confounder','8s=b""'),
        )

    def GSS_GetMIC(self, sessionKey, data, sequenceNumber, direction = 'init'):
        GSS_GETMIC_HEADER = b'\x60\x23\x06\x09\x2a\x86\x48\x86\xf7\x12\x01\x02\x02'
        token = self.MIC()

        pad = _calculateMICPad(data)
        data += pad
 
        token['SGN_ALG'] = GSS_HMAC
        if direction == 'init':
            token['SND_SEQ'] = struct.pack('>L', sequenceNumber) + b'\x00'*4
        else:
            token['SND_SEQ'] = struct.pack('>L', sequenceNumber) + b'\xff'*4

        Ksign = HMAC.new(sessionKey.contents, b'signaturekey\0', MD5).digest()
        Sgn_Cksum = MD5.new( struct.pack('<L',15) + token.getData()[:8] + data).digest()
        Sgn_Cksum = HMAC.new(Ksign, Sgn_Cksum, MD5).digest()
        token['SGN_CKSUM'] = Sgn_Cksum[:8]

        Kseq = HMAC.new(sessionKey.contents, struct.pack('<L',0), MD5).digest()
        Kseq = HMAC.new(Kseq, token['SGN_CKSUM'], MD5).digest()
        token['SND_SEQ'] = ARC4.new(Kseq).encrypt(token['SND_SEQ'])
        finalData = GSS_GETMIC_HEADER + token.getData()
        return finalData
   
    def GSS_Wrap(self, sessionKey, data, sequenceNumber, direction = 'init', encrypt=True, authData=None):
        # Damn inacurate RFC, useful info from here
        # https://social.msdn.microsoft.com/Forums/en-US/fb98e8f4-e697-4652-bcb7-604e027e14cc/gsswrap-token-size-kerberos-and-rc4hmac?forum=os_windowsprotocols
        # and here
        # http://www.rfc-editor.org/errata_search.php?rfc=4757
        GSS_WRAP_HEADER = b'\x60\x2b\x06\x09\x2a\x86\x48\x86\xf7\x12\x01\x02\x02'
        token = self.WRAP()

        # Let's pad the data
        pad = (8 - (len(data) % 8)) & 0x7
        padStr = b(chr(pad)) * pad
        data += padStr

        token['SGN_ALG'] = GSS_HMAC
        token['SEAL_ALG'] = GSS_RC4

        if direction == 'init':
            token['SND_SEQ'] = struct.pack('>L', sequenceNumber) + b'\x00'*4
        else:
            token['SND_SEQ'] = struct.pack('>L', sequenceNumber) + b'\xff'*4

        # Random confounder :)
        token['Confounder'] = b(''.join([rand.choice(string.ascii_letters) for _ in range(8)]))

        Ksign = HMAC.new(sessionKey.contents, b'signaturekey\0', MD5).digest()
        Sgn_Cksum = MD5.new(struct.pack('<L',13) + token.getData()[:8] + token['Confounder'] + data).digest()

        Klocal = bytearray()
        from builtins import bytes
        for n in bytes(sessionKey.contents):
            Klocal.append( n ^ 0xF0)

        Kcrypt = HMAC.new(Klocal,struct.pack('<L',0), MD5).digest()
        Kcrypt = HMAC.new(Kcrypt,struct.pack('>L', sequenceNumber), MD5).digest()
        
        Sgn_Cksum = HMAC.new(Ksign, Sgn_Cksum, MD5).digest()

        token['SGN_CKSUM'] = Sgn_Cksum[:8]

        Kseq = HMAC.new(sessionKey.contents, struct.pack('<L',0), MD5).digest()
        Kseq = HMAC.new(Kseq, token['SGN_CKSUM'], MD5).digest()

        token['SND_SEQ'] = ARC4.new(Kseq).encrypt(token['SND_SEQ'])

        if authData is not None:
            from impacket.dcerpc.v5.rpcrt import SEC_TRAILER
            wrap = self.WRAP(authData[len(SEC_TRAILER()) + len(GSS_WRAP_HEADER):])
            snd_seq = wrap['SND_SEQ']

            Kseq = HMAC.new(sessionKey.contents, struct.pack('<L',0), MD5).digest()
            Kseq = HMAC.new(Kseq, wrap['SGN_CKSUM'], MD5).digest()

            snd_seq = ARC4.new(Kseq).encrypt(wrap['SND_SEQ'])
 
            Kcrypt = HMAC.new(Klocal,struct.pack('<L',0), MD5).digest()
            Kcrypt = HMAC.new(Kcrypt,snd_seq[:4], MD5).digest()
            rc4 = ARC4.new(Kcrypt)
            cipherText = rc4.decrypt(token['Confounder'] + data)[8:]
        elif encrypt is True:
            rc4 = ARC4.new(Kcrypt)
            token['Confounder'] = rc4.encrypt(token['Confounder'])
            cipherText = rc4.encrypt(data)
        else:
            cipherText = data

        finalData = GSS_WRAP_HEADER + token.getData()
        return cipherText, finalData

    def GSS_Unwrap(self, sessionKey, data, sequenceNumber, direction = 'init', encrypt=True, authData=None):
        return self.GSS_Wrap(sessionKey, data, sequenceNumber, direction, encrypt, authData)

    def GSS_Wrap_LDAP(self, sessionKey, data, sequenceNumber, direction = 'init', encrypt=True):
       
        if encrypt:
            data += b'\x01'

        token = self.WRAP()
        token['SGN_ALG'] = GSS_HMAC
        token['SEAL_ALG'] = GSS_RC4

        if direction == 'init':
            token['SND_SEQ'] = struct.pack('>L', sequenceNumber) + b'\x00'*4
        else:
            token['SND_SEQ'] = struct.pack('>L', sequenceNumber) + b'\xff'*4

        # Random confounder :)
        token['Confounder'] = b(''.join([rand.choice(string.ascii_letters) for _ in range(8)]))

        Ksign = HMAC.new(sessionKey.contents, b'signaturekey\0', MD5).digest()
        Sgn_Cksum = MD5.new(struct.pack('<L',13) + token.getData()[:8] + token['Confounder'] + data).digest()

        Klocal = bytearray()
        from builtins import bytes
        for n in bytes(sessionKey.contents):
            Klocal.append( n ^ 0xF0)

        Kcrypt = HMAC.new(Klocal,struct.pack('<L',0), MD5).digest()
        Kcrypt = HMAC.new(Kcrypt,struct.pack('>L', sequenceNumber), MD5).digest()
        
        Sgn_Cksum = HMAC.new(Ksign, Sgn_Cksum, MD5).digest()

        token['SGN_CKSUM'] = Sgn_Cksum[:8]

        Kseq = HMAC.new(sessionKey.contents, struct.pack('<L',0), MD5).digest()
        Kseq = HMAC.new(Kseq, token['SGN_CKSUM'], MD5).digest()

        token['SND_SEQ'] = ARC4.new(Kseq).encrypt(token['SND_SEQ'])

        if encrypt is False:
            sspi_wrap = MechIndepToken.from_bytes(data)

            wrap = self.WRAP(sspi_wrap.data[:32])
            data = sspi_wrap.data[32:]
            
            Kseq = HMAC.new(sessionKey.contents, struct.pack('<L',0), MD5).digest()
            Kseq = HMAC.new(Kseq, wrap['SGN_CKSUM'], MD5).digest()

            snd_seq = ARC4.new(Kseq).encrypt(wrap['SND_SEQ'])

            Kcrypt = HMAC.new(Klocal,struct.pack('<L',0), MD5).digest()
            Kcrypt = HMAC.new(Kcrypt,snd_seq[:4], MD5).digest()
            rc4 = ARC4.new(Kcrypt)
            cipherText = rc4.decrypt(token['Confounder'] + data)[8:]
            return cipherText[:-1], None
        
        elif encrypt is True:
            rc4 = ARC4.new(Kcrypt)
            token['Confounder'] = rc4.encrypt(token['Confounder'])
            cipherText = rc4.encrypt(data)
            finalData, cipherText = MechIndepToken(token.getData() + cipherText, KRB_OID).to_bytes()
            return cipherText, finalData

    def GSS_Unwrap_LDAP(self, sessionKey, data, sequenceNumber, direction = 'init'):
        return self.GSS_Wrap_LDAP(sessionKey, data, sequenceNumber, direction, encrypt=False)

class GSSAPITokenError(ValueError):
    """A received GSS per-message token failed structural or integrity validation.

    Carries the byte ``offset`` (within the token) and the ``field`` name where
    the failure was detected so callers and tests can pinpoint the rejection.
    """
    def __init__(self, message, offset=None, field=None):
        ValueError.__init__(self, message)
        self.offset = offset
        self.field = field


class GSSAPI_AES():
    checkSumProfile = None
    cipherType = None

    class MIC(Structure):
        structure = (
            ('TOK_ID','>H=0x0404'),
            ('Flags','B=0'),
            ('Filler0','B=0xff'),
            ('Filler','>L=0xffffffff'),
            ('SND_SEQ','8s=b""'),
            ('SGN_CKSUM','12s=b""'),
        )

    # 1.2.2. Per-message Tokens - Wrap
    class WRAP(Structure):
        structure = (
            ('TOK_ID','>H=0x0504'),
            ('Flags','B=0'),
            ('Filler','B=0xff'),
            ('EC','>H=0'),
            ('RRC','>H=0'),
            ('SND_SEQ','8s=b""'),
        )

    # RFC 4121 section 4.2.2 token flag bits
    _FLAG_SENDER_IS_ACCEPTOR = 0x01
    _FLAG_SEALED = 0x02
    _FLAG_ACCEPTOR_SUBKEY = 0x04

    _WRAP_TOK_ID = 0x0504
    _MIC_TOK_ID = 0x0404
    _WRAP_FILLER = 0xff
    _SEALED_RRC = 28
    _SIGN_ONLY_RRC = 12
    _CHECKSUM_LEN = 12

    # -- key usage / direction handling -----------------------------------
    # ``direction`` names the LOCAL role.  The party that produced a token we
    # receive is the peer, so unwrapping selects the opposite role's usage.
    @staticmethod
    def _peer(direction):
        return 'accept' if direction == 'init' else 'init'

    @classmethod
    def _seal_usage(cls, sender):
        return KG_USAGE_INITIATOR_SEAL if sender == 'init' else KG_USAGE_ACCEPTOR_SEAL

    @classmethod
    def _sign_usage(cls, sender):
        return KG_USAGE_INITIATOR_SIGN if sender == 'init' else KG_USAGE_ACCEPTOR_SIGN

    @classmethod
    def _flags_for(cls, sender, sealed):
        flags = cls._FLAG_ACCEPTOR_SUBKEY
        if sender == 'accept':
            flags |= cls._FLAG_SENDER_IS_ACCEPTOR
        if sealed:
            flags |= cls._FLAG_SEALED
        return flags

    # -- token construction ------------------------------------------------
    def _build_wrap_header(self, sender, sealed, ec, rrc, sequenceNumber):
        token = self.WRAP()
        token['Flags'] = self._flags_for(sender, sealed)
        token['EC'] = ec
        token['RRC'] = rrc
        token['SND_SEQ'] = struct.pack('>Q', sequenceNumber & 0xFFFFFFFFFFFFFFFF)
        return token

    def GSS_GetMIC(self, sessionKey, data, sequenceNumber, direction = 'init'):
        token = self.MIC()

        pad = _calculateMICPad(data)
        data += pad

        checkSumProfile = self.checkSumProfile()

        token['Flags'] = self._flags_for(direction, sealed=False)
        token['SND_SEQ'] = struct.pack('>Q', sequenceNumber & 0xFFFFFFFFFFFFFFFF)
        token['SGN_CKSUM'] = checkSumProfile.checksum(
            sessionKey, self._sign_usage(direction), data + token.getData()[:16])

        return token.getData()

    def GSS_VerifyMIC(self, sessionKey, data, micToken, sequenceNumber=None, direction = 'init'):
        """Verify a received MIC token.  ``direction`` is the local role, so the
        token is expected to come from the peer.  Raises GSSAPITokenError on
        structural problems and InvalidChecksum on a bad checksum."""
        sender = self._peer(direction)
        if len(micToken) < len(self.MIC()):
            raise GSSAPITokenError('MIC token shorter than %d bytes' % len(self.MIC()),
                                   offset=0, field='MIC')
        token = self.MIC(micToken)
        if token['TOK_ID'] != self._MIC_TOK_ID:
            raise GSSAPITokenError('bad MIC TOK_ID 0x%04x' % token['TOK_ID'],
                                   offset=0, field='TOK_ID')
        flags = token['Flags']
        if flags & 0xF8:
            raise GSSAPITokenError('reserved MIC flag bits set', offset=2, field='Flags')
        if flags & self._FLAG_SEALED:
            raise GSSAPITokenError('MIC token must not set the sealed flag',
                                   offset=2, field='Flags')
        if bool(flags & self._FLAG_SENDER_IS_ACCEPTOR) != (sender == 'accept'):
            raise GSSAPITokenError('MIC direction mismatch', offset=2, field='Flags')
        if token['Filler0'] != 0xff or token['Filler'] != 0xffffffff:
            raise GSSAPITokenError('bad MIC filler', offset=3, field='Filler')
        seq = struct.unpack('>Q', token['SND_SEQ'])[0]
        if sequenceNumber is not None and seq != (sequenceNumber & 0xFFFFFFFFFFFFFFFF):
            raise GSSAPITokenError('MIC sequence number mismatch', offset=8, field='SND_SEQ')

        pad = _calculateMICPad(data)
        data += pad
        # The checksum covers the data followed by the first 16 bytes of the
        # MIC token (everything except the trailing SGN_CKSUM).
        self.checkSumProfile().verify(sessionKey, self._sign_usage(sender),
                                      data + micToken[:16], token['SGN_CKSUM'])
        return seq

    def rotate(self, data, numBytes):
        numBytes %= len(data)
        left = len(data) - numBytes
        result = data[left:] + data[:left]
        return result

    def unrotate(self, data, numBytes):
        numBytes %= len(data)
        result = data[numBytes:] + data[:numBytes]
        return result

    # -- receiving ----------------------------------------------------------
    def _parse_wrap_header(self, header, expect_sender, expect_sealed):
        if len(header) < len(self.WRAP()):
            raise GSSAPITokenError('wrap token shorter than 16-byte header',
                                   offset=0, field='header')
        token = self.WRAP(header)
        if token['TOK_ID'] != self._WRAP_TOK_ID:
            raise GSSAPITokenError('bad wrap TOK_ID 0x%04x' % token['TOK_ID'],
                                   offset=0, field='TOK_ID')
        flags = token['Flags']
        if flags & 0xF8:
            raise GSSAPITokenError('reserved wrap flag bits set', offset=2, field='Flags')
        if token['Filler'] != self._WRAP_FILLER:
            raise GSSAPITokenError('bad wrap filler 0x%02x' % token['Filler'],
                                   offset=3, field='Filler')
        sealed = bool(flags & self._FLAG_SEALED)
        if expect_sealed is not None and sealed != expect_sealed:
            raise GSSAPITokenError('sealed flag mismatch', offset=2, field='Flags')
        if bool(flags & self._FLAG_SENDER_IS_ACCEPTOR) != (expect_sender == 'accept'):
            raise GSSAPITokenError('wrap direction mismatch', offset=2, field='Flags')
        ec = token['EC']
        rrc = token['RRC']
        if sealed:
            if rrc != self._SEALED_RRC:
                raise GSSAPITokenError('sealed token must carry RRC=%d' % self._SEALED_RRC,
                                       offset=6, field='RRC')
            if ec > 15:
                raise GSSAPITokenError('EC out of range', offset=4, field='EC')
        else:
            if rrc != self._SIGN_ONLY_RRC:
                raise GSSAPITokenError('sign-only token must carry RRC=%d' % self._SIGN_ONLY_RRC,
                                       offset=6, field='RRC')
            if ec != 0:
                raise GSSAPITokenError('EC must be 0 for a sign-only token',
                                       offset=4, field='EC')
        seq = struct.unpack('>Q', token['SND_SEQ'])[0]
        return token, flags, ec, rrc, seq

    def _unwrap_token(self, sessionKey, token, expect_sender, expect_sealed=None):
        """Validate and open a contiguous wrap token (16-byte header + body).

        Returns ``(plaintext, sequenceNumber, sealed)``.  Structural problems
        raise GSSAPITokenError; integrity failures raise InvalidChecksum."""
        _, flags, ec, rrc, seq = self._parse_wrap_header(token[:16], expect_sender, expect_sealed)
        sealed = bool(flags & self._FLAG_SEALED)
        if sealed:
            rotated = token[len(self.WRAP()):]
            cipherText = self.unrotate(rotated, rrc + ec)
            plainText = self.cipherType().decrypt(sessionKey, self._seal_usage(expect_sender),
                                                  cipherText)
            if len(plainText) < ec + len(self.WRAP()):
                raise GSSAPITokenError('sealed token too short for EC padding and inner header',
                                       offset=0, field='EC')
            # The decrypted trailer holds the authenticated inner copy of the header.
            # Cross-check it against the plaintext outer header so a tampered outer
            # TOK_ID/Flags/EC/SND_SEQ is rejected instead of silently trusted.
            inner = self.WRAP(plainText[-len(self.WRAP()):])
            if inner['TOK_ID'] != self._WRAP_TOK_ID or inner['Flags'] != flags or \
                    inner['EC'] != ec or inner['RRC'] != 0 or \
                    struct.unpack('>Q', inner['SND_SEQ'])[0] != seq:
                raise GSSAPITokenError('inner header does not match outer header',
                                       offset=0, field='inner-header')
            # Strip exactly EC padding bytes plus the 16-byte inner header so the
            # rotated trailer is never mistaken for application data.
            return plainText[:-(ec + len(self.WRAP()))], seq, True
        body = token[len(self.WRAP()):]
        if len(body) < self._CHECKSUM_LEN:
            raise GSSAPITokenError('sign-only token truncated before checksum',
                                   offset=len(self.WRAP()), field='SGN_CKSUM')
        checksum, data = body[:self._CHECKSUM_LEN], body[self._CHECKSUM_LEN:]
        inner = self._build_wrap_header(expect_sender, False, 0, 0, seq)
        self.checkSumProfile().verify(sessionKey, self._sign_usage(expect_sender),
                                      data + inner.getData(), checksum)
        return data, seq, False

    # -- sending -------------------------------------------------------------
    def GSS_Wrap(self, sessionKey, data, sequenceNumber, direction = 'init', encrypt=True):
        cipher = self.cipherType()

        if not encrypt:
            # RFC 4121 section 4.2.6.2: integrity-only wrap token.
            header = self._build_wrap_header(direction, False, 0, 0, sequenceNumber)
            checkSum = self.checkSumProfile().checksum(
                sessionKey, self._sign_usage(direction), data + header.getData())
            header = self._build_wrap_header(direction, False, 0, self._SIGN_ONLY_RRC,
                                             sequenceNumber)
            # The plaintext is carried unmodified; the signature is header+checksum.
            return data, header.getData() + checkSum

        # Let's pad the data
        pad = (cipher.blocksize - (len(data) % cipher.blocksize)) & 15
        padStr = b'\xFF' * pad
        data += padStr

        # The RRC field ([RFC4121] section 4.2.5) is 12 if no encryption is requested or 28 if
        # encryption is requested. The RRC field is chosen such that all the data can be
        # encrypted in place.
        rrc = self._SEALED_RRC

        token = self._build_wrap_header(direction, True, pad, 0, sequenceNumber)

        cipherText = cipher.encrypt(sessionKey, self._seal_usage(direction),
                                    data + token.getData(), None)
        token['RRC'] = rrc

        cipherText = self.rotate(cipherText, token['RRC'] + token['EC'])

        ret1 = cipherText[len(self.WRAP()) + token['RRC'] + token['EC']:]
        ret2 = token.getData() + cipherText[:len(self.WRAP()) + token['RRC'] + token['EC']]

        return ret1, ret2

    def GSS_Unwrap(self, sessionKey, data, sequenceNumber, direction = 'init', encrypt=True, authData=None):
        from impacket.dcerpc.v5.rpcrt import SEC_TRAILER

        # The DCE/RPC security trailer carries the 16-byte header plus the leading
        # rotated bytes; ``data`` carries the remainder.  Concatenated they form the
        # full contiguous wrap token.
        token = authData[len(SEC_TRAILER()):] + data
        plainText, _, _ = self._unwrap_token(sessionKey, token, self._peer(direction),
                                             expect_sealed=encrypt)
        return plainText, None

    def GSS_Wrap_LDAP(self, sessionKey, data, sequenceNumber, direction = 'init', encrypt=True, use_padding=False):
        cipher = self.cipherType()

        pad = 0
        if use_padding:
            # Let's pad the data
            pad = (cipher.blocksize - (len(data) % cipher.blocksize)) & 15
            padStr = b'\xFF' * pad
            data += padStr

        rrc = self._SEALED_RRC

        token = self._build_wrap_header(direction, True, pad, 0, sequenceNumber)

        cipherText = cipher.encrypt(sessionKey, self._seal_usage(direction),
                                    data + token.getData(), None)
        token['RRC'] = rrc

        cipherText = self.rotate(cipherText, token['RRC'] + token['EC'])

        ret1 = cipherText
        ret2 = token.getData()

        return ret1, ret2

    def GSS_Unwrap_LDAP(self, sessionKey, data, sequenceNumber, direction = 'init'):
        plainText, _, _ = self._unwrap_token(sessionKey, data, self._peer(direction),
                                             expect_sealed=True)
        return plainText, None

class GSSAPI_AES256(GSSAPI_AES):
    checkSumProfile = crypto._SHA1AES256
    cipherType = crypto._AES256CTS

class GSSAPI_AES128(GSSAPI_AES):
    checkSumProfile = crypto._SHA1AES128
    cipherType = crypto._AES128CTS
