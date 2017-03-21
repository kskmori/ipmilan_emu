import sys
import os
import socket
import struct
import binascii
import hashlib
import hmac
from Crypto.Cipher import AES
import traceback
import inspect

from session import Session

RMCP_VERSION = 0x06
RMCP_RESERVED = 0x00
RMCP_SEQ_NOACK = 0xff
RMCP_CLASS_ASF = 0x06
RMCP_CLASS_IPMI = 0x07

ASF_MSG_IANA_NUM = 0x11be
ASF_MSG_TYPE_PONG = 0x40
ASF_MSG_TYPE_PING = 0x80

IPMI_SES_HDR_AUTH_TYPE_NONE = 0x00
IPMI_SES_HDR_AUTH_TYPE_MD2  = 0x01
IPMI_SES_HDR_AUTH_TYPE_MD5  = 0x02
IPMI_SES_HDR_AUTH_TYPE_PW   = 0x04
IPMI_SES_HDR_AUTH_TYPE_RMCPPLUS = 0x06

IPMI_PAYLOAD_TYPE_IPMI_MSG  = 0x00
IPMI_PAYLOAD_TYPE_SOL       = 0x01
IPMI_PAYLOAD_TYPE_OEM       = 0x02
IPMI_PAYLOAD_TYPE_RMCPP_OPEN_SES_REQ = 0x10
IPMI_PAYLOAD_TYPE_RMCPP_OPEN_SES_RES = 0x11
IPMI_PAYLOAD_TYPE_RAKP_1    = 0x12
IPMI_PAYLOAD_TYPE_RAKP_2    = 0x13
IPMI_PAYLOAD_TYPE_RAKP_3    = 0x14
IPMI_PAYLOAD_TYPE_RAKP_4    = 0x15

IPMI_AUTH_ALG_NONE        = 0x00
IPMI_AUTH_ALG_HMAC_SHA1   = 0x01
IPMI_AUTH_ALG_HMAC_MD5    = 0x02
IPMI_AUTH_ALG_HMAC_SHA256 = 0x03

IPMI_INTE_ALG_NONE            = 0x00
IPMI_INTE_ALG_HMAC_SHA1_96    = 0x01
IPMI_INTE_ALG_HMAC_MD5_128    = 0x02
IPMI_INTE_ALG_MD5_128         = 0x03
IPMI_INTE_ALG_HMAC_SHA256_128 = 0x04

IPMI_CONF_ALG_NONE        = 0x00
IPMI_CONF_ALG_AES_CBC_128 = 0x01
IPMI_CONF_ALG_xRC4_128    = 0x02
IPMI_CONF_ALG_xRC4_40     = 0x03


class RMCPPacket:
    """RMCP packet structure """

    def __init__(self, response = None):
        self.packet = ""
        self.version = RMCP_VERSION
        self.seq_no = 0xff  # for IPMI
        self.rmcp_class = 0
        self.payload = None

        if response:
            # version and seq_no are used in myside
            self.rmcp_class = response.rmcp_class
            # payload needs to be set in the processing

    def dump(self):
        print "RMCPPacket.dump(): version=0x%02x, seq_no=0x%02x, rmcp_class=0x%02x" \
            % (self.version, self.seq_no, self.rmcp_class)

    def unpack(self, packet):
        self.packet = packet
        self.version, reserved, self.seq_no, self.rmcp_class = \
            struct.unpack('BBBB', self.packet[0:4])
        if self.version != RMCP_VERSION or reserved != RMCP_RESERVED:
            raise Exception("Invalid RMCP packet: ", self.version, reserved, self.seq_no, self.rmcp_class)

        if self.seq_no == RMCP_SEQ_NOACK: # no ack needed
            if self.rmcp_class == RMCP_CLASS_ASF:
                self.payload = ASFPacket()
                self.payload.unpack(self.packet[4:])
            elif self.rmcp_class == RMCP_CLASS_IPMI:
                self.payload = IPMIPacket().createIPMIPacket(self.packet[4:])
                self.payload.unpack(self.packet[4:])
            else:
                raise Exception("Unknown RMCP class: ", self.rmcp_class)
        else: # ack is needed
            raise NotImplementedError(self.__class__.__name__ + '.' + inspect.currentframe().f_code.co_name)

    def pack(self):
        #self.dump()
        self.packet = struct.pack('BBBB',
                                  self.version,
                                  0, # reserved
                                  self.seq_no,
                                  self.rmcp_class)
        self.packet += self.payload.pack()

        return self.packet

    def process(self, session):
        response = RMCPPacket(self)
        response.payload = self.payload.process(session)
        return response


class ASFPacket:
    """ASF packet structure """

    def __init__(self):
        self.packet = ""
        self.IANA_num = 0
        self.type = 0
        self.tag = 0
        self.length = 0

    def unpack(self, packet):
        self.packet = packet
        self.IANA_num, self.type, self.tag, reserved, self.length = \
            struct.unpack('!IBBBB', self.packet)
        print "DEBUG: ASFPacket unpack: %x %x %x %x %x" % (self.IANA_num, self.type, self.tag, reserved, self.length)

    def pack(self):
        #print "DEBUG: ASFPacket.pack(): "
        if self.type == ASF_MSG_TYPE_PING:
            raise Exception("ASFPacket.pack(): not implementedtype = " + "ASF_MSG_TYPE_PING")
        elif self.type == ASF_MSG_TYPE_PONG:
            # pack asf header
            self.packet = struct.pack('!IBBBB',
                                      ASF_MSG_IANA_NUM,
                                      ASF_MSG_TYPE_PONG,
                                      self.tag,
                                      0,  # reserved
                                      16) # pong payload length
            # pack pong payload
            self.packet += struct.pack('!IIBB6b',
                                       ASF_MSG_IANA_NUM,
                                       0,    # OEM; not in use
                                       0x81, # IPMI with ASF 1.0
                                       0,    # supported interaction
                                       0,0,0,0,0,0)    # reserved
        else:
            raise Exception("ASFPacket.pack(): not implemented type = ", self.type)
        return self.packet

    def process(self, session):
        print "DEBUG: ASFPacket.process(): "
        response = None
        if self.type == ASF_MSG_TYPE_PING:
            print "ASF Ping"
            # Reply ASF Pong packet
            response = ASFPacket()
            response.type = ASF_MSG_TYPE_PONG
            response.tag = self.tag
        elif self.type == ASF_MSG_TYPE_PONG:
            print "ASF Pong"
            # do nothing
        else:
            raise Exception("Not implemented: ASF type = ", self.type)
        return response

class IPMIPacket:
    """IPMI packet factory class"""
    

    @classmethod
    def createIPMIPacket(cls, packet):
        auth_type = ord(packet[0])
        if auth_type == IPMI_SES_HDR_AUTH_TYPE_RMCPPLUS:
            received = IPMI20Packet(packet=packet)
        else:
            received = IPMI15Packet(packet=packet)
        #received.packet = packet
        return received


class IPMI15Packet(IPMIPacket):
    """IPMI 1.5 packet structure """

    def __init__(self, request = None, packet = ''):
        self.packet = packet
        # IPMI session headers
        self.auth_type = 0
        self.seq_no = 0
        self.session_id = 0
        self.auth_code = ""
        self.payload_len = 0
        # IPMI payload
        self.payload = None
        # IPMI Session trailer
        ##  Legacy PAD

        if request:
            self.auth_type = request.auth_type
            self.seq_no = request.seq_no
            self.session_id = request.session_id
            # auth_code, payload needs to be set in processing
            # payload_len will be calculated in pack

    def dump(self):
        print "IPMI15Packet: auth_type = 0x%02x, seq_no=0x%04x, session_id=0x%04x" \
            % (self.auth_type, self.seq_no, self.session_id)

    def unpack(self, packet = ''):
        if packet: 
            self.packet = packet
        self.auth_type, self.seq_no, self.session_id = struct.unpack('<BII', self.packet[0:9])
        if self.auth_type == IPMI_SES_HDR_AUTH_TYPE_NONE:
            self.payload_len = struct.unpack('B', self.packet[9:10])
            payload_data = self.packet[10:]
        else:
            self.auth_code = self.packet[9:25] # 16 bytes length
            self.payload_len = struct.unpack('B', self.packet[25:26])
            payload_data = self.packet[26:]

        self.dump()
        self.payload = IPMIMessageRequest()
        self.payload.unpack(payload_data)

    def pack(self):
        #print "DEBUG: IPMI15Packet.pack(): "
        payload_data = self.payload.pack()
        self.payload_len = len(payload_data)

        self.packet = struct.pack('<BII', self.auth_type, self.seq_no, self.session_id)
        if self.auth_type != IPMI_SES_HDR_AUTH_TYPE_NONE:
            self.packet += struct.pack('16s', '') # TODO
            raise NotImplementedError(self.__class__.__name__ + '.' + inspect.currentframe().f_code.co_name)
        self.packet += struct.pack('B', self.payload_len) + payload_data
        return self.packet

    def process(self, session):
        #print "DEBUG: IPMI15Packet.process(): "
        response = IPMI15Packet(self)
        response.payload = self.payload.process(session)
        print "TODO: IPMI15Packet.process(): build response packet"

        return response

class IPMI20Packet(IPMIPacket):
    """IPMI 2.0 packet structure """

    def __init__(self, request = None, packet = ''):
        self.packet = packet
        # IPMI session headers
        self.auth_type = IPMI_SES_HDR_AUTH_TYPE_RMCPPLUS
        self.payload_type = 0
        self.OEM_IANA = 0       # optional
        self.OEM_payload_id = 0 # optional
        self.session_id = 0
        self.seq_no = 0
        self.payload_len = 0
        # IPMI payload
        ## Confidentiality Header
        self.payload = None
        ## Confidentiality Trailer
        # IPMI Session trailer
        ##  Integrity PAD
        ##  PAD Length
        ##  Next Header
        ##  Auth Code

        if request:
            self.session_id = request.session_id
            self.seq_no = request.seq_no
            # payload_type and payload need to be set in processing
        

    def dump(self):
        print "IPMI20Packet: auth_type=0x%02x, payload_type=0x%02x, OEM_IANA=0x%08x, OEM_payload_id=0x%04x, session_id=0x%08x, seq_no=0x%08x, payload_len=0x%04x" \
            % (self.auth_type, self.payload_type, self.OEM_IANA, self.OEM_payload_id,
               self.session_id, self.seq_no, self.payload_len)

    def unpack(self, packet = ''):
        # Note: byte order in IPMI messages is LSB first, not Network byte order
        # see IPMI 2.0 spec. 13.5.1 RMCP/ASF and IPMI Byte Order
        if packet:
            self.packet = packet
        self.auth_type, self.payload_type = struct.unpack('BB', self.packet[:2])
        rest = self.packet[2:]
        if self.payload_type & 0x3f == IPMI_PAYLOAD_TYPE_OEM:
            self.OEM_IANA, self.OEM_payload_id \
                = struct.unpack('<IH', self.packet[2:8])
            idx_sid = 8
        else:
            idx_sid = 2
        self.session_id, self.seq_no, self.payload_len \
            = struct.unpack('<IIH', self.packet[idx_sid:idx_sid + 10])
        payload_data = self.packet[idx_sid + 10:idx_sid + 10 + self.payload_len]
        self.dump()

        session = Session.getCurrentSession() # TODO: proper session management
        if self.payload_type & 0x40 != 0: # autohenticated
            self.session_trailer = self.packet[idx_sid+10+self.payload_len:]
            if self.check_integlity(idx_sid + 10 + self.payload_len, session) != True:
                print "Invalid integlity"
                # TODO error handling
        if self.payload_type & 0x80 != 0: # encrypted
            payload_data = self.decrypt_payload(payload_data, session)

        self.payload = RCMPPLUSPacket.createRCMPPLUSPacket(self.payload_type & 0x3f)
        self.payload.unpack(payload_data)

    def check_integlity(self, integlity_data_length, session):
        pad_len = (len(self.packet) + 2) % 4 # +2 for pad len and next header field
        if pad_len != 0:
            pad_len = 4 - pad_len
        # make sure pad len is expected
        if ord(self.packet[integlity_data_length + pad_len]) != pad_len:
            # TODO: error handling
            print "Invalid pad_len"
            return False
        auth_code = hmac.new(session.K1, self.packet[0:integlity_data_length + pad_len + 2], hashlib.sha1).digest()[:12]
        return (auth_code == self.packet[integlity_data_length + pad_len + 2:])

    def decrypt_payload(self, encrypted_payload, session):
        iv = encrypted_payload[0:16]
        cipher = AES.new(session.K2[0:16], AES.MODE_CBC, iv)
        decrypted = cipher.decrypt(encrypted_payload[16:])
        pad_len = ord(decrypted[-1])
        return decrypted[:-pad_len-1]

    def pack(self):
        session = Session.getCurrentSession() # TODO: proper session management

        if self.payload_type & 0x40 != 0 and len(session.SIK) > 0: # authenticated
            is_authenticated = True
        else:
            is_authenticated = False
            self.payload_type &= ~0x40
        if self.payload_type & 0x80 != 0 and len(session.SIK) > 0: # encrypted
            is_encrypted = True
        else:
            is_encrypted = False
            self.payload_type &= ~0x80

        payload_data = self.payload.pack()
        if is_encrypted:
            payload_data = self.encrypt_payload(payload_data, session)
        self.payload_len = len(payload_data)

        self.packet = struct.pack('<BBIIH',
                                  self.auth_type, self.payload_type,
                                  self.session_id, self.seq_no,
                                  self.payload_len)
        self.packet += payload_data

        if is_authenticated:
            # add session trailer to self.packet
            self.add_session_trailer(session)

        self.dump()
        return self.packet

    def add_session_trailer(self, session):
        pad_len = (len(self.packet) + 2) % 4 # +2 for pad len and next header field
        if pad_len != 0:
            pad_len = 4 - pad_len
            self.packet += '\xff' * pad_len
        self.packet += struct.pack('BB', pad_len, 0x07) # pad len and next header
        # IPMI_INTE_ALG_HMAC_SHA1_96 is only supported now
        auth_code = hmac.new(session.K1, self.packet, hashlib.sha1).digest()[:12]
        self.packet += auth_code

    def encrypt_payload(self, unencrypted, session):
        pad_len = (len(unencrypted) + 1) % 16 # assumes AES-CBC-128
        if pad_len != 0:
            pad_len = 16 - pad_len
            unencrypted += b''.join(map(chr, range(1, pad_len + 1)))
        unencrypted += struct.pack('B', pad_len)
        iv = os.urandom(16)
        cipher = AES.new(session.K2[0:16], AES.MODE_CBC, iv)
        return iv + cipher.encrypt(unencrypted)

    def process(self, session):
        # create RCMP+ Open Session Response packet
        response = IPMI20Packet(self)
        response.session_id = session.remote_session_id # TODO is this correct?
        session.remote_seq_no += 1 # TODO init, increment timing
        response.seq_no = session.remote_seq_no
        response.payload_type = self.payload_type + 1 # response type
        response.payload = self.payload.process(session)

        return response


class RCMPPLUSPacket(IPMIPacket):
    """RCMP+ packet factory class"""

    @classmethod
    def createRCMPPLUSPacket(cls, payload_type):
        class_table = {
            0x00: IPMIMessageRequest,
            0x10: RCMPP_OpenSessionRequest,
            0x11: RCMPP_OpenSessionResponse,
            0x12: RCMPP_RAKP_1,
            0x13: RCMPP_RAKP_2,
            0x14: RCMPP_RAKP_3,
            0x15: RCMPP_RAKP_4
            }
        received = class_table[payload_type]()
        return received

class RCMPP_OpenSessionRequest(RCMPPLUSPacket):
    """RCMP+ Open Session Request packet structure"""

    def __init__(self):
        self.packet = ''
        self.tag = 0
        self.max_priv = 0
        self.session_id = 0
        self.auth_alg = 0
        self.inte_alg = 0
        self.conf_alg = 0

    def dump(self):
        print "RCMPP_OpenSessionRequest: tag=0x%02x, max_priv=0x%04x, session_id=0x%04x, auth_alg=0x%02x, inte_alg=0x%02x, conf_alg=0x%02x" \
            % (self.tag, self.max_priv, self.session_id, self.auth_alg, self.inte_alg, self.conf_alg)

    def unpack(self, packet):
        self.packet = packet
        self.tag, self.max_priv, reserved, self.session_id \
            = struct.unpack('<BBHI', self.packet[0:8])

        # assumes each payloads have a valid format
        self.auth_alg = ord(self.packet[8+4])
        self.inte_alg = ord(self.packet[16+4])
        self.conf_alg = ord(self.packet[24+4])

        self.dump()

    def pack(self):
        raise NotImplementedError(self.__class__.__name__ + '.' + inspect.currentframe().f_code.co_name)
        return self.packet
    def process(self, session):
        session.remote_session_id = self.session_id
        session.managed_session_id, = struct.unpack('I', os.urandom(4)) # TODO
        response = RCMPP_OpenSessionResponse(self)
        response.max_priv = 0x04 # admin level
        response.managed_session_id = session.managed_session_id
        response.status_code = 0 # success
        return response
#        raise NotImplementedError(self.__class__.__name__ + '.' + inspect.currentframe().f_code.co_name)


class RCMPP_OpenSessionResponse(RCMPPLUSPacket):
    """RCMP+ Open Session Response packet structure"""

    def __init__(self, request = None):
        self.packet = ''
        self.tag = 0
        self.status_code = 0x12 # unrecognized parameter
        self.max_priv = 0
        self.remote_session_id = 0
        self.managed_session_id = 0
        self.auth_alg = IPMI_AUTH_ALG_HMAC_SHA1
        self.inte_alg = IPMI_INTE_ALG_HMAC_SHA1_96
        self.conf_alg = IPMI_CONF_ALG_AES_CBC_128

        if request:
            self.tag = request.tag
            self.remote_session_id = request.session_id
            # status_code, max_priv, managed_session_id need to be processed

    def unpack(self):
        raise NotImplementedError(self.__class__.__name__ + '.' + inspect.currentframe().f_code.co_name)
    def pack(self):
        if self.status_code != 0:
            self.max_priv = 0
        self.packet = struct.pack('<BBBBI', self.tag, self.status_code, self.max_priv, 0, self.remote_session_id)
        if self.status_code == 0:
            self.packet += struct.pack('<I', self.managed_session_id)
            self.packet += struct.pack('BBBBBBBB',
                                       0x00, # authentication algorithm
                                       0, 0, # reserved
                                       0x08, # payload length
                                       self.auth_alg,
                                       0,0,0) # reserved
            self.packet += struct.pack('BBBBBBBB',
                                       0x01, # integrity algorithm
                                       0, 0, # reserved
                                       0x08, # payload length
                                       self.inte_alg,
                                       0,0,0) # reserved
            self.packet += struct.pack('BBBBBBBB',
                                       0x02, # confidentiality algorithm
                                       0, 0, # reserved
                                       0x08, # payload length
                                       self.conf_alg,
                                       0,0,0) # reserved
        return self.packet
            
    def process(self, session):
        raise NotImplementedError(self.__class__.__name__ + '.' + inspect.currentframe().f_code.co_name)

class RCMPP_RAKP_1(RCMPPLUSPacket):
    """RCMP+ RAKP Message 1 packet structure"""

    def __init__(self):
        self.packet = ''
        self.tag = 0
        self.managed_session_id = 0
        self.remote_random = '' # little endian
        self.max_priv = 0
        self.username_length = 0
        self.username = ''

    def dump(self):
        print "RCMPP_RAKP_1: tag=0x%02x, managed_session_id=0x%08x, remote_random=0x%s, max_priv=0x%02x, username_length=0x%02x, username=%s" \
            % (self.tag, self.managed_session_id, binascii.hexlify(self.remote_random), self.max_priv, self.username_length, self.username)

    def unpack(self, packet):
        self.packet = packet
        self.tag, reserved, reserved, reserved, \
            self.managed_session_id, self.remote_random, \
            self.max_priv, reserved, reserved, self.username_length \
            = struct.unpack('<BBBBI16sBBBB', self.packet[0:28])
        self.username = self.packet[28:28 + self.username_length]

        self.dump()

    def pack(self):
        raise NotImplementedError(self.__class__.__name__ + '.' + inspect.currentframe().f_code.co_name)
        return self.packet

    def process(self, session):
        response = RCMPP_RAKP_2(self)
        response.remote_session_id = session.remote_session_id

        # validate RAKP 1 from remote console
        if self.managed_session_id != session.managed_session_id:
            response.status_code = 0x02 # invalid session id
            return response

        # calculate auth code
        session.remote_random = self.remote_random
        session.managed_random = os.urandom(16)
        session.role = self.max_priv # TODO always use max_priv in request
        response.auth_code = self.calculate_auth_code(session)

        response.managed_random = session.managed_random
        response.managed_guid = session.config.guid
        response.status_code = 0 # succeed
        return response

    def calculate_auth_code(self, session):
        text = struct.pack('<II16s16s16sBB',
                           session.remote_session_id,
                           session.managed_session_id,
                           session.remote_random,
                           session.managed_random,
                           session.config.guid,
                           session.role,
                           len(session.config.username))
        text += session.config.username
        # IPMI_AUTH_ALG_HMAC_SHA1 is only supported now
        return hmac.new(session.config.password, text, hashlib.sha1).digest()

class RCMPP_RAKP_2(RCMPPLUSPacket):
    """RCMP+ RAKP Message 2 packet structure"""

    def __init__(self, request = None):
        self.packet = b''
        self.tag = 0
        self.status_code = 0x12 # unrecognized parameter
        self.remote_session_id = 0
        self.managed_random = b''
        self.managed_guid = b''
        self.auth_code = b''

        if request:
            self.tag = request.tag
            # managed_guid, remote_session_id, auth_code need to be processed

    def unpack(self):
        raise NotImplementedError(self.__class__.__name__ + '.' + inspect.currentframe().f_code.co_name)

    def pack(self):
        self.packet = struct.pack('<BBBBI',
                                  self.tag, self.status_code,
                                  0, 0, # reserved
                                  self.remote_session_id)
        if self.status_code == 0:
            self.packet += self.managed_random \
                + self.managed_guid \
                + self.auth_code

        return self.packet

    def process(self, session):
        raise NotImplementedError(self.__class__.__name__ + '.' + inspect.currentframe().f_code.co_name)


class RCMPP_RAKP_3(RCMPPLUSPacket):
    """RCMP+ RAKP Message 3 packet structure"""

    def __init__(self):
        self.packet = b''
        self.tag = 0
        self.status_code = 0x12 # unrecognized parameter
        self.managed_session_id = 0
        self.auth_code = b''

    def dump(self):
        print "RCMPP_RAKP_3: tag=0x%02x, status_code=0x%02x, managed_session_id=0x%08x, auth_code=0x%s..(%d bytes)" \
            % (self.tag, self.status_code, self.managed_session_id, binascii.hexlify(self.auth_code[0:4]), len(self.auth_code))

    def unpack(self, packet):
        self.packet = packet
        self.tag, self.status_code = struct.unpack('BB', self.packet[0:2])
        if self.status_code == 0:
            self.managed_session_id, = struct.unpack('<I', self.packet[4:8])
            self.auth_code = self.packet[8:]

        self.dump()

    def pack(self):
        raise NotImplementedError(self.__class__.__name__ + '.' + inspect.currentframe().f_code.co_name)
        return self.packet

    def process(self, session):
        if self.status_code != 0:
            # TODO close session
            print "DEBUG: RAKP_3 closing session with an error: 0x%02x" % (self.status_code)
            return None # no response

        response = RCMPP_RAKP_4(self)
        response.remote_session_id = session.remote_session_id

        # validate RAKP 3 from remote console
        if self.managed_session_id != session.managed_session_id:
            response.status_code = 0x02 # invalid session id
            return response
        if self.validate_auth_code(session) == False:
            response.status_code = 0x0f # invalid integlity check value
            return response

        session.generateSessionKeys()
        response.integlity_check_value = self.calculate_integlity_check_value(session)
        response.status_code = 0 # succeed
        return response

    def validate_auth_code(self, session):
        text = struct.pack('<16sIBB',
                           session.managed_random,
                           session.remote_session_id,
                           session.role,
                           len(session.config.username))
        text += session.config.username
        value = hmac.new(session.config.password, text, hashlib.sha1).digest()
        return self.auth_code == value

    def calculate_integlity_check_value(self, session):
        # calculate integlity key
        text = struct.pack('<16sI16s',
                           session.remote_random,
                           session.managed_session_id,
                           session.config.guid)
        return hmac.new(session.SIK, text, hashlib.sha1).digest()

class RCMPP_RAKP_4(RCMPPLUSPacket):
    """RCMP+ RAKP Message 4 packet structure"""

    def __init__(self, request = None):
        self.packet = b''
        self.tag = 0
        self.status_code = 0x12 # unrecognized parameter
        self.remote_session_id = 0
        self.integlity_check_value = b''

        if request:
            self.tag = request.tag
            # remote_session_id, integlity need to be processed

    def unpack(self):
        raise NotImplementedError(self.__class__.__name__ + '.' + inspect.currentframe().f_code.co_name)

    def pack(self):
        self.packet = struct.pack('<BBBBI',
                                  self.tag, self.status_code,
                                  0, 0, # reserved
                                  self.remote_session_id)
        if self.status_code == 0:
            self.packet += self.integlity_check_value

        return self.packet

    def process(self, session):
        raise NotImplementedError(self.__class__.__name__ + '.' + inspect.currentframe().f_code.co_name)

# calculate 2's complement checksum in an unsigned byte
# 0 should be returned if data is including the correct checksum byte
def ipmi_checksum(data):
    sum = 0
    for i in data:
        sum = (sum + ord(i)) % 256
    return (-sum) % 256
    

class IPMIMessageRequest:
    """IPMI LAN Message Request structure """

    def __init__(self):
        self.packet = ""
        self.rsAddr = 0
        self.netFn = 0
        self.rsLUN = 0
        self.checksum_header = 0
        self.rqAddr = 0
        self.rqSeq = 0
        self.rqLUN = 0
        self.cmd = 0
        self.data = ""
        self.checksum_data = 0

    def dump(self):
        print "IPMIMessageRequest: rsAddr=0x%02x, netFn=0x%02x, rsLUN=0x%02x, rqAddr=0x%02x, rqSeq=0x%02x, rqLUN=0x%02x, cmd=0x%02x" % \
            (self.rsAddr, self.netFn, self.rsLUN, self.rqAddr, self.rqSeq, self.rqLUN, self.cmd)

    def unpack(self, packet):
        self.packet = packet
        self.rsAddr, netFnByte, self.checksum_header, \
            self.rqAddr, rqSeqByte, self.cmd \
            = struct.unpack('BBBBBB', self.packet[0:6])
        self.rsLUN = netFnByte & 0x3
        self.netFn = netFnByte >> 2
        self.rqLUN = rqSeqByte & 0x3
        self.rqSeq = rqSeqByte >> 2
        self.data = self.packet[6:-1]
        self.checksum_data = struct.unpack('B', self.packet[-1:])

        self.dump()

        # checksum validate
        if ipmi_checksum(self.packet[0:3]) != 0 or ipmi_checksum(self.packet) != 0:
            raise Exception("IPMIMessageRequest: invalid checksum")
        
    def pack(self):
        raise NotImplementedError(self.__class__.__name__ + '.' + inspect.currentframe().f_code.co_name)
        return self.packet

    def process(self, session):
        #print "DEBUG: IPMIMessageRequest.process(): "
        self.session = session # to pass to cmd_x functions

        cmd_table = {
            0x00: {		# netFN chassis
                0x00: self.cmd_get_chassis_capa,
                0x02: self.cmd_chassis_control,
                },
            0x06: {		# netFN app
                0x01: self.cmd_get_device_id,
                0x38: self.cmd_get_chan_auth_capa,
                0x39: self.cmd_get_sess_challenge,
                0x3a: self.cmd_active_sess,
                0x3b: self.cmd_set_sess_priv_level,
                0x3c: self.cmd_close_session
                }
            }

        response = IPMIMessageResponse(self)
        try:
            cmd_func = cmd_table[self.netFn][self.cmd]
        except KeyError:
            print "DEBUG: Not implemented yet: IPMIMessageRequest(0x%02x, 0x%02x)" \
                % (self.netFn, self.cmd)
            response.completion_code = 0xd5 # command or parameter not supported
            return response

        cmd_func(response)
        return response

    ### IPMIMessageRequest command functions
    def cmd_get_device_id(self, res):
        print "DEBUG: IPMIMessageRequest.cmd_get_device_id(): "
        res.data = struct.pack('BBBBBBBBBBB',
                               0x00, # Device ID; unspecified
                               0x01, # Device Revision
                               0x01, # Firmware Revision
                               0x01, # Firmware Minor Revision
                               0x51, # IPMI Version 1.5
                               0x80, # Device Support; Chassis
                               0x00, 0x00, 0x00, # Manufac. ID (20bits)
                               0x00, 0x00) # Product ID (16bits)
        res.completion_code = 0x00 # success

    def cmd_get_chan_auth_capa(self, res):
        print "DEBUG: IPMIMessageRequest.cmd_get_chan_auth_capa(): "
        if False: # IPMI v1.5
            res.data = struct.pack('BBBBBBBB',
                                   0, # channel number
                                   #0x15, # auth type support; PWKEY|MD5|NONE
                                   0x01, # auth type support; NONE
                                   0x07, # auth status
                                   0x01, # IPMI v1.5
                                   0,0,0,0) # reserved
        else: # IPMI v2.0
            res.data = struct.pack('BBBBBBBB',
                                   0, # channel number
                                   0x81, # auth type support; IPMIv2.0|NONE
                                   0x07, # auth status
                                   0x03, # IPMI v2.0 and v1.5
                                   0,0,0,0) # reserved

        res.completion_code = 0x00 # success

    def cmd_get_sess_challenge(self, res):
        print "DEBUG: IPMIMessageRequest.cmd_get_sess_challenge(): "
        res.data = struct.pack('!I16s',
                               0xffffffff, # tmp session
                               "challenge") # tmp challenge string; TODO: use random
        res.completion_code = 0x00 # success


    def cmd_active_sess(self, res):
        print "DEBUG: IPMIMessageRequest.cmd_active_sess(): "
        res.data = struct.pack('!BIIB',
                               ord(self.data[0]),
                               0xffffffff, # tmp session
                               0, # tmp session
                               0x04) # Admin privilege level allowed
        res.completion_code = 0x00 # success

    def cmd_set_sess_priv_level(self, res):
        print "DEBUG: IPMIMessageRequest.cmd_set_sess_priv_level(): "
        res.data = struct.pack('B',
                               ord(self.data[0])) # privilege level as requested
        res.completion_code = 0x00 # success

    def cmd_close_session(self, res):
        print "DEBUG: IPMIMessageRequest.cmd_close_session(): "
        res.completion_code = 0x00 # success

    ### Chassis Commands
    ##  28.1 Get Chassis Capabilities
    def cmd_get_chassis_capa(self, res):
        raise NotImplementedError(self.__class__.__name__ + '.' + inspect.currentframe().f_code.co_name)

    ##  28.3 Chassis Control Command
    def cmd_chassis_control(self, res):
        raise NotImplementedError(self.__class__.__name__ + '.' + inspect.currentframe().f_code.co_name)


        

class IPMIMessageResponse:
    """IPMI LAN Message Response structure """

    def __init__(self, request = None):
        self.packet = ""
        self.rqAddr = 0
        self.netFn = 0
        self.rqLUN = 0
        self.checksum_header = 0
        self.rsAddr = 0
        self.rqSeq = 0
        self.rsLUN = 0
        self.cmd = 0
        self.completion_code = 0xff # unspecified error
        self.data = ""
        self.checksum_data = 0

        if request:
            self.rqAddr = request.rqAddr
            self.netFn = request.netFn + 1
            self.rqLUN = request.rqLUN
            self.rsAddr = request.rsAddr
            self.rqSeq = request.rqSeq
            self.rsLUN = request.rsLUN
            self.cmd = request.cmd
            # completion_code and data needs to be set in the processing of the request
            # checksums will be calculated in pack()

    def dump(self):
        print "IPMIMessageResponse: rqAddr=0x%02x, netFn=0x%02x, rqLUN=0x%02x, rsAddr=0x%02x, rqSeq=0x%02x, rsLUN=0x%02x, cmd=0x%02x, completion_code=0x%02x" % \
            (self.rqAddr, self.netFn, self.rqLUN, self.rsAddr, self.rqSeq, self.rsLUN, self.cmd, self.completion_code)

    def unpack(self, packet):
        self.packet = packet
        raise NotImplementedError(self.__class__.__name__ + '.' + inspect.currentframe().f_code.co_name)

    def pack(self):
        #print "DEBUG: IPMIMessageResponse.pack(): "
        self.dump()
        self.packet = struct.pack('BB', self.rqAddr, (self.netFn << 2) + self.rqLUN)
        self.packet += struct.pack('B', ipmi_checksum(self.packet))
        self.packet += struct.pack('BBBB',
                                   self.rsAddr, (self.rqSeq << 2) + self.rsLUN,
                                   self.cmd, self.completion_code)
        self.packet += self.data
        self.packet += struct.pack('B', ipmi_checksum(self.packet))

        return self.packet

    def process(self, session):
        print "DEBUG: IPMIMessageResponse.process(): "
        reply = None
        return reply
