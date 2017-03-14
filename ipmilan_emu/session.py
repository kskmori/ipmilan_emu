import uuid
import struct
import hmac
import hashlib

USER = "pacemaker"
PASSWORD = "pacemakerpass"

class Config:
    def __init__(self):
        self.username = 'pacemaker'
        self.password = 'pacemakerpass'
        self.guid = uuid.uuid4().bytes
        #self.guid = uuid.uuid1().bytes[::-1] # little endian

    def readConfig(self, file=None):
        raise NotImplementedError

class Session:

    # only single session for the present
    theSession = None

    @classmethod
    def getCurrentSession(cls):
        if cls.theSession == None:
            cls.theSession = Session()
        return cls.theSession
    
    def __init__(self):
        self.config = Config()
        self.remote_session_id = 0
        self.managed_session_id = 0
        self.remote_random = 0
        self.managed_random = 0
        self.remote_seq_no = 0
        self.managed_seq_no = 0
        self.role = 0
        self.SIK = b''
        self.K1 = b''
        self.K2 = b''

    def generateSessionKeys(self):
        # calclulate SIK
        text = struct.pack('<16s16sBB',
                           self.remote_random,
                           self.managed_random,
                           self.role,
                           len(self.config.username))
        text += self.config.username
        self.SIK = hmac.new(self.config.password, text, hashlib.sha1).digest()

        # generate additional keying material
        self.K1 = hmac.new(self.SIK, '\x01' * 20, hashlib.sha1).digest()
        self.K2 = hmac.new(self.SIK, '\x02' * 20, hashlib.sha1).digest()


REMOTE_SESSION_ID = 0 # temporary global; should be managed
MANAGED_SESSION_ID = 0x1234abcd # temporary fixed; should be managed

