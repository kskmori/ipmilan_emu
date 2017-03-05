import uuid

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
    
    def __init__(self):
        self.config = Config()
        self.remote_session_id = 0
        self.managed_session_id = 0
        self.remote_random = 0
        self.managed_random = 0
        self.role = 0
        

REMOTE_SESSION_ID = 0 # temporary global; should be managed
MANAGED_SESSION_ID = 0x1234abcd # temporary fixed; should be managed

