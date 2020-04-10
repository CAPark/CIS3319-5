#ID constants
ID_C = "CIS3319USERID"
ID_V = "CIS3319SERVERID"
ID_TGS = "CIS3319TGSID"

#port addresses
host = '127.0.0.1'
TGS_port = 10000
V_port = 10001

#timeout values
lifetime2 = 60000
lifetime4 = 86400000

#buffer size
CON_SIZE = 1024000000  # 1024 MB

#message objects
class Packet:
    def __init__(self, content, TS, ID_C, ID_V, ID_TGS,
                    lifetime2, lifetime4):
        self.content = content
        self.TS = TS
        self.ID_C = ID_C
        self.ID_V = ID_V
        self.ID_TGS = ID_TGS
        self.lifetime2 = lifetime2
        self.lifetime4 = lifetime4
