class SMPPClientConfig(object):
    
    def __init__(self, **kwargs):
        self.host = kwargs['host']
        self.port = kwargs['port']
        self.username = kwargs['username']
        self.password = kwargs['password']
        self.systemType = kwargs.get('systemType', '')
        self.sessionInitTimerSecs = kwargs.get('sessionInitTimerSecs', 30)
        self.enquireLinkTimerSecs = kwargs.get('enquireLinkTimerSecs', 10)
        self.inactivityTimerSecs = kwargs.get('inactivityTimerSecs', 120)
        self.responseTimerSecs = kwargs.get('responseTimerSecs', 60)
        self.pduReadTimerSecs = kwargs.get('pduReadTimerSecs', 10)
        self.useSSL = kwargs.get('useSSL', False)
        self.SSLCertificateFile = kwargs.get('SSLCertificateFile', None)