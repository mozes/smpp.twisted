SMPP 3.4 client built on Twisted

http://www.nowsms.com/discus/messages/1/24856.html

Example
-------
    import logging
    from twisted.internet import reactor, defer
    from smpp.twisted.client import SMPPClientTransceiver, SMPPClientService
    from smpp.twisted.config import SMPPClientConfig

    class SMPP(object):

        def __init__(self, config=None):
            if config is None:
                config = SMPPClientConfig(host='localhost', port=999, username='uname', password='pwd')
            self.config = config
        
        @defer.inlineCallbacks
        def run(self):
            try:
                #Bind
                smpp = yield SMPPClientTransceiver(self.config, self.handleMsg).connectAndBind()
                #Wait for disconnect
                yield smpp.getDisconnectedDeferred()
            except Exception, e:
                print "ERROR: %s" % str(e)
            finally:
                reactor.stop()
    
        def handleMsg(self, smpp, pdu):
            """
            NOTE: you can return a Deferred here
            """
            print "Received pdu %s" % pdu
    
    if __name__ == '__main__':
        logging.basicConfig(level=logging.DEBUG)
        SMPP().run()
        reactor.run()
        
Credits
=======
* Thanks to [rtrdev](https://github.com/rtrdev) for adding support for SMPP servers
* Thanks to [Fourat Zouari](https://github.com/fourat) for finding and fixing an enquirelinks bug