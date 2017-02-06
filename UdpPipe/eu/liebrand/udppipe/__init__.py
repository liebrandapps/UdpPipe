import socket
import threading
from ConfigParser import NoSectionError, NoOptionError, RawConfigParser
from os.path import isfile, join, exists, basename
import time
import logging
from logging.handlers import RotatingFileHandler
import exceptions
import sys
import select
import eu.liebrand.udppipe.Utility
import cStringIO
import signal
import os
import Queue
import datetime
from optparse import OptionParser
import errno
from daemon import runner
from threading import Thread
import uuid
from datetime import date
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Signature import PKCS1_v1_5
import json
import traceback




class Config:

    STRING_KEYS=["msgFormat", "logFileName", "secretKey", "id", "forwardHost", \
                 "headHost", "privateKey", "publicKey", "certificate"]
    INT_KEYS=["maxFilesize", "listenPort", "adminPort", "forwardPort", "logLevel", "headPort", "timeout", "pipePort"]
    BOOLEAN_KEYS=["enableLogging", "enableAdmin"]

    DEFAULTS={"enableLogging" :"yes",
              "logFileName" : "/tmp/udppipe.log",
              "maxFilesize" : 1000000,
              "msgFormat" : "%(asctime)s, %(levelname)s, %(module)s, %(lineno)d, %(message)s",
              "logLevel" :20,
              "enableAdmin" :"no"
              }

    
    def __init__(self, cfgFile, section):
        self.section=section
        self.cfg=RawConfigParser(Config.DEFAULTS)
        _=self.cfg.read(cfgFile)

    def hasKey(self, dct, key):
        k=key.upper()
        for d in dct:
            if d.upper() == k:
                return d
        return None
    
    def hasSection(self, section):
        return self.cfg.has_section(section)
    
    def hasOption(self, option):
        return self.cfg.has_option(self.section, option)

    def __getattr__(self, name):
        key=self.hasKey(Config.STRING_KEYS, name)
        if not key is None:
            return self.cfg.get(self.section, key)
        key=self.hasKey(Config.INT_KEYS, name)
        if not key is None:
            return self.cfg.getint(self.section, key)
        key=self.hasKey(Config.BOOLEAN_KEYS, name)
        if not key is None:
            return self.cfg.getboolean(self.section, key)
        return None

    def setSection(self, newSection):
        tmp=self.section
        self.section=newSection
        return tmp

class DateTimeEncoder(json.JSONEncoder):

        
    def default(self, obj):
        if isinstance(obj, datetime.datetime):
            return {
                '__type__' : 'seconds',
                'seconds' : int(obj.strftime('%s')),
                'info' : str(obj)
            }   
        else:
            return json.JSONEncoder.default(self, obj)
    
class DateTimeDecoder(json.JSONDecoder):
    
    def __init__(self, *args, **kargs):
        json.JSONDecoder.__init__(self, object_hook=self.dict_to_object,
                             *args, **kargs)
    
    def dict_to_object(self, d): 
        if '__type__' not in d:
            return d

        return datetime.datetime.fromtimestamp(d['seconds'])


class PipeBase:
    
    CONFIG_DIR="./"
    CONFIG_FILE="udppipe.ini"

    SECTION_PORTCONFIG="portConfig_%d"    
    
    KEY_CFGFILE="__cfgFile"
    
    FIELD_HOST='host'
    FIELD_PORT='port'
    FIELD_OP='OP'
    FIELD_SRVPORT='srvPort'
    FIELD_UDPDATA='udpData'
    FIELD_PRIVKEY="privateKey"
    FIELD_PUBKEY="publicKey"
    FIELD_CERTIFICATE="certificate"
    FIELD_ADMINPORT="adminPort"
    FIELD_ADMINSTATUS="adminStatus"
    
    VALUE_UDP='udp'
    VALUE_PING='ping'
    VALUE_CONFIG='__cfg__'
    VALUE_KEY='__key__'
    
    IDX_FORWARDHOST=3
    IDX_FORWARDPORT=4


    def __init__(self, section):
        
        self.section=section
        path=join(PipeBase.CONFIG_DIR, PipeBase.CONFIG_FILE)
        if not(exists(path)):
            self.printLogLine(sys.stderr,"[UDPPIPE] No config file %s found at %s" % (PipeBase.CONFIG_FILE, PipeBase.CONFIG_DIR))
            self.setupOk=False
            return
        self.cfg=Config(path, section)
        self.readConfig(self.cfg)
        self.stdin_path = '/dev/null'
        self.stdout_path = self.cfg.logFileName
        self.stderr_path = self.cfg.logFileName
        self.pidfile_path =  '/tmp/udppipe.pid'
        self.pidfile_timeout = 5         
        #self.setupLogger(self.cfg)
        self.setupOk=True
        #self.log.info("[%s] init done" % (section))
        self.packetsIn=0
        self.packetsOut=0
        self.UDPBytesIn=0
        self.UDPBytesOut=0
        self.TCPBytesIn=0
        self.TCPBytesOut=0
        self.reconnects=0
        signal.signal(signal.SIGUSR1, self.toggleLogLevel)
        signal.signal(signal.SIGUSR2, self.logStats)
        signal.signal(signal.SIGQUIT, self.dumpstacks)
        self.startTime=datetime.datetime.now()
        self.lastPing=None
        

        
    def getTimeStamp(self):
        return time.strftime('%d.%m.%Y %H:%M:%S',  time.localtime(time.time()))

    def printLogLine(self, fl, message):
        fl.write('%s %s\n' % (self.getTimeStamp(), message))
        fl.flush()

    def setupLogger(self, cfg):
        try:
            self.log=logging.Logger(self.section)
            loghdl=RotatingFileHandler(cfg.logFileName, 'a', cfg.maxFilesize, 4)
            loghdl.setFormatter(logging.Formatter(cfg.msgFormat))
            loghdl.setLevel(cfg.logLevel)
            self.log.addHandler(loghdl)
            self.log.disabled=False
            return True
        except exceptions.Exception, e:
            self.printLogLine(sys.stderr, "[UDPPIPE] Unable to initialize logging. Reason: %s" % e)
            return False
        
    def toggleLogLevel(self, sigNo, stackFrame):
        if self.log.getEffectiveLevel()==10:
            newLevel=20
        else:
            newLevel=10
        self.log.setLevel(newLevel)

    def logStats(self, sigNo, stackFrame):
        now=datetime.datetime.now()
        uptime=now-self.startTime
        self.log.info("[%s] %d Packets in, %d Packets out" % (self.section, self.packetsIn, self.packetsOut))
        self.log.info("[%s] UDP Traffic %d bytes in, %d bytes out, TCP Traffic %d bytes in, %d bytes out" % (self.section, self.UDPBytesIn, self.UDPBytesOut, self.TCPBytesIn, self.TCPBytesOut))
        self.log.info("[%s] Uptime %s, Reconnects %d" % (self.section, str(uptime), self.reconnects))
        if self.lastPing is None:
            self.log.info("[%s] Last Ping: never" % (self.section))
        else:
            ago=now-self.lastPing
            self.log.info("[%s] Last Ping: %s (%s ago)" % (self.section, str(self.lastPing), str(ago)))

    def dumpstacks(self, signal, frame):
        id2name = dict([(th.ident, th.name) for th in threading.enumerate()])
        code = []
        for threadId, stack in sys._current_frames().items():
            code.append("\n# Thread: %s(%d)" % (id2name.get(threadId,""), threadId))
            for filename, lineno, name, line in traceback.extract_stack(stack):
                code.append('File: "%s", line %d, in %s' % (filename, lineno, name))
                if line:
                    code.append("  %s" % (line.strip()))
            code.append("\n###########################################################")
        self.log.info("\n".join(code))
        
    def readConfig(self, cfg):
        #cfg.set(self.section, PipeBase.KEY_CFGFILE)
        i=0
        self.listenerConfig=[]
        while True:
            i+=1
            section=PipeBase.SECTION_PORTCONFIG % (i)
            if cfg.hasSection(section):
                tmpSection=cfg.setSection(section)
                listenPort=cfg.listenPort
                cfgId=cfg.id
                if cfgId==PipeBase.VALUE_CONFIG:
                    self.printLogLine(sys.stderr, "WARN: Don't use ID %s for a port configuration" % (cfgId))
                if self.section==Head.SECTION:
                    forwardHost=None
                    forwardPort=None
                else:
                    forwardHost=cfg.forwardHost
                    forwardPort=cfg.forwardPort
                self.listenerConfig.append([ cfgId, listenPort, None, forwardHost, forwardPort ])
                cfg.setSection(tmpSection)
            else:
                break
        return cfg
        

class Head(PipeBase):

    SECTION="head"
    BYTES_IN, BYTES_OUT, PACKETS_IN, PACKETS_OUT, CONNECTS = range(0,5)
    STATUS=['wait', 'idle', 'busy']

    
    def __init__(self):
        PipeBase.__init__(self, Head.SECTION)
        self.readHeadConfig(self.cfg)
        self._terminate=False
        signal.signal(signal.SIGTERM, self.terminate)
        signal.signal(signal.SIGINT, self.terminate)
        self.adminSocket=None
        self._terminateAdmin=False
        self.statisticEvent = threading.Event()
        self.statisticThread = None
        self.status=0


    def terminate(self, sigNo, stackFrame):
        if sigNo==signal.SIGINT:
            self.log.info("[Head] Terminating upon Keyboard Interrupt")
        if sigNo==signal.SIGTERM:
            self.log.info("[Head] Terminating upon Signal Term")
        self._terminate=True
        self.pipeSocket.close()
        self.statisticEvent.set()
        if self.adminSocket is not None:
            self._terminateAdmin=True
            self.adminSocket.close()
            self.adminSocket=None
            
        

    def readHeadConfig(self, cfg):
        self.pipePort=cfg.pipePort
        self.enableHostNameCheck=cfg.hasOption("tailHostname")
        if self.enableHostNameCheck:
            self.tailHostname=cfg.tailHostname
        self.enableAdmin=cfg.enableAdmin
        
         
    def run(self):
        # Important: logging cannot be setup any earlier as the RotatingFileHandler produces errors
        # in combination with the daemon function
        self.setupLogger(self.cfg)
        socketArray=[]

        # Step #1: Setup all the sockets
        self.pipeSocket=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.pipeSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.pipeSocket.bind(('', self.pipePort))
        self.pipeSocket.listen(5)
        thrd=None
        self.isThreadRunning=False
        self.controlPipe=os.pipe()
        socketArray.append(self.controlPipe[0])
        while not(self._terminate):
            try:
                self.log.info("[Head] Waiting for >Tail< to connect on port %d" % (self.pipePort))
                (clientSocket, address) = self.pipeSocket.accept()
                if self.enableHostNameCheck:
                    data = socket.gethostbyname(self.tailHostname)
                    if address[0]!=data:
                        self.log.warn("[Head] Connection attempt from wrong IP (%s but expected %s)" % (address[0], data))
                        clientSocket.close()
                        continue
                self.log.info("[Head] Connection from tail at %s:%d" % (address[0], address[1]))
                # now we are ready for incoming udp messages
                try:
                    if len(socketArray)==1:
                        for lstCfg in self.listenerConfig:
                            lstCfg[2]=socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                            lstCfg[2].bind(('', lstCfg[1]))
                            socketArray.append(lstCfg[2])
                            self.log.info("[Head] UDP Listener <%s> on port <%d>" % (lstCfg[0], lstCfg[1]))
                except socket.error as e:
                    if e.errno==errno.EADDRINUSE:
                        self.log.error("[Head] Unable to listen on port %d - already in use" % (lstCfg[1]))
                    else:
                        self.log.error("[Head] Unable to listen on port %d - Error %d %s" % (lstCfg[1], e.errno, errno.errorcode[e.errno]))
                    self._terminate=True
                    clientSocket.close()
                    continue
                self.reconnects+=1
                socketArray.append(clientSocket)
                if self.isThreadRunning:
                    self._terminateThread=True
                    os.write(self.controlPipe[1], 'x')
                    thrd.join()
                thrd=Thread(target=self.handleMessages, args=(socketArray, clientSocket))
                thrd.start()
                    
            except socket.error as e:
                if e.errno == errno.EINTR:
                    pass
                elif e.errno == errno.ECONNRESET:
                    self.log.warn("[Head] Tail disconnected")
                    if clientSocket in socketArray:
                        socketArray.remove(clientSocket)
                else:
                    self.log.exception(e)
                    raise
            except Exception as e:            
                self.log.exception(e)
                raise
                    
                    
                        
    def handleMessages(self, socketArray, clientSocket):
        self.isThreadRunning=True            
        # Step #2: listen on all the sockets
        lastReport=datetime.datetime.now()
        self._terminateThread=False
        while not(self._terminate) and not(self._terminateThread):
            try:
                ready=select.select(socketArray, [], [], 180)
                if ready[0]:
                    for r in ready[0]:
                        if r==self.controlPipe:
                            os.read(self.controlPipe[0],1)
                            continue
                        if r==clientSocket:
                            # we received something from the tail
                            dta=r.recv(5)
                            if len(dta)==0:
                                #connection reset
                                self.log.warn("[Head] >Tail< disconnected")
                                clientSocket.close()
                                self._terminateThread=True
                                continue
                            while(len(dta)<5):
                                dta+=r.recv(5-len(dta))
                            sockRd=eu.liebrand.udppipe.Utility.SockRead()
                            buf=cStringIO.StringIO(dta)
                            _,_,length=sockRd.read(buf)
                            data=[]
                            tmp=length
                            while length>0:
                                chunk=r.recv(length)
                                data.append(chunk)
                                length-=len(chunk)
                            self.log.debug("[Head] Received %d bytes from >Tail<" % (tmp))
                            self.TCPBytesIn+=tmp
                            self.packetsIn+=1
                            readDict=eu.liebrand.udppipe.Utility.ReadDictionary()
                            fields=readDict.read(''.join(data))
                            if fields[PipeBase.FIELD_OP]==PipeBase.VALUE_PING:
                                self.lastPing=datetime.datetime.now()
                                self.status=1
                                continue
                            if fields[PipeBase.FIELD_OP]==PipeBase.VALUE_CONFIG:
                                for k in fields.keys():
                                    if k.startswith('++'):
                                        k=k[2:]
                                        found=False
                                        for lstCfg in self.listenerConfig:
                                            if k==lstCfg[0]:
                                                found=True
                                                # existing ID
                                                if fields['++' + k]!=lstCfg[1]:
                                                    # listening port changed
                                                    self.log.info("[Head] Received new port for service id %s (old %d -> new %d)" % (k, lstCfg[1], fields[k]))
                                                    lstCfg[2].close()
                                                    socketArray.remove(lstCfg[2])
                                                    lstCfg[1]=fields['++'+k]
                                                    lstCfg[2]=socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                                                    lstCfg[2].bind(('', lstCfg[1]))
                                                    socketArray.append(lstCfg[2])
                                        if not(found):
                                            s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                                            s.bind(('', fields['++' + k]))
                                            self.listenerConfig.append([ k, fields['++' + k], s, None, None ])
                                            socketArray.append(s)
                                            self.log.info("[Head] New UDP Listener <%s> on port <%d>" % (k, fields['++' + k]))
                                        continue
                                    if k==PipeBase.FIELD_PUBKEY:
                                        self.publicKey=fields[k]
                                        continue
                                    if k==PipeBase.FIELD_ADMINPORT:
                                        self.adminPort=fields[k]
                                        self.enableAdmin=(self.adminPort!=0)
                                        if self.enableAdmin:
                                            if self.adminSocket is not None:
                                                self.log.info("[Head] Disabling current admin")
                                                self._terminateAdmin=True
                                                self.adminSocket.close()
                                                self.adminSocket=None
                                                self.adminThread.join()
                                            self.log.info("[Head] Admin is enabled on port %d" % (self.adminPort))
                                            self._terminateAdmin=False
                                            self.adminThread=threading.Thread(target=self.adminServer, name="AdminServer-Thread")
                                            self.adminThread.daemon=True
                                            self.adminThread.start()
                                            if self.statisticThread is None:
                                                self.statisticThread=threading.Thread(target=self.statisticThread, name="Statistic-Thread")
                                                self.statisticThread.daemon=True
                                                self.statisticThread.start()
                                        continue
                                    
                                for lstCfg in self.listenerConfig:
                                    found=False
                                    for k in fields.keys():
                                        k=k[2:]
                                        if k==lstCfg[0]:
                                            found=True
                                            break
                                    if not(found):
                                        lstCfg[2].close()
                                        self.listenerConfig.remove(lstCfg)
                                        socketArray.remove(lstCfg[2])
                                        self.log.info("[Head] Deleted UDP Listener <%s> on port <%d>" % (lstCfg[0], lstCfg[1]))            
                                continue
                            # find the outbound socket
                            found=False
                            for lstCfg in self.listenerConfig:
                                if lstCfg[1]==fields['srvPort']:
                                    self.status=2
                                    lstCfg[2].sendto(fields[PipeBase.FIELD_UDPDATA], (fields['host'], fields['port']))
                                    found=True
                                    self.log.debug("[Head] Forwarded response packet of %d bytes to %s:%d for port %d" % \
                                                  (len(fields[PipeBase.FIELD_UDPDATA]), fields['host'], fields['port'], \
                                                   fields['srvPort']))
                                    self.UDPBytesOut+=len(fields[PipeBase.FIELD_UDPDATA])
                                    self.packetsOut+=1
                                    break
                            if not(found):
                                self.log.warn("[Head] Received a response for an unknown client on port %d" % (fields['srvPort']))
                                continue
                                        
                        for lstCfg in self.listenerConfig:
                            if r==lstCfg[2]:
                                self.status=2
                                # we have an inbound message
                                udpData, address=r.recvfrom(4096)
                                self.log.debug("[Head] Received %d bytes from %s:%d" % (len(udpData), address[0], address[1]))
                                self.UDPBytesIn+=len(udpData)
                                self.packetsIn+=1
                                # we need to send udpData, listening Port, address
                                util=eu.liebrand.udppipe.Utility.SockWrite()
                                dataBuffer=cStringIO.StringIO()
                                util.writeString(PipeBase.FIELD_OP, PipeBase.VALUE_UDP, dataBuffer)
                                util.writeString(PipeBase.FIELD_HOST, address[0], dataBuffer)
                                util.writeLong(PipeBase.FIELD_PORT, address[1], dataBuffer)
                                util.writeLong(PipeBase.FIELD_SRVPORT, lstCfg[1], dataBuffer)
                                util.writeBinary(PipeBase.FIELD_UDPDATA, udpData, dataBuffer)
                                dta=dataBuffer.getvalue()
                                ctlBuffer=cStringIO.StringIO()
                                util.writeLongDirect(len(dta), ctlBuffer)
                                util.writeBinaryDirect(dta, ctlBuffer)
                                dta=ctlBuffer.getvalue()
                                bytesSnd=0
                                while bytesSnd<len(dta):
                                    bytesSnd=bytesSnd+clientSocket.send(dta[bytesSnd:])
                                self.log.debug("[Head] Send %d bytes to >Tail<" % (bytesSnd))
                                self.TCPBytesOut+=bytesSnd
                                self.packetsOut+=1
                                dataBuffer.close()
                                ctlBuffer.close()
                                break
                else:
                    self.log.warn("[Head] No activity for 180 seconds, assuming Tail is absent")
                    self._terminateThread=True
                    self.status=0
                now=datetime.datetime.now()
                if (now-lastReport).seconds>=(3600*24) or self._terminateThread or self._terminate:
                    self.logStats(0, None)
                    lastReport=now
            except select.error, (_errno, _strerror):
                if _errno == errno.EINTR:
                    continue
            except socket.error, (_errno, _strerror):
                if _errno == errno.ECONNRESET:
                    self.log.warn("[Head] Tail disconnected")
                else:
                    self.log.exception(socket.error)
                self._terminateThread=True
                self.status=0
            except Exception as e:            
                self.log.exception(e)
                self._terminateThread=True
                self.status=0
        if clientSocket in socketArray:
            socketArray.remove(clientSocket)
        self.isThreadRunning=False
        self.status=0
        
        
    def adminServer(self):
        pubKeyObj=RSA.importKey(self.publicKey)
        adminSocket=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        adminSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        adminSocket.bind(('', self.adminPort))
        adminSocket.listen(5)
        while not(self._terminate) and not(self._terminateAdmin):
            self.log.info("[Head] Waiting for >Admin< to connect on port %d" % (self.adminPort))
            try:
                (clientSocket, address)=adminSocket.accept()
                self.log.info("[Head] Connection from >Admin< at %s:%d" % (address[0], address[1]))
                dta=clientSocket.recv(5)
                if len(dta)==0:
                    #connection reset
                    self.log.warn("[Head] >Admin< disconnected")
                    clientSocket.close()
                    continue
                while(len(dta)<5):
                    dta+=clientSocket.recv(5-len(dta))
                sockRd=eu.liebrand.udppipe.Utility.SockRead()
                buf=cStringIO.StringIO(dta)
                _,_,length=sockRd.read(buf)
                data=[]
                tmp=length
                while length>0:
                    chunk=clientSocket.recv(length)
                    data.append(chunk)
                    length-=len(chunk)
                self.log.debug("[Head] Received %d bytes from >Admin<" % (tmp))
                readDict=eu.liebrand.udppipe.Utility.ReadDictionary()
                fields=readDict.read(''.join(data))
                retData={}
                if fields.has_key('payload') and fields.has_key('signature'):
                    dta=fields['payload']
                    signature=fields['signature']
                    hsh = SHA256.new(dta)
                    verifier=PKCS1_v1_5.new(pubKeyObj)
                    signed=verifier.verify(hsh, signature)
                    if not(signed):
                        self.log.info("[Head] Received INVALID request from >Admin>")
                        retData['status']='fail'
                    else:
                        dct=json.loads(dta)
                        self.log.info("[Head] Received valid request from >Admin> (op %s)" % (dct['op']))
                    
                        if dct['op']=="challenge":
                            retData["challenge"]=str(uuid.uuid4())
                        if dct['op']=="status":
                            retData["tailConnected"]=self.isThreadRunning
                            retData["lastPing"]=self.lastPing
                            retData["startTime"]=self.startTime
                            retData["reconnects"]=self.reconnects
                            retData["noOfPorts"]=len(self.listenerConfig)
                            retData["connStatus"]=Head.STATUS[self.status]
                        if dct['op']=="statisticHour":
                            for mn in self.byMinute:
                                tmp={}
                                tmp['bytesIn']=mn[Head.BYTES_IN]
                                tmp['bytesOut']=mn[Head.BYTES_OUT]
                                tmp['packetsIn']=mn[Head.PACKETS_IN]
                                tmp['packetsOut']=mn[Head.PACKETS_OUT]
                                tmp['reconnects']=mn[Head.CONNECTS]
                                retData[str(mn)]=tmp
                        if dct['op']=="statisticDay":
                            for hr in self.byHour:
                                tmp={}
                                tmp['bytesIn']=hr[Head.BYTES_IN]
                                tmp['bytesOut']=hr[Head.BYTES_OUT]
                                tmp['packetsIn']=hr[Head.PACKETS_IN]
                                tmp['packetsOut']=hr[Head.PACKETS_OUT]
                                tmp['reconnects']=hr[Head.CONNECTS]
                                retData[str(hr)]=tmp
                            pass    
                        retData['status']='ok'
                else:
                    retData['status']='fail'
                sockWt=eu.liebrand.udppipe.Utility.SockWrite()
                buf=cStringIO.StringIO()
                retStrg=json.dumps(retData, cls=DateTimeEncoder)
                sockWt.writeString('result', retStrg, buf)
                dta=buf.getvalue()
                ctlBuffer=cStringIO.StringIO()
                sockWt.writeLongDirect(len(dta), ctlBuffer)
                sockWt.writeBinaryDirect(dta, ctlBuffer)
                dta=ctlBuffer.getvalue()
                bytesSnd=0
                while bytesSnd<len(dta):
                    bytesSnd=bytesSnd+clientSocket.send(dta[bytesSnd:])
                buf.close()
                ctlBuffer.close()
                self.log.info("[Head] Send %d bytes to >Admin<" % (bytesSnd))
                clientSocket.close()
            except socket.error as e:
                if e.errno == errno.EINTR:
                    pass
                else:
                    self.log.exception(e)     


    
    def statisticTracker(self):
        self.byHour={}
        self.byMinute={}
        now=datetime.datetime.now()
        waitTime=59-now.second
        if waitTime>0:
            self.statisticEvent.wait(waitTime)
        baseline=[self.UDPBytesIn, self.UDPBytesOut, self.packetsIn, self.packetsOut, self.reconnects]
        lastHour=25
        while not(self._terminate):
            self.statisticEvent.wait(60)
            now=datetime.datetime.now()
            minute=now.minute
            self.byMinute[now.minute]=[self.UDPBytesIn-baseline[0], self.UDPBytesOut-baseline[1], 
                              self.packetsIn-baseline[2], self.packetsOut-baseline[3], self.reconnects-baseline[4]]
            baseline=[self.UDPBytesIn, self.UDPBytesOut, self.packetsIn, self.packetsOut, self.reconnects]
            hour=now.hour
            if hour!=lastHour:
                lastHour=hour
                self.byHour[hour]=[self.byMinute[minute][0], self.byMinute[minute][1], self.byMinute[minute][2], self.byMinute[minute][3], self.byMinute[minute][4] ]    
            else:
                self.byHour[hour]=[self.byHour[hour][0]+self.byMinute[minute][0], self.byHour[hour][1]+self.byMinute[minute][1], 
                              self.byHour[hour][2]+self.byMinute[minute][2], self.byHour[hour][3]+self.byMinute[minute][3], self.byHour[hour][4]+self.byMinute[minute][4] ]

        
                
class Tail(PipeBase):

    SECTION="tail"
    WAIT4RETRY=300
    
    
    def __init__(self):
        PipeBase.__init__(self, Tail.SECTION)
        self._terminate=False
        signal.signal(signal.SIGTERM, self.terminate)
        signal.signal(signal.SIGINT, self.terminate)
        self.readTailConfig(self.cfg)
        self.sourceIds={}
        self.sourceIdLock=threading.Lock()
        self.responseQ=Queue.Queue()
        self.connected=False


    def readTailConfig(self, cfg):
        self.headHost=cfg.headHost
        self.headPort=cfg.headPort
        self.timeout=cfg.timeout
        self.adminSocket=None
        self.enableAdmin=cfg.enableAdmin
        if self.enableAdmin:
            self.adminPort=cfg.adminPort
            self.publicKey=cfg.publicKey
            self.privateKey=cfg.privateKey
            self.certificate=cfg.certificate
        
    def terminate(self, sigNo, stackFrame):
        if sigNo==signal.SIGINT:
            self.log.info("[Tail] Terminating upon Keyboard Interrupt")
        if sigNo==signal.SIGTERM:
            self.log.info("[Tail] Terminating upon Signal Term")
        self._terminate=True
        if self.connected:
            os.write(self.controlPipe[1], 'x')
        for s in self.sourceIds.keys():
            v=self.sourceIds[s]
            v[0].put({})
            os.write(v[1][1], 'x')
        if self.adminSocket is not None:
            self.adminSocket.close()
            self.adminSocket=None
            
        
    def run(self):
        # Important: logging cannot be setup any earlier as the RotatingFileHandler produces errors
        # in combination with the daemon function
        self.setupLogger(self.cfg)
        self.controlPipe=os.pipe()
        self.fds=[]
        self.fds.append(self.controlPipe[0])
        sockRd=eu.liebrand.udppipe.Utility.SockRead()
        sockWt=eu.liebrand.udppipe.Utility.SockWrite()
        
        if self.enableAdmin:
            t=threading.Thread(target=self.adminServer)
            t.daemon=True
            t.start()

        # Step #1: Connect to the head
        servSocket=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # wait for 2 seconds before trying to connect (avoid missing each other, when cron 
        # starts head & tail at the same time
        time.sleep(2)
        lastReport=datetime.datetime.now()
        while not(self._terminate):
            try:
                self.log.info("[Tail] Trying to connect to >Head< at %s:%d" % (self.headHost,self.headPort))
                servSocket.connect((self.headHost,self.headPort))
                self.connected=True
                self.log.info("[Tail] Connected to >Head< at %s" % (str(servSocket.getpeername())))
                self.fds.append(servSocket)
                
                # send config
                dataBuffer=cStringIO.StringIO()
                sockWt.writeString(PipeBase.FIELD_OP, PipeBase.VALUE_CONFIG, dataBuffer)
                for lstCfg in self.listenerConfig:
                    sockWt.writeLong("++" + lstCfg[0], lstCfg[1], dataBuffer)
                if (self.enableAdmin):
                    keyPath=self.publicKey
                    if not(os.path.exists(keyPath)):
                        pwd=os.environ['PWD']
                        keyPath=os.path.join(pwd,keyPath)
                    if not(os.path.exists(keyPath)):
                        self.log.warn("[Tail] Could not enable admin functionality, public key not found at %s nor %s" % (self.publicKey, keyPath))
                        self.enableAdmin=False
                if not(self.enableAdmin):
                    sockWt.writeLong(PipeBase.FIELD_ADMINPORT, 0, dataBuffer)
                else:
                    sockWt.writeLong(PipeBase.FIELD_ADMINPORT, self.adminPort, dataBuffer)
                    fl=open(keyPath, 'r')
                    pubKey=fl.read()
                    fl.close()
                    sockWt.writeString(PipeBase.FIELD_PUBKEY, pubKey, dataBuffer)
                dta=dataBuffer.getvalue()
                ctlBuffer=cStringIO.StringIO()
                sockWt.writeLongDirect(len(dta), ctlBuffer)
                sockWt.writeBinaryDirect(dta, ctlBuffer)
                dta=ctlBuffer.getvalue()
                bytesSnd=0
                while bytesSnd<len(dta):
                    bytesSnd=bytesSnd+servSocket.send(dta[bytesSnd:])
                dataBuffer.close()
                ctlBuffer.close()
                self.log.info("[Tail] Send %d UDP port configs to head" % (len(self.listenerConfig)))
                
                while not(self._terminate) and self.connected:
                    try:
                        ready=select.select(self.fds, [], [], 60)
                    except select.error, (_errno, _strerror):
                        if _errno == errno.EINTR:
                            continue
                        else:
                            raise
                    if len(ready[0])==0:
                        # send something every 60 seconds to avoid a timeout on the connection
                        self.log.debug("[Tail] Sending ping to head")
                        dataBuffer=cStringIO.StringIO()
                        sockWt.writeString(PipeBase.FIELD_OP, PipeBase.VALUE_PING, dataBuffer)
                        dta=dataBuffer.getvalue()                            
                        ctlBuffer=cStringIO.StringIO()
                        sockWt.writeLongDirect(len(dta), ctlBuffer)
                        sockWt.writeBinaryDirect(dta, ctlBuffer)
                        dta=ctlBuffer.getvalue()
                        bytesSnd=0
                        while bytesSnd<len(dta):
                            bytesSnd=bytesSnd+servSocket.send(dta[bytesSnd:])
                        dataBuffer.close()
                        ctlBuffer.close()
                        now=datetime.datetime.now()
                        self.lastPing=now
                        if (now-lastReport).seconds>=(3600*24):
                            self.logStats(0, None)
                            lastReport=now
                        continue
                    for r in ready[0]:
                        if r==servSocket:
                            dta=servSocket.recv(5)
                            if len(dta)==0:
                                # Head has gone
                                self.connected=False
                                servSocket.close()
                                continue
                            while(len(dta)<5):
                                dta+=r.recv(5-len(dta))
                            buf=cStringIO.StringIO(dta)
                            _,_,length=sockRd.read(buf)
                            self.log.debug("[Tail] Received %ld bytes from >Head<" % (length))
                            data=[]
                            while length>0:
                                chunk=r.recv(length)
                                data.append(chunk)
                                length-=len(chunk)
                            self.TCPBytesIn+=len(chunk)
                            self.packetsIn+=1
                            readDict=eu.liebrand.udppipe.Utility.ReadDictionary()
                            fields=readDict.read(''.join(data))
                            # received the data as dict - now we need to find out whether we already have thread
                            # for host:port running
                            if fields[PipeBase.FIELD_OP]==PipeBase.VALUE_UDP:
                                sourceId=str(fields[PipeBase.FIELD_SRVPORT]) + "@" + fields[PipeBase.FIELD_HOST] + ":" + str(fields[PipeBase.FIELD_PORT])
                                self.sourceIdLock.acquire()
                                if self.sourceIds.has_key(sourceId):
                                    self.log.debug("[Tail] Adding packet to existing handler")
                                    self.sourceIds[sourceId][0].put(fields)
                                    #wake up thread
                                    os.write(self.sourceIds[sourceId][1][1],'x')
                                else:
                                    self.log.debug("[Tail] Creating new handler for source id %s" % (sourceId))
                                    found=False
                                    for lstCfg in self.listenerConfig:
                                        if lstCfg[1]==fields[PipeBase.FIELD_SRVPORT]:
                                            found=True
                                            break
                                    if found:
                                        q=Queue.Queue()
                                        q.put(fields)
                                        self.sourceIds[sourceId]=[q, os.pipe()]
                                        t=threading.Thread(target=self.handleUdpPacket, args=(lstCfg, sourceId, fields))
                                        t.daemon=True
                                        t.start()
                                    else:
                                        self.log.error("[TAIL] Received UDP Packet for port %d without having a forward configured" % fields[PipeBase.FIELD_SRVPORT])
                                self.sourceIdLock.release()
                            if fields[PipeBase.FIELD_OP]==PipeBase.VALUE_CONFIG:
                                #todo send a dict / json with the head configuration over
                                pass
                        if r==self.controlPipe[0]:
                            os.read(self.controlPipe[0],1)
                            data=self.responseQ.get()
                            dataBuffer=cStringIO.StringIO()
                            sockWt.writeString(PipeBase.FIELD_OP, PipeBase.VALUE_UDP, dataBuffer)
                            sockWt.writeString(PipeBase.FIELD_HOST, data[PipeBase.FIELD_HOST], dataBuffer)
                            sockWt.writeLong(PipeBase.FIELD_PORT, data[PipeBase.FIELD_PORT], dataBuffer)
                            sockWt.writeLong(PipeBase.FIELD_SRVPORT, data[PipeBase.FIELD_SRVPORT], dataBuffer)
                            sockWt.writeBinary(PipeBase.FIELD_UDPDATA, data[PipeBase.FIELD_UDPDATA], dataBuffer)
                            dta=dataBuffer.getvalue()
                            ctlBuffer=cStringIO.StringIO()
                            sockWt.writeLongDirect(len(dta), ctlBuffer)
                            sockWt.writeBinaryDirect(dta, ctlBuffer)
                            dta=ctlBuffer.getvalue()
                            bytesSnd=0
                            while bytesSnd<len(dta):
                                bytesSnd=bytesSnd+servSocket.send(dta[bytesSnd:])
                            dataBuffer.close()
                            ctlBuffer.close()
                            self.responseQ.task_done()
                            self.TCPBytesOut+=bytesSnd
                            self.packetsOut+=1
                            self.log.debug("[Tail] Forwarded response packet of %d bytes for listening port %d from client %s:%d to >Head<" % \
                                            (len(data[PipeBase.FIELD_UDPDATA]), data[PipeBase.FIELD_SRVPORT], data[PipeBase.FIELD_HOST], data[PipeBase.FIELD_PORT]  ) )
            except socket.error as e:
                self.connected=False
                if e.errno == errno.EINTR and self._terminate:
                    pass
                elif e.errno==errno.ECONNREFUSED or e.errno==errno.EBADF or e.errno==errno.ECONNRESET or e.errno==errno.ENETUNREACH:
                    self.log.warn("[Tail] Unable to connect to host %s:%d. Will try again in %d seconds.(Reason %s)" % (self.headHost,self.headPort, Tail.WAIT4RETRY, str(e)))
                    servSocket.close()
                    if servSocket in self.fds:
                        self.fds.remove(servSocket)
                    self.connected=False
                    time.sleep(Tail.WAIT4RETRY)
                    servSocket=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                else:
                    raise
        self.logStats(0, None)
        self.log.info("[Tail] Terminating")
                            
    def handleUdpPacket(self, listenerCfg, sourceId, fields):
        queue=self.sourceIds[sourceId][0]
        localfds=self.sourceIds[sourceId][1]
        udpSocket=socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        lastAction=datetime.datetime.now()
        initial=True
        while not(self._terminate) and (datetime.datetime.now()-lastAction).seconds<self.timeout:
            if not(initial):
                ready=select.select([localfds[0], udpSocket], [], [], self.timeout)
            else:
                ready=[[localfds[0]],]
                os.write(localfds[1], 'x')
                initial=False
            for r in ready[0]:
                if r==localfds[0]:
                    os.read(localfds[0],1)
                    while not(queue.empty()):
                        if self._terminate:
                            continue
                        #output udp, we should have sthg in the queue   
                        try:
                            data=queue.get(True, 5)
                            if self._terminate or len(data.keys())==0:
                                continue
                            udpSocket.sendto(data[PipeBase.FIELD_UDPDATA], (listenerCfg[PipeBase.IDX_FORWARDHOST], listenerCfg[PipeBase.IDX_FORWARDPORT]))
                            queue.task_done()
                            self.UDPBytesOut+=len(data[PipeBase.FIELD_UDPDATA])
                            self.packetsOut+=1
                            self.log.debug("[Tail] Send %d bytes to local address %s:%d" % (len(data[PipeBase.FIELD_UDPDATA]), listenerCfg[PipeBase.IDX_FORWARDHOST], listenerCfg[PipeBase.IDX_FORWARDPORT]))
                        except Queue.Empty:
                            pass
                    lastAction=datetime.datetime.now()
                if r==udpSocket:
                    #inbound udp, need to pass it back to head
                    udpData, address=udpSocket.recvfrom(4096)
                    data={}
                    data[PipeBase.FIELD_UDPDATA]=udpData
                    data[PipeBase.FIELD_HOST]=fields[PipeBase.FIELD_HOST]
                    data[PipeBase.FIELD_PORT]=fields[PipeBase.FIELD_PORT]
                    data[PipeBase.FIELD_SRVPORT]=fields[PipeBase.FIELD_SRVPORT]
                    self.responseQ.put(data)
                    os.write(self.controlPipe[1], 'x')
                    self.log.debug("[Tail] Received %d bytes from local address %s:%d" % (len(udpData), address[0], address[1]))
                    lastAction=datetime.datetime.now()
                    self.UDPBytesIn+=len(udpData)
                    self.packetsIn+=1
                    
        # upon exit we need to remove the queue object to avoid receiving more requests
        self.sourceIdLock.acquire()
        del self.sourceIds[sourceId]
        self.sourceIdLock.release()
        self.log.debug("[Tail] Removed handler for source id %s" % (sourceId))

    def adminServer(self):
        sockWt=eu.liebrand.udppipe.Utility.SockWrite()
        adminSocket=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        adminSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        adminSocket.bind(('', self.adminPort))
        adminSocket.listen(5)
        while not(self._terminate):
            self.log.info("[Tail] Waiting for 'Admin' to connect on port %d" % (self.adminPort))
            try:
                (clientSocket, address)=adminSocket.accept()
                self.log.info("[Tail] Connection from 'Admin' at %s:%d" % (address[0], address[1]))
                dataBuffer=cStringIO.StringIO()
                privateKeyPath=self.privateKey
                if not(os.path.exists(privateKeyPath)):
                    pwd=os.environ['PWD']
                    privateKeyPath=os.path.join(pwd,privateKeyPath)
                if not(os.path.exists(privateKeyPath)):
                    self.log.warn("[Tail] Could not enable admin functionality, **private** key not found at %s nor %s" % (self.privateKey, privateKeyPath))
                    self.enableAdmin=False
                certficatePath=self.certificate
                if not(os.path.exists(certficatePath)):
                    pwd=os.environ['PWD']
                    certficatePath=os.path.join(pwd, certficatePath)
                if not(os.path.exists(certficatePath)):
                    self.log.warn("[Tail] Could not enable admin functionality, **public** key not found at %s nor %s" % (self.publicKey, certficatePath))
                    self.enableAdmin=False
                if not(self.enableAdmin):
                    sockWt.writeString(PipeBase.FIELD_ADMINSTATUS, "FAIL", dataBuffer)
                else:
                    # read keys
                    fl=open(privateKeyPath, 'r')
                    privKey=fl.read()
                    fl.close()
                    privKey="".join(privKey.split("-----")[2].split())
                    fl=open(certficatePath, 'r')
                    cert=fl.read()
                    fl.close()
                    cert="".join(cert.split("-----")[2].split())
                    #privKey=privKey[2]
                    #privKey="".join(privKey.split())
                    sockWt.writeString(PipeBase.FIELD_ADMINSTATUS, "ok", dataBuffer)
                    sockWt.writeString(PipeBase.FIELD_PRIVKEY, privKey, dataBuffer)
                    sockWt.writeString(PipeBase.FIELD_PUBKEY, cert, dataBuffer)
                    sockWt.writeString(PipeBase.FIELD_HOST, self.headHost, dataBuffer)
                    sockWt.writeLong(PipeBase.FIELD_PORT, self.adminPort, dataBuffer)
                dta=dataBuffer.getvalue()
                ctlBuffer=cStringIO.StringIO()
                sockWt.writeLongDirect(len(dta), ctlBuffer)
                sockWt.writeBinaryDirect(dta, ctlBuffer)
                dta=ctlBuffer.getvalue()
                bytesSnd=0
                while bytesSnd<len(dta):
                    bytesSnd=bytesSnd+clientSocket.send(dta[bytesSnd:])
                dataBuffer.close()
                ctlBuffer.close()     
                clientSocket.close()
                self.log.info("[Tail] Send %d bytes to 'Admin'" % (bytesSnd))
            except socket.error as e:
                if e.errno == errno.EINTR:
                    pass
                else:
                    self.log.exception(e)
            
    
if __name__ == '__main__':
    parser = OptionParser('"usage: %prog start|stop [option]')
    parser.add_option("-H", "--head", action="store_const", const="head", dest="mode",
                  help="run as head end of the pipe")
    parser.add_option("-T", "--tail", action="store_const", const="tail", dest="mode",
                  help="run as tail end of the pipe")
    (options, args) = parser.parse_args()
    if(len(args)==0):
        print "specify start|stop|restart"
        sys.exit()
    if options.mode=="head":
        head=Head()
        daemon_runner = runner.DaemonRunner(head)
        daemon_runner.do_action()
    if options.mode=="tail":
        tail=Tail()
        daemon_runner = runner.DaemonRunner(tail)
        daemon_runner.do_action()
        