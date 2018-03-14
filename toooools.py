import time
import re
import logging
import logging.handlers
import sys
import os
import subprocess
import platform
import datetime
import signal
import pexpect
import requests

LOG_FILENAME=__file__
LOG_FILENAME=LOG_FILENAME.split('.')[0]+'.log'
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
logger_handler = logging.FileHandler(LOG_FILENAME)
logger_fortmater = logging.Formatter(fmt='%(asctime)s:%(funcName)s:%(lineno)d: [%(levelname)s] %(message)s', datefmt="%d-%m-%Y %H:%M:%S")
logger_handler.setFormatter(logger_fortmater)
logger.addHandler(logger_handler)
logging.getLogger().addHandler(logging.StreamHandler())
TIMEOUT=5

def ssh_login(ip,username,password,prompt,timeout=5):
    
    try: 
        obj = dict()
        obj['ip'] = ip
        obj['username'] = username
        obj['password'] = password
        obj['prompt'] = prompt
        obj['expect_session'] = ''
        logger.info("Connecting to the device - "+ ip+"\nIt may take some time")
        cmd = "ssh " +  str(username) + "@" + str(ip)
        s = pexpect.spawn(cmd, timeout=timeout)
        pexpect_log = file(LOG_FILENAME, 'w+')
        s.logfile_read = pexpect_log
	s.expect
        i = s.expect ([pexpect.TIMEOUT, pexpect.EOF, 'yes/no', 'assword:',r'(?<!\w)>'])
	logger.info("expect command execcuted")
        if i == 0:
	    logger.info("timeout prompt")
            logger.error("Timeout Error hit in Spawn. Is the - "+ip+" - reachable?")
            obj['expect_session'] = None
            return(None)
        elif i == 1:
	    logger.info("eof prompt")   
            logger.error("EOF Error hit in Spawn. Is the DUT - "+ip+" - reachable?")
            obj['expect_session'] = None
            return(None)
        elif i == 2:
	    logger.info("yes/no prompt")
            s.sendline('yes')
            s.expect ('assword:')
            s.sendline(password)
        elif i == 3:
	    logger.info("password prompt")
            s.sendline(password)
	    s.expect(prompt)
            logger.info("prompt reached in passwd prompt")
	    obj['expect_session'] = s
	    return(obj)
        elif i == 4:
            logger.info("normal prompt")
            obj['expect_session'] = s
            return(obj)   
        else:
            logger.info("Unexpected Prompt\n")
            pass
        s.expect(prompt)
        obj['expect_session'] = s
        return(obj)
    except:
        return(None)

def exec_cmd(obj,command):

    obj['expect_session'].sendline(command)
    try:
        obj['expect_session'].expect(obj['prompt'])
    except:
        pass
    out = obj['expect_session'].before
    return out

def main():
    s=ssh_login('10.102.56.220','root','freebsd','#')
    cmd=exec_cmd(s,"ifconfig")
    logger.info(cmd)
    '''
    s['expect_session'].sendline("ssh root@10.102.230.4")
    i= s['expect_session'].expect(['assword:','yes/no'])
    if i==0:
    	s['expect_session'].sendline('citrix')
    	s['expect_session'].expect('#')
    	s['expect_session'].sendline("xe vm-list")
    	s['expect_session'].expect('#')
    	logger.info(s['expect_session'].before) 
    elif i==1:
        s['expect_session'].sendline('yes')
        s['expect_session'].expect('assword:')
        s['expect_session'].sendline('citrix')
    	s['expect_session'].expect('#')
    	s['expect_session'].sendline("xe vm-list")
    	s['expect_session'].expect('#')
    	logger.info(s['expect_session'].before)
    '''
    logger.info(repr(s['expect_session'].before))
    s['expect_session'].sendline('xl console NSVM-229')
    # s['expect_session'].send('\r')
    #s['expect_session'].expect('(\r\n)+')
    #s['expect_session'].send('\r')
    #s['expect_session'].send('\r')
    #logger.info(repr(s['expect_session'].before)) 
    s['expect_session'].send('\n')
    #logger.info(repr(s['expect_session'].before))  
    s['expect_session'].expect(r'\s*>\s*')
    logger.info(repr(s['expect_session'].before))
    s['expect_session'].sendline('sh license')
    s['expect_session'].expect(r'\s*>\s*')
    logger.info(s['expect_session'].before)

if __name__ == '__main__':
   main()   
