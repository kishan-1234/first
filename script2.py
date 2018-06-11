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
import MySQLdb

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
logger_handler = logging.FileHandler('SCRIPT2.txt','w+')
logger_fortmater = logging.Formatter(fmt='%(asctime)s:%(funcName)s:%(lineno)d: [%(levelname)s] %(message)s', datefmt="%d-%m-%Y %H:%M:%S")
logger_handler.setFormatter(logger_fortmater)
logger.addHandler(logger_handler)
logging.getLogger().addHandler(logging.StreamHandler())


def ssh_login(ip,username,password,prompt,Timeout=15):
    
#    try: 
        obj = dict()
        obj['ip'] = ip
        obj['username'] = username
        obj['password'] = password
        obj['prompt'] = prompt
        obj['expect_session'] = ''
        logger.info("Connecting to the device - "+ ip+"\tIt may take some time")
        cmd = "ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " +  str(username) + "@" + str(ip)
        s = pexpect.spawn(cmd, timeout=Timeout)
	logger.info('spawned')
        i = s.expect ([pexpect.TIMEOUT, pexpect.EOF, 'yes/no', 'assword:',prompt])
        if i == 0:
            logger.error("Timeout Error hit in Spawn. Is the - "+ip+" - reachable?")
            obj['expect_session'] = None
            return(None)
        elif i == 1:
            logger.error("EOF Error hit in Spawn. Is the DUT - "+ip+" - reachable?")
            obj['expect_session'] = None
            return(None)
        elif i == 2:
	    logger.info('yes/no')
            s.sendline('yes')
            s.expect ('assword:')
            s.sendline(password)
        elif i == 3:
	    logger.info('pswd prompt!')
            s.sendline(password)
	    j = s.expect([prompt,'assword:'])
	    if j == 0:
		logger.info('$ promot reached')
	    	obj['expect_session'] = s
	    	return(obj)
	    elif j == 1:
		logger.info("Cant SSH.Incorrect Xenserver password entered!")
		return None
        elif i == 4:
	    logger.info(s.before)
	    logger.info('normal')
            obj['expect_session'] = s
            return(obj)   
        else:
            logger.info("Unexpected Prompt\n")
            pass
        s.expect(prompt)
        obj['expect_session'] = s
        return(obj)

def exec_cmd(obj,command):

    obj['expect_session'].sendline(command)
    try:
        obj['expect_session'].expect(obj['prompt'])
    except:
        logger.info("Prompt not found\nTrying to login to VPX")
    out = obj['expect_session'].before
    return out

def main():

	newtestbedid = sys.argv[3]	
	testbedid = sys.argv[2]
	xenserversession=ssh_login('10.106.80.180','atsuser','atsuser','\$',3)
	cmd = exec_cmd(xenserversession,'ifconfig')
	logger.info(cmd)
	xenserversession['prompt'] = '>'	
	cmd = exec_cmd(xenserversession,'mysql')
	logger.info(cmd)
	#xenserversession['prompt'] = '>'	
	cmd = exec_cmd(xenserversession,'use ATS_MOD;')
	logger.info(cmd)
	#xenserversession['prompt'] = '>'	
	cmd = exec_cmd(xenserversession,'select * from resource where testbedId = \''+testbedid+'\';')
	logger.info(cmd)
	resource = re.split(r'\s*[|\r]\s*',cmd)
	resource = resource[7:-3]
	resource.append('')
	logger.info(resource)
	logger.info(len(resource))
	for i in range(len(resource)/5):
		logger.info(resource[5*i+0])
		logger.info(resource[5*i+1])
		logger.info(resource[5*i+2])
		logger.info(resource[5*i+3])
	logger.info(len(resource))
	anakin = ssh_login('10.102.1.97','atsuser','atsuser','\$',3)
	cmd = exec_cmd(anakin,'ls')
	logger.info(cmd)
	anakin['prompt'] = 'assword: '
	cmd = exec_cmd(anakin,'mysql -u root -p')
	logger.info(cmd)
	anakin['prompt'] = '>'
	cmd = exec_cmd(anakin,'freebsd')
	logger.info(cmd)
	cmd = exec_cmd(anakin,'use ATS_MOD;')
	logger.info(cmd)
	for i in range(len(resource)/5):
		logger.info(i)
		query = 'insert into resource (IP,hostname,resourceId,testbedId) values (\''+resource[5*i+0]+'\',\''+resource[5*i+1]+'\',\''+resource[5*i+2]+'\',\''+resource[5*i+3]+'\');'
		logger.info(query)
		cmd = exec_cmd(anakin,query)
		logger.info(cmd)	
	#db = MySQLdb.connect(host="10.106.80.180",user="root",passwd="",db="ATS_MOD")
	#db.close()	
if __name__ == '__main__':
    main() 
