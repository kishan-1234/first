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
        i = s.expect ([pexpect.TIMEOUT, pexpect.EOF, 'yes/no', 'assword:',prompt])
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

def ns_ha_check(session,session_ip,ha_ip):

    if not session:
        logger.info("Cannot ssh into device "+session_ip)
    	return 1

    else:
    	cmd=exec_cmd(session,"show ip | grep 1")
        logger.info(cmd)
        cmd=cmd.split()
        if 'NetScaler' not in cmd:
            logger.info("NSIP is not present on device "+session_ip)
            return 2
        cmd=exec_cmd(session,"show ha node | grep \"Node\" ")    
        logger.info(cmd)
        stri=re.findall(r'(?<=Node ID:)\s*\d+',cmd)
        if len(stri)!=2:
            logger.info('HA is not present on this setup\nAdding HA on this setup')
            logger.info(exec_cmd(session,"add ha node 1 "+ha_ip))
            logger.info("Please wait for few seconds while HA comes up")
            l=list()
            start_time=time.time()
            while len(l)!=2:
                time.sleep(5)
            	cmd=exec_cmd(session,"show ha node | grep \"Node State:\" ")
                logger.info(cmd)
                l=re.findall(r'UP',cmd)
                elapsed_time=time.time()-start_time
                if elapsed_time >=20:
                    logger.info("More than twenty seconda passed, it seems there is an issue with Testbed\nPleae check manually")
                    break    
            if len(l)==2 and l[0]=='UP' and l[1]=='UP':
                return 0
            else:
            	return 1 	        
                    
        else:
            cmd=exec_cmd(session,"show ha node | grep \"Node State:\" ")
            logger.info(cmd)
            l=re.findall(r'UP',cmd)
            if len(l)!=2:
            	logger.info("HA is not proper on this setup (IP) "+session_ip)
            	return 1
            else: 	
            	return 0	

def ns_error_check(session,session_ip):

    if not session:
        logger.info("Cannot ssh into device "+session_ip)
    	return 1
    else:
        session['prompt']='#'
        cmd=exec_cmd(session,"shell")
        cmd=exec_cmd(session,"cd /var/core")
        logger.info(cmd)
        cmd=exec_cmd(session,"cat bounds")
        logger.info(cmd)
        cmd=cmd.split()
        n=cmd[2]
        cmd=exec_cmd(session,"cd "+n)
        logger.info(cmd)
        cmd=exec_cmd(session,"ls")
        logger.info(cmd)    
        session['prompt']='>'
        cmd=exec_cmd(session,"exit")
        return 0

def usage():
    
    logger.info("Usage : "+__file__.split('.')[0]+".py <Resource file> [-ha] [-c] [-ap]")
    logger.info("\t\t-ha To check if NSIP is present and HA pair is created, if not present then script will create HA")
    logger.info("\t\t-c To check for errors in /var/core bounds on NetScaler")
    logger.info("\t\t-ap To make Admin partition on testbed 7700, Pleae remember to provide ip for the testbed in a file")

def main():

    try: 
        if len(sys.argv)<=2:
            logger.info("Please provide valid arguements\nSee usage")
            usage()
            exit() 
	f_open=open(sys.argv[1],"r")  
	sys.argv=[i.lower() for i in sys.argv]
        ip = list()
        for line in f_open:
            if re.search(r'^((\d+\.)+\d+-)+(\d+\.)+\d+$',line):
                ip=re.split(r'[-\n]',line)
                ip1=ip[0]
                ip2=ip[1]
        if '-c' in sys.argv:
	    for ips in ip:
		if len(ips)>0:
            		ip1_session=ssh_login(ips,'nsroot','nsroot','>')
	    		cmd=exec_cmd(ip1_session,"sh license")
            		logger.info(cmd)
            		cmd=exec_cmd(ip1_session,"sh ha node")
            		logger.info(cmd)
            		cmd=exec_cmd(ip1_session,"sh version")
            		logger.info(cmd)
	    		var=ns_error_check(ip1_session,ip1)
            		if var==0:
                		logger.info("Done checking errors on "+ips)
            		else:
                		logger.info("Some error occured\nPlease check manually")     
        if '-ha' in sys.argv:
            ip1_session=ssh_login(ip1,'nsroot','nsroot','>')
            var=ns_ha_check(ip1_session,ip1,ip2)
            if var==0:
                logger.info("SUCCESS\nHA setup is in proper condition to run test")
            else:
                logger.info("FAILED\nPlease correct the testbed") 	    
            ip2_session=ssh_login(ip2,'nsroot','nsroot','>')
            var=ns_ha_check(ip2_session,ip2,ip1) 
            if var==0:
                logger.info("SUCCESS\nHA setup is in proper condition to run test")
            else:
                logger.info("FAILED\nPlease correct the testbed")	
	if '-ap' in sys.argv:
	    cmd=os.system("partition_maker 10.106.81.170 1")
	    logger.info(cmd)
	    time.sleep(5)  
	    session=ssh_login('10.106.81.170','nsroot','nsroot','>')
	    cmd=exec_cmd(session,"add vlan 95 -sharing enabled")
	    logger.info(cmd)	
	    cmd=exec_cmd(session,"bind vlan 95 -ifnum 1/2 1/3")
	    logger.info(cmd)
            cmd=exec_cmd(session,"bind partition p1 -vlan 95")
	    logger.info(cmd)
 	    cmd=exec_cmd(session,"switch partition p1")
	    logger.info(cmd)
            cmd=exec_cmd(session,"add ns ip 10.106.95.129 255.255.255.128")
	    logger.info(cmd)
	    cmd=exec_cmd(session,"add ns ip 10.106.95.61 255.255.255.128")
	    logger.info(cmd)
 	    cmd=exec_cmd(session,"add route 0 0 10.106.95.1")
	    logger.info(cmd)
	    cmd=exec_cmd(session,"bind vlan 95 -ipAddress 10.106.95.129 255.255.255.128")
	    logger.info(cmd)
	    cmd=exec_cmd(session,"bind vlan 95 -ipAddress 10.106.95.61 255.255.255.128")
	    logger.info(cmd)
	    cmd=exec_cmd(session,"savec")
	    logger.info(cmd)
            cmd=exec_cmd(session,"ping -c 4 10.102.1.98")
	    logger.info(cmd)

    except IOError as e:
        logger.info("Filename "+sys.argv[1]+" was not found!!!\nPlease specify file name correctly"+str(e)) 


if __name__ == '__main__':
    main()   
