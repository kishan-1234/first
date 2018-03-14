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

def usage():

	print("Usage : "+__file__.split('.')[0]+".py [-mpx <ip> <port>] [-vpx <xenserver ip> <VM ip>]")
	print("\t\t-mpx To recover MPX device.IP and Port Number has to provides as command line arguments respectively")
	print("\t\t-vpx To recover VPX device.VM's Xenserver IP and IP of the VM thathas to be provided as commad line argument respectively\n\t\t     If not able to login from ip enter VM name instead of IP")

if len(sys.argv) < 4:
	print("Please provide valid arguments\nSee Usage")
	usage()
	exit()

sys.argv[1].lower

if '-mpx' in sys.argv:
        ind = sys.argv.index('-mpx')
        if re.match(r'^(\d+\.){3}\d+$',sys.argv[ind+1]):
                ip = sys.argv[ind+1]
        else:
                print("Invalid IP address entered.See usage")
                usage()
                exit()
        if re.match(r'^\d+$',sys.argv[ind+2]):
		if int(sys.argv[ind+2]) > 7000:
                	port = sys.argv[ind+2]
		else:
			print "Enter a valid Console port greater than 7000"
			usage()
			exit()
        else:
                print("Invalid Port entered.See usage")
                usage()
                exit()
        LOG_FILENAME='/home/atsuser/Log/BU/'+ip+'_'+port+'.log'

if '-vpx' in sys.argv:
        ind = sys.argv.index('-vpx')
        if re.match(r'^(\d+\.){3}\d+$',sys.argv[ind+1]):
                xenserverip = sys.argv[ind+1]
        else:
                print("Invalid Xenserver IP entered.See usage")
                usage()
                exit()
        vmname = sys.argv[ind+2]
        LOG_FILENAME='/home/atsuser/Log/BU/'+xenserverip+'_'+vmname+'.log'
        
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
logger_handler = logging.FileHandler(LOG_FILENAME,'w+')
logger_fortmater = logging.Formatter(fmt='%(asctime)s:%(funcName)s:%(lineno)d: [%(levelname)s] %(message)s', datefmt="%d-%m-%Y %H:%M:%S")
logger_handler.setFormatter(logger_fortmater)
logger.addHandler(logger_handler)
logging.getLogger().addHandler(logging.StreamHandler())
TIMEOUT=5

def telnet_login(ip,port,console_user,username,password,prompt,sessionhandle,flag,timeout=15):
    
    try: 
        obj = dict()
        obj['ip'] = ip
        obj['port'] = port
        obj['username'] = username
        obj['password'] = password
        obj['prompt'] = prompt
        obj['expect_session'] = ''
        obj['ret_val'] = 0
	'''
	if flag is 1:
		pexpect_log = file(LOG_FILENAME, 'a')
	elif flag is 0:
		pexpect_log = file(LOG_FILENAME, 'w')
	'''
        if sessionhandle is None:
                logger.info("Connecting to the device - "+ ip+" "+port+"\nIt may take some time")
                cmd = "/usr/bin/telnet "+ ip +" "+ port+" \n\r"
                logger.info("======================================================================================")
                logger.info(cmd)
                logger.info("======================================================================================\n")
                s = pexpect.spawn(cmd, timeout=timeout)
        else:
                s=sessionhandle
        s.send('\r')  
	'''	
        if '-vpx' in sys.argv:
                pexpect_log = file(LOG_FILENAME, 'a+')
        else:
                pexpect_log = file(LOG_FILENAME, 'a+')	
	'''
        #s.logfile_read = pexpect_log
        i = s.expect([pexpect.TIMEOUT, pexpect.EOF, 'ogin:', 'db>','(?<!\w)>','#','OK'])
        if i == 0:
                s.sendcontrol('z')
                j = s.expect(['cli->',pexpect.TIMEOUT])
                if j == 0:
                        logger.info("cli -> prompt reached!!!!")
                elif j == 1:
                        logger.info("Timeout Error hit in Spawn. Is the - "+ip+" - reachable?")
                obj['expect_session'] = None
                obj['ret_val'] = 0
                return None
        elif i == 1:
                logger.info("EOF Error hit in Spawn. Is the DUT - "+ip+" - reachable?")
                obj['expect_session'] = None
                obj['ret_val'] = 0
                return None
        elif i == 2:
                logger.info("login prompt reached!!!")
                s.sendline(username)
                k = s.expect([pexpect.TIMEOUT,'assword:'])
                if k == 0:
                        logger.info("Does not reach Password prompt")
                        obj['expect_session'] = None
                        obj['ret_val'] = 0
                        return None
                elif k == 1:
                        s.sendline(password)
                        if username == 'nsrecover':
                                logger.info("username is nsrecover")
                                l = s.expect([pexpect.TIMEOUT,'ogin:','#'])
                                if l == 0:
                                        logger.info("Does not reach Password prompt")
                                        obj['expect_session'] = None
                                        obj['ret_val'] = 0
                                        return None
                                elif l == 1:
                                        logger.info("nsrecover/nsroot not working")
                                        obj['expect_session'] = None
                                        obj['ret_val'] = 0
                                        return None
                                elif l == 2:
                                        logger.info("# prompt reached by login through nsrecover/nsroot")    
                                        obj['expect_session'] = s 
                                        obj['ret_val'] = 5
                                        return obj
                        l = s.expect([pexpect.TIMEOUT,r'Done.*?>',r'-\s+login:'])
                        cmd = s.before
                        logger.info("======================================================================================")	
                        logger.info(cmd)
                        logger.info("======================================================================================\n")
                        if l == 0:
                                logger.info("Does not reach Password prompt or Password incorrect")
                                obj['expect_session'] = None
                                obj['ret_val'] = 0
                                return None    
                        elif l == 1:
                                logger.info("connected to console server "+str(ip)) 
                                obj['expect_session'] = s
                                obj['ret_val'] = 1
                                return obj
                        elif l == 2:
                                logger.info("nsroot/nsroot not working")
                                obj['expect_session'] = s   
                                obj['ret_val'] = 2
                                return obj        
        elif i == 3:
                logger.info("Debugger prompt reached!!!")
                s.sendline('c')
                s.expect('UP')
                time.sleep(90)
                obj['expect_session'] = s
                obj['ret_val'] = 6
                return obj
        elif i == 4:
                logger.info("normal prompt reached!!!")
                cmd=s.before
                logger.info("======================================================================================")
                logger.info(cmd)
                logger.info("======================================================================================\n")
                s.sendline('savec')
                s.expect('>')
                s.sendline('exit')
                s.expect('ogin:') 
                obj['expect_session'] = s
                obj['ret_val'] = 6
                return obj
        elif i == 5:
                logger.info("hash prompt reached!!!")  
                s.sendline('exit')
                j = s.expect([pexpect.TIMEOUT,'>','ogin:'])
                if j == 1:
                        obj['expect_session'] = s
                        s.sendline('savec')
                        s.expect('>')
                        s.sendline('exit')
                        s.expect('ogin:')
                        obj['ret_val'] = 6
                        return obj
                if j == 0:
                        obj['expect_session'] = None
                        obj['ret_val'] = 0
                        return None
                if j == 2:
                        obj['expect_session'] = s
                        obj['ret_val'] = 6
                        return obj    
        elif i == 6:
		# For VPX in case of OK prompt ID of VM will not be displayed from xl vm-list so this case wont hit
                logger.info("OK prompt reached!!!")
                s.sendline('unload')
                s.expect('OK')
                cmd=s.before
                s.send('ls')
                time.sleep(5)
                index = s.expect(['ls', pexpect.TIMEOUT], 1)
                s.send('\n')
                index = s.expect(['OK','quit'])
                cmd=s.before
                if index == 0 or index == 1:
                        s.sendline('q')
                        s.expect('OK')
                        cmd=cmd.split()
                        kernellist = list()
                        for x in cmd:
                                if re.match(r'ns-\d+\.\d+-\d+\.\d+',x):
                                        y = re.search(r'(ns-\d+\.\d+-\d+\.\d+)',x)
                                        kernellist.append(y.group(1))
                                if re.match(r'kernel.*?\.gz',x) and not re.search(r'[\[\]]',x):
                                        a = re.search(r'(\w+(\.\w+)+)\.gz',x)
                                        kernellist.append(a.group(1))
			logger.info("List of Kernels pesent on device")
                        logger.info(kernellist)
                        s.sendline("load /"+kernellist[-1])
                        logger.info("======================================================================================")
                        logger.info("load /"+kernellist[-1])
                        logger.info("======================================================================================\n")
			logger.info("Please wait for Netscaler to come up\n")
                        time.sleep(60)
                        s.expect('OK')
                        s.sendline("boot")
                        logger.info("Please wait for Netscaler to come up..1 minute passed\n")
                        time.sleep(60)	
                        logger.info("Please wait for Netscaler to come up..2 minutes passed\n")
                        time.sleep(60)	
                        logger.info("Please wait for Netscaler to come up..3 minutes passed\n")
                        time.sleep(60)	
                        logger.info("Please wait for Netscaler to come up..4 minutes passed\n")
                        time.sleep(60)	
                        logger.info("Please wait for Netscaler to come up..5 minutes passed\n")
                        time.sleep(20)	
                        logger.info("======================================================================================")
                        logger.info("Kernel Loaded!!!\nDevice booted")	
                        logger.info("======================================================================================\n")	
                        obj['expect_session'] = s
			if '-vpx' in sys.argv:
				obj['ret_val'] = 3
			else:
				obj['ret_val'] = 6
                        return obj
        else:
                logger.info("Unexpected Prompt\n")
                obj['expect_session'] = None
                obj['ret_val'] = 0
                return None
    except:
        return None

def ssh_login(ip,username,password,prompt,timeout=5):
    
    try: 
        obj = dict()
        obj['ip'] = ip
        obj['username'] = username
        obj['password'] = password
        obj['prompt'] = prompt
        obj['expect_session'] = ''
        logger.info("Connecting to the device - "+ ip+"\tIt may take some time")
        cmd = "ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " +  str(username) + "@" + str(ip)
        s = pexpect.spawn(cmd, timeout=timeout)
        #pexpect_log = file(LOG_FILENAME, 'w')
        #s.logfile_read = pexpect_log
        i = s.expect ([pexpect.TIMEOUT, pexpect.EOF, 'yes/no', 'assword:',prompt])
	#logger.info("expect command execcuted")
        if i == 0:
            logger.error("Timeout Error hit in Spawn. Is the - "+ip+" - reachable?")
            obj['expect_session'] = None
            return(None)
        elif i == 1:
            logger.error("EOF Error hit in Spawn. Is the DUT - "+ip+" - reachable?")
            obj['expect_session'] = None
            return(None)
        elif i == 2:
            s.sendline('yes')
            s.expect ('assword:')
            s.sendline(password)
        elif i == 3:
            s.sendline(password)
	    s.expect(prompt)
	    obj['expect_session'] = s
	    return(obj)
        elif i == 4:
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
        logger.info("Prompt not found\nTrying to login to VPX")
        pass
    out = obj['expect_session'].before
    return out

def main():

	global vmname 
        session = None
        if '-mpx' in sys.argv:
                session=telnet_login(ip,port,'root','nsroot','nsroot','>',None,0)
        if '-vpx' in sys.argv:
                xenserversession=ssh_login(xenserverip,'root','freebsd','#')
		cmd = exec_cmd(xenserversession,"xe vm-list params=name-label,networks")
		cmd = cmd.split()
		tempvmname = vmname
		if re.match(r'^(\d+\.){3}\d+$',vmname):
			logger.info("VM Ip is provided as argument")
			if vmname in cmd:
				ind = cmd.index(vmname)
 				vmname = cmd[ind-4]
                cmd = exec_cmd(xenserversession,"xl vm-list")
                logger.info(cmd)
                cmd = cmd.split()
                cmd = cmd[5:]
                cmd = cmd[:-2]
                if vmname in cmd:
                        ind = cmd.index(vmname)
                        vmid = cmd[ind-1]
                        logger.info("VM id is "+vmid)
                else:
			if re.match(r'^(\d+\.){3}\d+$',tempvmname):
				logger.info("Cant find the given VM Ip in the provided Xenserver")
			else:
                        	logger.error("Cant find the given VM name in Xenserver.\nPlease check the given VM name")
                        exit()
		#xenserversession['prompt'] = '\r\n'
                xenserversession['expect_session'].sendline("xl console "+vmid+"\r")
		#xenserversession['expect_session'].expect(r'\r(\n)+')
		#xenserversession['expect_session'].send('\r')
		session=telnet_login('vpx','vpx','root','nsroot','nsroot','>',xenserversession['expect_session'],0)
		'''
		k = xenserversession['expect_session'].expect(['>','ogin:'])
		#xenserversession['expect_session'].expect('>')
		if k == 1:
			xenserversession['expect_session'].send("nsroot\r")
			xenserversession['expect_session'].expect("assword:")
			xenserversession['expect_session'].send("nsroot\r")
		xenserversession['expect_session'].expect('>')
		xenserversession['expect_session'].send("sh ha node\r")		
                xenserversession['expect_session'].expect('>')
		logger.info(xenserversession['expect_session'].before)
		xenserversession['expect_session'].send('exit\r')
		xenserversession['expect_session'].expect('Bye!')
		#logger.info(xenserversession['expect_session'].before)
		xenserversession['expect_session'].sendcontrol(']')
		#session = telnet_login('vpx','vpx','root','nsroot','nsroot','>',xenserversession['expect_session'],0)
                '''
        if session == None:
                logger.info("Unable to connect to the console of the box!")	
                
        elif session['ret_val'] == 1:
                cmd1=exec_cmd(session,"ping -c 4 10.102.1.98")
                time.sleep(2)
                logger.info("======================================================================================")
                logger.info(cmd1)
                logger.info("======================================================================================\n")
                if re.search(r'0\.0%',cmd1):
                        logger.info("Obelix is pingable from device")
                else:
                        logger.info("Obelix is NOT pingable from device")
                        cmd2=exec_cmd(session,"stat int | grep DOWN")
                        cmd2=cmd2.split()
                        logger.info("======================================================================================")
                        logger.info(cmd2)
                        logger.info("======================================================================================\n")
                        down_ints=list()
                        n=(len(cmd2)-5)/6
                        i=0
                        while i<n:
                                down_ints.append(cmd2[5+i*6])
                                i+=1
                        for i in down_ints:
                                cmd3=exec_cmd(session,"en int "+i)
                                logger.info("======================================================================================")
                                logger.info(cmd3)
                                logger.info("======================================================================================\n") 
                                cmd4=exec_cmd(session,"ping -c 4 10.102.1.98")
                                logger.info(cmd4)
                                session['expect_session'].close()
                                if re.search(r'0\.0%',cmd4):
                                        logger.info("Obelix is now pingable from device!!!!!!!!!\n")
                                else:
                                        logger.info("Obelix is still not pingable\nPlease check manually!")	
		session['expect_session'].send('exit\r')
		session['expect_session'].expect([pexpect.TIMEOUT,'ogin:'])	
		if '-vpx' in sys.argv:
			session['expect_session'].sendcontrol(']')	

        elif session['ret_val'] == 2:
                logger.info("Trying login through nsrecover/nsroot")
                if '-vpx' in sys.argv:
                        session = telnet_login('vpx','vpx','root','nsrecover','nsroot','>',session['exect_session'],1)
			session['expect_session'].sendcontrol(']')
                else:
                        session = telnet_login(ip,port,'root','nsrecover','nsroot','>',None,1)       
        
        elif session['ret_val'] == 3:
		logger.info("======================================================================================") 
		logger.info("Device Recovered please Login now")
		logger.info("======================================================================================\n") 
 
        elif session['ret_val'] == 5:
                logger.info("logged into BSD through nsrecover/nsroot")
                #session['expect_session'].close()
		if '-vpx' in sys.argv:
			session['expect_session'].sendcontrol(']')               

        elif session['ret_val'] == 6:
                logger.info("Trying to login again to device")
                
                if '-vpx' in sys.argv:
                        session = telnet_login('vpx','vpx','root','nsroot','nsroot','>',session['expect_session'],1)
                else:
                        session = telnet_login(ip,port,'root','nsroot','nsroot','>',None,1)
                        
                if session == None:
                        logger.info("Not able to recover device please check manually")
                elif session['ret_val'] == 1:
                        cmd1=exec_cmd(session,"ping -c 4 10.102.1.98")
                        time.sleep(2)
                        logger.info("======================================================================================")
                        logger.info(cmd1)
                        logger.info("======================================================================================\n")
                        if re.search(r'\s0\.0% packet loss',cmd1,re.IGNORECASE):
                                logger.info("Obelix is pingable from device")
                        else:
                                logger.info("Obelix is NOT pingable from device")
                                cmd2=exec_cmd(session,"stat int | grep DOWN")
                                logger.info("======================================================================================")
                                logger.info(cmd2)
                                logger.info("======================================================================================\n")
                                cmd2=cmd2.split() 
                                down_ints=list()
                                n=(len(cmd2)-5)/6
                                i=0
                                while i<n:
                                        down_ints.append(cmd2[5+i*6])
                                        i+=1
                                for i in down_ints:
                                        cmd3=exec_cmd(session,"en int "+i)
                                        logger.info("======================================================================================")
                                        logger.info(cmd3)
                                        logger.info("======================================================================================\n")
                                cmd4=exec_cmd(session,"ping -c 4 10.102.1.98")
                                logger.info(cmd4)
                                session['expect_session'].close()
                                if re.search(r'0\.0%',cmd4):
                                        logger.info("Obelix is now pingable from device!!!!!!!!!\n")
                                else:
                                        logger.info("Obelix is still not pingable\nPlease check manually!")
                                #session['expect_session'].close()
			session['expect_session'].send('exit\r')
			session['expect_session'].expect([pexpect.TIMEOUT,'ogin:'])	
			if '-vpx' in sys.argv:
				session['expect_session'].sendcontrol(']')
		elif session['ret_val'] == 6:
			logger.info("======================================================================================") 
			logger.info("Device Recovered please Login now")
			logger.info("======================================================================================\n")                
               
if __name__ == '__main__':
    main()  
