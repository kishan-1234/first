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

	print("Usage : "+__file__.split('.')[0]+".py <IP of device> [-ip <IP address>] [-mpx <Console ip> <Console port>] [-vpx <xenserver ip> <Xenserver username> <Xenserver Password> <VM ip|VM name>] [-t <testbed name>] [-eats <ip>] [-powerip <PowerIP:Powerpath>] [-powerports <Ports>] [-log <log path>] [-int <interfaces>]")
        print("\t\t-ip IP to SSH into the DUT")
	print("\t\t-mpx To recover MPX device.Console IP and Console Port Number has to provides as command line arguments respectively")
	print("\t\t-vpx To recover VPX device.VM's Xenserver IP, Xenserver username, Xenserver password and IP of the VM has to be provided as commad line argument respectively\n\t\t     If not able to login from ip enter VM name instead of IP.")
	print("\t\t-eats To recover EATS testbed DUT.IP of the dut has to be provided as argument")		
        print("\t\t-powerip Console sever IP address followed by colon, followed by exact path needed in console server")
        print("\t\t-powerports Comma seperated ports on which powercycle is to be performed")
        print("\t\t-log Followed by exact path and filename where log is to be generated")
        print("\t\t-int To enable only the specified interfaces")
        
        
if len(sys.argv) < 3:
	print("Please provide valid arguments\nSee Usage")
	usage()
	exit()

sys.argv[1].lower
eats_flag = 0
ok_flag = 0
kernel = ''

try:
        def checker(string,regex,num,error,*args):
                if string in args[0]:
                        ind = args[0].index(string)
                        if re.match(regex,args[0][ind+num]):
                                return args[0][ind+num]
                        else:
                                print(error)
                                usage()
                                exit()
                                
        eats_ip = checker('-eats',r'^(\d+\.){3}\d+$',1,'Invalid IP entered.See usage',sys.argv)        

	if '-eats' in sys.argv:
		eats_flag = 1
		eats_file = open("/export/home/atsuser/Scripts/ATS_Internal/EATS_DUT_DETAILS.txt","r")
		cont = eats_file.readlines()
		for line in cont:
			line = line.split()
			if 0 < len(line):
				if line[0]==eats_ip:
					if line[3]=='MPX' or line[3]=='mpx':
						if re.match(r'^(\d+\.){3}\d+$',line[1]):
							file_ip = line[1]
						else:
							print("Incorrect IP present in EATS testbed file corresponding to "+eats_ip)
							exit()
						if re.match(r'^\d+$',line[2]):
							if int(line[2]) > 7000:
                						file_port = line[2]
						else:
							print("Incorrect Port present in EATS testbed file corresponding to "+eats_ip)
							exit() 
						sys.argv = sys.argv[:1]
						sys.argv.extend(['-mpx',file_ip,file_port])
					elif line[3]=='VPX' or line[3]=='vpx':
						if re.match(r'^(\d+\.){3}\d+$',line[4]):
							file_xen_ip = line[4]
						else:
							print("Incorrect Xenserver IP present in EATS testbed file corresponding to "+eats_ip)
							exit()
						if re.match(r'\w+$',line[5]):
							file_xen_user = line[5]
						else:
							print("Incorrect Xenserver username present in EATS testbed file corresponding to "+eats_ip)
							exit()
						if re.match(r'^\w+$',line[6]):
							file_xen_pass = line[6]
						else:
							print("Incorrect Xenserver password in EATS testbed file corresponding to "+eats_ip)
							exit()
						file_vmname = " ".join(str(x) for x in line[7:])
						sys.argv = sys.argv[:1]
						sys.argv.extend(['-vpx',file_xen_ip,file_xen_user,file_xen_pass,file_vmname])


        ip = checker('-mpx',r'^(\d+\.){3}\d+$',1,'Invalid IP address entered.See usage',sys.argv)
        temp_port = checker('-mpx',r'^\d+$',2,'Invalid Port entered.See usage',sys.argv)
                
	if '-mpx' in sys.argv:
                if int(temp_port)>7000:
                        port = temp_port
                else:
                        print "Enter a valid Console port greater than 7000"
                        usage()
                        exit()
		if eats_flag==1:
			LOG_FILENAME='/export/home/atsuser/eats_logs/EATS_RECOVERY_LOG.txt'
		else:	
        		LOG_FILENAME='/home/atsuser/Log/BU/'+ip+'_'+port+'.log'

        xenserverip = checker('-vpx',r'^(\d+\.){3}\d+$',1,'Invalid Xenserver IP entered.See usage',sys.argv)
        xen_user = checker('-vpx',r'^\w+$',2,'Incorrect Xenserver username entered.See usage',sys.argv)
        xen_pass = checker('-vpx',r'^\w+$',3,'Incorrect Xenserver password entered.See usage',sys.argv)
        
	if '-vpx' in sys.argv:
                vmid = None
                uuid = None
                ind = sys.argv.index('-vpx')
        	vmname = sys.argv[ind+4]
		for i in range(5,len(sys.argv)-ind):	
			vmname = vmname + ' ' + sys.argv[ind+i] 	
		if eats_flag==1:
			LOG_FILENAME='/export/home/atsuser/eats_logs/EATS_RECOVERY_LOG.txt'
		else:
        		LOG_FILENAME='/home/atsuser/Log/BU/'+xenserverip+'_'+vmname+'.log'

        if '-powerip' in sys.argv and '-powerports' in sys.argv:
                powerip,powerpath = checker('-powerip',r'^(\d+\.){3}\d+:\/(.*?\/)+$',1,'Incorrect PowerIP/Path provided',sys.argv).split(':')
        powerports = checker('-powerports',r'^(\d+,)*.*?\d+$',1,'Incorrect Power ports provided',sys.argv)
	if '-log' in sys.argv:
		ind = sys.argv.index('-log')
		log = sys.argv[ind+1]
		LOG_FILENAME = log
     #   log = checker('-log',r'^(\/\w+)+\.\w+$',1,'Incorrect log path provided',sys.argv)
#	if log != None:
#		LOG_FILENAME=log
	intefaces = checker('-int',r'^((\d+\/)+\d+,)+(\d+\/)+\d+$',1,'Incorrect interfaces provided',sys.argv)
        ssh_ip = checker('-ip',r'^(\d+\.){3}\d+$',1,'Incorrect DUT ip provided',sys.argv)

	if'-mpx' not in sys.argv and '-vpx' not in sys.argv and '-eats' not in sys.argv:
		print("Please provide valid arguements")
		usage()
		exit()

except IndexError:
	print("Incorrect arguements provided.See Usage")
	usage()
	exit()
        
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
if eats_flag==1:
	logger_handler = logging.FileHandler(LOG_FILENAME,'a+')
else:
	logger_handler = logging.FileHandler(LOG_FILENAME,'w+')
logger_fortmater = logging.Formatter(fmt='%(asctime)s:%(funcName)s:%(lineno)d: [%(levelname)s] %(message)s', datefmt="%d-%m-%Y %H:%M:%S")
logger_handler.setFormatter(logger_fortmater)
logger.addHandler(logger_handler)
logging.getLogger().addHandler(logging.StreamHandler())

def powercycle(Powerip,Powerpath,Powerports):
        
	ports = Powerports
        telnetip = Powerip
        path = Powerpath
          
        logger.info("Attempting to Power cycle on  (ports: "+ports+")")
      	logger.info("Trying to telnet to IP: "+telnetip)
        cmd = "/usr/bin/telnet "+ telnetip +" \n\r"
        logger.info("======================================================================================")
        logger.info(cmd)
        logger.info("======================================================================================\n")
        s = pexpect.spawn(cmd, timeout=100)
        s.send('\r')  
                
        i = s.expect(['sername:','ogin:'])
        if i == 0 or i == 1:
		logger.info("======================================================================================")
		logger.info(s.before)
		logger.info("======================================================================================")
		logger.info("Inside console Server")
        	s.sendline('root')
                s.expect('assword:')
        	s.sendline('linux')
                s.expect('#')
		logger.info("======================================================================================")
		logger.info(s.before)
		logger.info("======================================================================================")
		logger.info("Logger in through root/linux")
		logger.info("======================================================================================")
                s.sendline('cli')
                s.expect('>')
		logger.info(s.before)
                s.sendline('cd '+path)
                s.expect('>')
		logger.info(s.before)
                s.sendline('cycle '+ports)
                s.expect('yes')
		logger.info(s.before)
                s.sendline('yes')
                s.expect('>')
		logger.info(s.before)
                s.sendline('exit')
                s.expect('#')
		logger.info(s.before)
		logger.info("======================================================================================")
                s.close()

def timeout_error(expect_session,obj):

	global vmid,uuid
        logger.info("Timeout Error Hit")
        obj['expect_session'] = expect_session
        if '-mpx' in sys.argv:
                if '-powerip' in sys.argv and '-powerports' in sys.argv:
                        powercycle(powerip,powerpath,powerports)                
                        expect_session.timeout = 600
                        expect_session.expect('loader.conf')
                        expect_session.sendcontrol('c')
                        expect_session.expect('OK')
                        return ok_prompt(expect_session,obj)
                else:
			logger.info("Please provide power console details")
                        obj['ret_val'] = 0
                        return obj                                               
        elif '-vpx' in sys.argv:
                expect_session.sendcontrol(']')
                expect_session.expect('#')
		logger.info(expect_session.before)
                expect_session.sendline('/opt/xensource/debug/destroy_domain -domid '+vmid)
                expect_session.expect('#')
		logger.info(expect_session.before)
		#expect_session.sendline('xl vm-list')
		expect_session.timeout = 20
                expect_session.sendline('xe vm-reboot uuid='+uuid+' --force')
                expect_session.expect('#')
		logger.info(expect_session.before)
                cmd = exec_cmd_with_prompt(obj,"xl vm-list",'#')
		logger.info(cmd)	
                cmd = re.split(r'\s{2,}',cmd)
                if vmname in cmd:
                        ind = cmd.index(vmname)
                        vmid = cmd[ind-1]
                        expect_session.timeout = 300
                        expect_session.sendline("xl console "+vmid)
			logger.info('xl console '+vmid)
                        expect_session.send('\r')
                        expect_session.expect('Press\s\[Ctrl-C\]')
                        expect_session.sendcontrol('c')
                        expect_session.expect('OK')
                        return ok_prompt(expect_session,obj)
                else:
                        logger.info("Cant find the vmid")
                        obj['ret_val'] = 0
                        return obj
                                      
def eof_error(expect_session,obj):

        logger.info("EOF error hit. The DUT - "+obj['ip']+" - is not reachable")
        obj['expect_session'] = None
        obj['ret_val'] = 0
        return obj                

def debugger_prompt(expect_session,obj):

        logger.info("Debugger prompt reached!")
        obj['expect_session'] = expect_session
        exec_cmd_with_prompt(obj,'c','UP')
        time.sleep(90)
        obj['ret_val'] = 6
        return obj

def normal_prompt(expect_session,obj):

        logger.info("Normal prompt reached!")
        obj['expect_session'] = expect_session
        logger.info("======================================================================================")
        logger.info(expect_session.before)
        logger.info("======================================================================================\n")
        exec_cmd(obj,"savec")
        exec_cmd_with_prompt(obj,'exit','ogin:')
        obj['ret_val'] = 6
        return obj
       
def hash_prompt(expect_session,obj):

        logger.info("Hash prompt reached!")
	logger.info(expect_session.before)
        obj['expect_session'] = expect_session
        expect_session.sendline('exit')              
        i = expect_session.expect([pexpect.TIMEOUT,'>','ogin:'])
        if i == 0:
                obj['expect_session'] = None
                obj['ret_val'] = 0
                return obj
        elif i == 1:
                exec_cmd(obj,'savec')
                exec_cmd_with_prompt(obj,'exit','ogin:')
                obj['ret_val'] = 6
                return obj
        elif i == 2:
                obj['ret_val'] = 6
                return obj
                
def ok_prompt(expect_session,obj):

	global ok_flag,kernel
	ok_flag = 1
        logger.info("OK prompt reached!")
        obj['expect_session'] = expect_session
        expect_session.timeout = 2
        ind = expect_session.expect(['OK',pexpect.TIMEOUT])
        if ind == 0 or ind ==1:
                prev_ker = exec_cmd_with_prompt(obj,'show kernel','OK')
                prev_ker = prev_ker.split()
                prev_ker = prev_ker[2][1:]
                logger.info("The Kernel present on the box is "+prev_ker)
                obj['expect_session'].timeout = 300
                exec_cmd_with_prompt(obj,'unload all','OK')
                expect_session.sendline('ls')
                index = expect_session.expect(['OK','q'])
                cmd = expect_session.before
                if index == 1:
                        while expect_session.after != 'OK':
                                expect_session.send('\r')
                                ind = expect_session.expect(['OK','q'])
                                cmd = cmd + expect_session.before
                cmd=cmd.split()
                kernellist = list()
                for x in cmd:
                        if re.match(r'ns.*?\.gz',x):
                                y = re.search(r'(\w+-\w+\.\w+-\w+(\.\w+)+)\.gz',x)
                                if y!=None:
                                        kernellist.append(y.group(1))
                        if re.match(r'kernel.*?\.gz',x) and not re.search(r'[\[\]]',x):
                                a = re.search(r'(\w+(\.\w+)+)\.gz',x)
                                if a!=None:
                                        kernellist.append(a.group(1))
                if not kernellist:
                        logger.info("No kernel is present on the device\nExiting")
                        obj['ret_vak'] = 6
                        return obj
                else:
                        logger.info("List of Kernels pesent on device")
                        logger.info(kernellist)
                        if kernellist[-1]==prev_ker:
                                n = -2
                        else:
                                n = -1
			kernel = kernellist[n]
                        exec_cmd_with_prompt(obj,'load /'+kernellist[n],'OK')
                        logger.info("======================================================================================")
                        logger.info("load /"+kernellist[n])
                        logger.info("======================================================================================\n")
                        logger.info("Please wait for Netscaler to come up\n")
			expect_session.timeout  = 600
                        expect_session.sendline('boot')
                        if '-vpx' in sys.argv:
                                expect_session.sendline('boot')
                                expect_session.expect('ogin:')
                        else:
                                expect_session.expect('ogin:')
                        obj['ret_val'] = 2
                        return obj


def login_prompt(expect_session,obj):

        logger.info("Login prompt reached!")
        obj['expect_session'] = expect_session
	expect_session.sendline(obj['username'])
        i = expect_session.expect([pexpect.TIMEOUT,'assword:'])
        if i == 0:
                logger.info("Does not reach Password Prompt")
                obj['ret_val'] = 0
                return None
        elif i == 1:
                expect_session.sendline(obj['password'])
                if obj['username'] == 'nsrecover':
                        logger.info("username is nsrecover")
                        j = expect_session.expect([pexpect.TIMEOUT,'ogin:','#'])
                        if j == 0:
                                logger.info("Does not reach Password prompt")
                                obj['ret_val'] = 0
                                return obj
                        elif j == 1:
                                logger.info("nsrecover/nsroot not working")
                                #if '-vpx' in sys.argv:
				expect_session.timeout = 300
                                return timeout_error(expect_session,obj)                                
                        elif j == 2:
				if ok_flag == 0:
                                	return change_kernel(expect_session,obj)
				elif ok_flag == 1:
					return change_kernel(expect_session,obj,[kernel,kernel])
                j = expect_session.expect([pexpect.TIMEOUT,r'Done.*?>',r'\s*login:(?!\s*\w+)'])
                logger.info("======================================================================================")
                logger.info(expect_session.before)
                logger.info("======================================================================================\n")
                if j == 0:
                        logger.info("Does not reach Password prompt or Password incorrect")
                        obj['ret_val'] = 0
                        return obj
                elif j == 1:
                        expect_session.timeout = 300
                        logger.info("connected to the device "+str(obj['ip']))
                        obj['ret_val'] = 1
                        return obj
                elif j == 2:
                        expect_session.timeout = 300
                        logger.info("nsroot/nsroot not working")
                        obj['ret_val'] = 2
                        return obj

def change_kernel(expect_session,obj,kernellist=None):
        
        logger.info("# prompt reached by login through nsrecover/nsroot")
	if not kernellist:
        	exec_cmd_with_prompt(obj,'cd /flash','#')
        	cmd = exec_cmd_with_prompt(obj,'ls','#')
        	cmd = cmd.split()
        	kernellist = list()
        	for x in cmd:
                	if re.match(r'ns.*?\.gz',x):
                        	y = re.search(r'(\w+-\w+\.\w+-\w+(\.\w+)+)\.gz',x)
                        	if y!=None:
                                	kernellist.append(y.group(1))
                        	if re.match(r'kernel.*?\.gz',x) and not re.search(r'[\[\]]',x):
                                	a = re.search(r'(\w+(\.\w+)+)\.gz',x)
                                	if a!=None:
                                        	kernellist.append(a.group(1))
        if not kernellist:
                logger.info("No kernel is present on the device\nExiting")
        else:
                logger.info(kernellist)
                exec_cmd_with_prompt(obj,'cd /flash/boot','#')
                response = exec_cmd_with_prompt(obj,'cat loader.conf','#')
                search = ''
                search = re.search(r'(?<=kernel\="\/)(.*?)"',response)
                if search:
                        search = search.group(1)
                if kernellist[-1] != search:
                        cmd = "sed -i '' 's/kernel=.*/"+"kernel=\"\/"+kernellist[-1]+"\""+"/' loader.conf"
                elif len(kernellist)>=2 and kernellist[-1] == search:
                        cmd = "sed -i '' 's/kernel=.*/"+"kernel=\"\/"+kernellist[-2]+"\""+"/' loader.conf"
                else:
                        logger.info("No other kernel present on the device!\nExiting")
                        obj['ret_val'] = 0
                        return obj
                cmd = exec_cmd_with_prompt(obj,cmd,'#')
		logger.info("======================================================================================")
                logger.info(cmd)
                logger.info("======================================================================================\n") 
		if ok_flag == 0:
                	expect_session.sendline('reboot')
                	expect_session.sendline('reboot')
			logger.info("Kernel Changed,device is Rebooting.Please check in Sometime")
		else:
			expect_session.sendline('exit')
			expect_session.sendline('exit')                
        obj['ret_val'] = 0
        return obj                

def telnet_login(ip,port,console_user,username,password,prompt,sessionhandle,flag,Timeout=15):
    
    #try: 
        obj = dict()
        obj['ip'] = ip
        obj['port'] = port
        obj['username'] = username
        obj['password'] = password
        obj['prompt'] = prompt
        obj['expect_session'] = ''
        obj['ret_val'] = 0

        if sessionhandle==None:
                logger.info("Connecting to the device - "+ ip+" "+port+"\nIt may take some time")
                cmd = "/usr/bin/telnet "+ ip +" "+ port+" \n\r"
                logger.info("======================================================================================")
                logger.info(cmd)
                logger.info("======================================================================================\n")
                s = pexpect.spawn(cmd, timeout=15)
        else:
                s=sessionhandle
		s.timeout = 15
        s.send('\r')  
        i = s.expect([pexpect.TIMEOUT, pexpect.EOF, 'ogin:', 'db>','(?<!\w)>(?!\w)',r'(?<=\w)#(?!\w)','OK'])
        if i == 0:
                return timeout_error(s,obj)
        elif i == 1:
                return eof_error(s,obj)
        elif i == 2:
                return login_prompt(s,obj)   
        elif i == 3:
                return debugger_prompt(s,obj)
        elif i == 4: 
                return normal_prompt(s,obj)
        elif i == 5:
                return hash_prompt(s,obj)    
        elif i == 6:
                return ok_prompt(s,obj)
    #except:
	logger.info("Exception Hitted")
        return None

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
            s.sendline('yes')
            s.expect ('assword:')
            s.sendline(password)
        elif i == 3:
            s.sendline(password)
	    j = s.expect([prompt,'assword:'])
	    if j == 0:
	    	obj['expect_session'] = s
	    	return(obj)
	    elif j == 1:
		logger.info("Cant SSH.Incorrect Xenserver password entered!")
		return None
        elif i == 4:
            obj['expect_session'] = s
            return(obj)   
        else:
            logger.info("Unexpected Prompt\n")
            pass
        s.expect(prompt)
        obj['expect_session'] = s
        return(obj)
#    except:
#	logger.info("Exception hitted!")
#        return(None)

def exec_cmd(obj,command):

    obj['expect_session'].sendline(command)
    try:
        obj['expect_session'].expect(obj['prompt'])
    except:
        logger.info("Prompt not found\nTrying to login to VPX")
    out = obj['expect_session'].before
    return out

def exec_cmd_with_prompt(obj,command,prompt):

    obj['prompt'] = prompt
    obj['expect_session'].sendline(command)
    try:
        obj['expect_session'].expect(obj['prompt'])
        obj['prompt'] = '>'
    except:
        logger.info("Prompt not found\nTrying to login to VPX")
    out = obj['expect_session'].before
    return out

def ping_check(session):
        
        cmd1=exec_cmd(session,"ping -c 4 10.102.1.98")
        time.sleep(5)
        logger.info("======================================================================================")
        logger.info(cmd1)
        logger.info("======================================================================================\n")
        if re.search(r'\s0\.0%',cmd1) or re.search(r'\s0% packet loss',cmd1,re.IGNORECASE):
                logger.info("Obelix is pingable from device")
        else:
                logger.info("Obelix is NOT pingable from device")
                if eats_flag==1:
                        if file_ip=="10.102.165.50" or file_ip=="10.102.165.51":
                                        cmd = exec_cmd(session,"set ha node -hastatus ENABLED")
                                        logger.info(cmd)
                                        cmd = exec_cmd(session,"rm channel LA/1")
                                        logger.info(cmd)
                                        cmd = exec_cmd(session,"savec")
                                        logger.info(cmd)
		if '-int' in sys.argv:
			interfaces = interfaces.split(',')
			for i in interfaces:
				cmd = exec_cmd(session,"en int "+i)
				logger.info("======================================================================================")
				logger.info(cmd)
				logger.info("======================================================================================\n")
		else:
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
                        	if re.match(r'^(\d\/)+\d$',i):
                                	cmd3=exec_cmd(session,"en int "+i)
                                	logger.info("======================================================================================")
                                	logger.info(cmd3)
                                	logger.info("======================================================================================\n") 
                cmd4=exec_cmd(session,"ping -c 4 10.102.1.98")
                logger.info(cmd4)
                if re.search(r'\s0\.0%',cmd4) or re.search(r'\s0% packet loss',cmd4,re.IGNORECASE):
                        logger.info("Obelix is now pingable from device!!!!!!!!!\n")
                else:
                        logger.info("Obelix is still not pingable\nPlease check manually!")	
        session['expect_session'].send('exit\r')
        ind = session['expect_session'].expect([pexpect.TIMEOUT,'ogin:','now'])
        if ind == 2:
                session['expect_session'].sendline('Y')
                session['expect_session'].expect('ogin:')	
        if '-vpx' in sys.argv:
                session['expect_session'].sendcontrol(']')	        

def main():
        
        global vmname,vmid,uuid 
        session = None
        if '-ip' in sys.argv:
                ssh_session1 = ssh_login(ssh_ip,'nsroot','nsroot','>')
                time.sleep(10)
                ssh_session2 = ssh_login(ssh_ip,'nsroot','nsroot','>')
                if ssh_session2!=None:
                        logger.info("DUT "+ssh_ip+" is UP.\nExiting")
                        exit()
        if '-mpx' in sys.argv:
                logger.info("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"+ip+":"+port+"+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
                session=telnet_login(ip,port,'root','nsroot','nsroot','(?<!\w)>',None,0)
        if '-vpx' in sys.argv:
                logger.info("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"+xenserverip+"++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
                xenserversession=ssh_login(xenserverip,xen_user,xen_pass,'#',100)
		if xenserversession == None:
			exit()
                cmd = exec_cmd(xenserversession,"xe vm-list params=name-label,networks")
                logger.info(cmd+'\n\n')
                cmd = re.split(r'\s*[:\r]\s*',cmd)
                tempvmname = vmname
                if re.match(r'^(\d+\.){3}\d+$',vmname):
                        logger.info("VM Ip is provided as argument")
                        if vmname in cmd:
                                ind = cmd.index(vmname)
                                vmname = cmd[ind-3]
                                logger.info("VM Name of the provided IP is "+vmname)
                cmd = exec_cmd(xenserversession,"xl vm-list")
                logger.info(cmd+'\n\n')	
                cmd = re.split(r'\s{2,}',cmd)
                if vmname in cmd:
                        ind = cmd.index(vmname)
                        uuid = cmd[ind-2]
                        vmid = cmd[ind-1]
                        logger.info("VM id is "+vmid)
                else:
                        if re.match(r'^(\d+\.){3}\d+$',tempvmname):
                                logger.info("Cant find the given VM Ip in the provided Xenserver")
                        else:
                                logger.error("Cant find the given VM name in Xenserver.\nPlease check the given VM name")
                        exit()
                xenserversession['expect_session'].sendline("xl console "+vmid)
                logger.info("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"+vmname+"++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
                session=telnet_login('vpx','vpx','root','nsroot','nsroot','(?<!\w)>',xenserversession['expect_session'],0)
                
        if session['ret_val'] == 0:
                logger.info("Unable to connect to the console of the box!")	
                
        elif session['ret_val'] == 1:
                ping_check(session)
                
        elif session['ret_val'] == 2:
                logger.info("Trying login through nsrecover/nsroot")
                if '-vpx' in sys.argv:
                        session = telnet_login('vpx','vpx','root','nsrecover','nsroot','(?<!\w)>',session['expect_session'],1)
			if session['ret_val'] == 2 and '-vpx' in sys.argv:
				session = telnet_login('vpx','vpx','root','nsrecover','nsroot','(?<!\w)>',session['expect_session'],1)
				session['expect_session'].sendcontrol(']')
                else:
                        session = telnet_login(ip,port,'root','nsrecover','nsroot','(?<!\w)>',None,1)       
			if session['ret_val'] == 2 and '-mpx' in sys.argv:
				session = telnet_login(ip,port,'root','nsrecover','nsroot','(?<!\w)>',None,1)
        
        elif session['ret_val'] == 3:
                logger.info("======================================================================================") 
                logger.info("Device Recovered please Login now")
                logger.info("======================================================================================\n")                
         
        elif session['ret_val'] == 6:
                logger.info("Trying to login again to device")
                
                if '-vpx' in sys.argv:
                        session = telnet_login('vpx','vpx','root','nsroot','nsroot','(?<!\w)>',session['expect_session'],1)
                else:
                        session = telnet_login(ip,port,'root','nsroot','nsroot','(?<!\w)>',None,1)
                        
                if session['ret_val'] == 0:
                        logger.info("Not able to recover device please check manually")

                elif session['ret_val'] == 1:
                        ping_check(session)

                elif session['ret_val'] == 6:
                        logger.info("======================================================================================") 
                        logger.info("Device Recovered please Login now")
                        logger.info("======================================================================================\n")			                
        logger.info("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
       
if __name__ == '__main__':
    main()  
