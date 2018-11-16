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
import datetime as dt
from colorama import Fore,init,Style
#print(Fore.RED+'Hello {Fore.GREEN}Everyon!{Style.RESET_ALL}')

LOG_FILENAME=__file__
LOG_FILENAME=LOG_FILENAME.split('.')[0]+'.log'
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
logger_handler = logging.FileHandler(LOG_FILENAME)
logger_fortmater = logging.Formatter(fmt='%(asctime)s:%(funcName)s:%(lineno)d: [%(levelname)s] %(message)s', datefmt="%d-%m-%Y %H:%M:%S")
logger_handler.setFormatter(logger_fortmater)
logger.addHandler(logger_handler)
logging.getLogger().addHandler(logging.StreamHandler())

def ssh_login(ip,username,password,prompt,timeout=100):
    
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


def fun(session,folder,crash_dict,crash_file):

	cmd = exec_cmd(session,"cd /var/core/"+folder)
	cmd = exec_cmd(session,"gunzip "+crash_file)
	cmd = exec_cmd(session,"what "+crash_file.split('.')[0])
	logger.info(cmd)
	if re.search(r'(?<=NS)\d+\.\d',cmd):
		release = re.search(r'(?<=NS)(\d+\.\d)',cmd)
		release = release.group(1)
        if re.search(r'(?<=Build\s).*?(\.nc|,)',cmd):
		build = re.search(r'(?<=Build\s)(.*?)(\.nc|,)',cmd)
		build = build.group(1)
	cmd = exec_cmd(session,"file "+crash_file.split('.')[0])
	logger.info(cmd)
	bit_flag = 0
	if re.search(r'64-bit',cmd):
		bit_flag = 1
	build_name_unmod=release+"-"+build+"_nc"
	release_dict = {'10.5':'tagma','11.0':'ion','11.1':'kopis','12.0':'oban','12.1':'kamet','13.0':'mana'}
	release=release_dict[release]
	build=re.sub(r'\.','_',build)
	if release=='oban' or release=='kamet' or release == 'mana':
		if bit_flag == 1:
			build_name=release+'_'+build+'_nc_64'
		else:
			build_name=release+'_'+build+'_nc_32'
	else:
		build_name=release+'_'+build+'_nc'
	dbg_file_tgz = 'dbgbins-'+build_name_unmod+'.tgz'
	dbg_file = 'dbgbins-'+build_name_unmod
	logger.info("Crash file is of build "+build_name)
	logger.info("dbgbins file to be copied is "+dbg_file_tgz)
	cmd = exec_cmd(session,'ls /var/core/'+dbg_file)	
	if re.search(r'No such',cmd):
		cmd = exec_cmd(session,"tar -zxvf /var/nsinstall/"+build_name+"/"+dbg_file_tgz+" -C /var/core/.")
		if re.search(r'Error opening',cmd):
			logger.info("Build folder is not present inside /var/nsinstall")
			return
	else:
		logger.info("dbgbins already present in /var/core")		
	session['prompt'] = '\(gdb\)'
	if bit_flag == 1:
		cmd = exec_cmd(session,'gdb /var/core/'+dbg_file+'/amd64/'+crash_file.split('-')[0].lower())
	else:
		cmd = exec_cmd(session,'gdb /var/core/'+dbg_file+'/i386/'+crash_file.split('-')[0].lower())
	cmd = exec_cmd(session,'set pagination off')
	cmd = exec_cmd(session,'set solib-absolute-prefix /dev/null')	
	cmd = exec_cmd(session,'nosharedlibrary')
	cmd = exec_cmd(session,'set solib-search-path '+dbg_file+'/i386')
	cmd = exec_cmd(session,'core-file '+crash_file.split('.')[0])	
	cmd = exec_cmd(session,'bt')
	logger.info(cmd)
	session['prompt'] = '#'
	cmd = exec_cmd(session,'q')
	cmd = exec_cmd(session,'gzip '+crash_file.split('.')[0])
	logger.info(cmd)	

def ns_error_check(session,session_ip,crash_dict):

    if not session:
        logger.info("Cannot ssh into device "+session_ip)
    else:
	bit_flag = 0  # 64 bit flag
	cmd=exec_cmd(session,"set cli mode -page OFF -color OFF -timeout 36000")	
	session['prompt'] = '#'
	cmd = exec_cmd(session,"shell")
	for i in crash_dict:
		k = 0
		if crash_dict[i][0].split('-')[0] == 'nscac64p':
			logger.info(crash_dict[i][0]+" crash is not handled")
		else:
			fun(session,i,crash_dict,crash_dict[i][0])
		for j in range(1,len(crash_dict[i])):
			if crash_dict[i][j].split('-')[0] == 'NSPPE':
				if (int(crash_dict[i][k].split('-')[1])+1) == int(crash_dict[i][j].split('-')[1]):
					k = j
					continue
				else:
					fun(session,i,crash_dict,crash_dict[i][j])
			else:
				logger.info("Crash not handled for "+crash_dict[i][j]+" type of crash") 

def usage():
    
	logger.info("Usage : "+__file__.split('.')[0]+".py <Resource file> [-ha] [-c] [-ap]")
    	logger.info("\t\t-ha To check if NSIP is present and HA pair is created, if not present then script will create HA")
    	logger.info("\t\t-c To check for errors in /var/core bounds on NetScaler")
    	logger.info("\t\t-ap To make Admin partition on testbed 7700, Pleae remember to provide ip for the testbed in a file")

def main():
	
   # try:
	#logger.info(Fore.GREEN+'BYE!!!')
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
	if '-crash' in sys.argv:
	    for ips in ip:
		if len(ips)>0:
			ip1_session = ssh_login(ips,'nsroot','nsroot','>')
			ip1_session['prompt'] = '#'
			cmd = exec_cmd(ip1_session,'shell')
			cmd = exec_cmd(ip1_session,'date +\"%F-%T\"')
			cmd = cmd.split('\n')[1]
			time_match = re.match("(\d+)-(\d+)-(\d+)-(\d+):(\d+):(\d+)",cmd)
			time = dt.datetime(int(time_match.group(1)),int(time_match.group(2)),int(time_match.group(3)),int(time_match.group(4)),int(time_match.group(5)),int(time_match.group(6)))
			logger.info(time)
			logger.info(str(dt.datetime.now()))
			delta = dt.datetime.now()-time
			logger.info(delta)
			cmd = exec_cmd(ip1_session,'cd /var/core')	
			#logger.info(cmd)
			cmd=exec_cmd(ip1_session,"ls -lD \"%F-%T\"")
         		file_list = cmd.split('\n')
         		del file_list[0:2]
         		del file_list[len(file_list)-1]
         		#logger.info(file_list)
			ind = sys.argv.index('-crash')
			test_start = sys.argv[ind+1] # Testinstance contains the test start timestamp
         		start_time = re.match("test-(\d+)_(\d+)_(\d+)-(\d+)_(\d+)_(\d+)_(\d+)",test_start)
         		test_start_time = dt.datetime(int(start_time.group(1)),int(start_time.group(2)),int(start_time.group(3)),int(start_time.group(4)),int(start_time.group(5)),int(start_time.group(6)))
         		testinstance_time = test_start_time
			logger.info(testinstance_time)
			crash_dict = dict()
			for i in file_list: #all folder inside /var/core
				folder_details = i.split()
               	 		folder_name = folder_details[6]
                 		if folder_name == "bounds":
                         		continue
                 		time_match = re.match("(\d+)-(\d+)-(\d+)-(\d+):(\d+):(\d+)",folder_details[5])
                         	time = dt.datetime(int(time_match.group(1)),int(time_match.group(2)),int(time_match.group(3)),int(time_match.group(4)),int(time_match.group(5)),int(time_match.group(6)))
                 		if (testinstance_time - time < delta) and (re.match("^(\d+)",folder_name)):	#confirm if folder is having right crash	
					logger.info("Crash might be seen in folder "+folder_name)
					crash_dict[folder_name] = list()
					cmd = exec_cmd(ip1_session,'cd /var/core/'+folder_name)
					cmd=exec_cmd(ip1_session,"ls -lD \"%F-%T\"")
         				file_list = cmd.split('\n')
         				del file_list[0:2]
         				del file_list[len(file_list)-1]		
					for j in file_list: #all files inside /var/core/<folder>
						dir_details = j.split()
						dir_name = dir_details[6]
						time_match = re.match("(\d+)-(\d+)-(\d+)-(\d+):(\d+):(\d+)",dir_details[5])
						time = dt.datetime(int(time_match.group(1)),int(time_match.group(2)),int(time_match.group(3)),int(time_match.group(4)),int(time_match.group(5)),int(time_match.group(6)))
						if (testinstance_time - time < delta) and (re.match(r'^n',dir_name,re.IGNORECASE)): #confirm if the file is actually a crash
							logger.info(dir_name+" crash file is seen")
							crash_dict[folder_name].append(dir_name)
			ip1_session['prompt'] = '>'
			cmd = exec_cmd(ip1_session,'exit')
			crash_dict = dict( [(k,v) for k,v in crash_dict.items() if len(v)>0])
			logger.info(crash_dict)
			ns_error_check(ip1_session,ips,crash_dict)
							
        if '-c' in sys.argv:
	    for ips in ip:
		if len(ips)>0:
            		ip1_session=ssh_login(ips,'nsroot','nsroot','>')
	    		cmd=exec_cmd(ip1_session,"sh license | grep NO")
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
		cmd=exec_cmd(ip2_session,"sh ha node | grep IP")
		if re.search(r'\d+\.\d+\.\d+\.(\d+)',cmd):
			search = re.findall(r'\d+\.\d+\.\d+\.(\d+)',cmd)
			#logger.info(search)
			#logger.info(search[0])
			ip1 = int(search[0])
			#logger.info(search[1])
			ip2 = int(search[1])
			#logger.info(ip1)
			#logger.info(ip2)
          		#logger.info(cmd)
		cmd=exec_cmd(ip2_session,"sh ha node | grep \"Master State\"")
		if re.search(r'(?<=Master State: )(\w+)',cmd):
			search = re.search(r'(?<=Master State: )(\w+)',cmd)
			state = search.group(1)
			#logger.info(state)
            		#logger.info(cmd)
		if (ip1>ip2 and state is 'Secondary') or (ip1<ip2 and state is 'Primary'):
			cmd=exec_cmd(ip2_session,"force HA failover -force")
			logger.info(cmd)
            else:
                logger.info("FAILED\nPlease correct the testbed")	
	if '-ap' in sys.argv:
	    #cmd=os.system("partition_maker 10.106.81.170 1")
	    #logger.info(cmd)
	    #time.sleep(5)  
	    session=ssh_login('10.106.81.171','nsroot','nsroot','>')
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
            cmd=exec_cmd(session,"ping -c 4 10.102.1.97")
	    logger.info(cmd)

   # except:
       # logger.info("Filename "+sys.argv[1]+" has some error please check mnually!") 


if __name__ == '__main__':
    main()   
