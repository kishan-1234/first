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
import socket

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
	    logger.info('pswd prompt!')
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

def exec_cmd(obj,command):

    obj['expect_session'].sendline(command)
    try:
        obj['expect_session'].expect(obj['prompt'])
    except:
        logger.info("Prompt mismatch. please check")
    out = obj['expect_session'].before
    return out

def get_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # doesn't even have to be reachable
        s.connect(('10.255.255.255', 1))
        IP = s.getsockname()[0]
    except:
        IP = '127.0.0.1'
    finally:
        s.close()
    return IP

def usage():
 
      print("Usage : "+__file__.split('.')[0]+".py -t <testbedid|testbedname> -sdb <username> <password> -ddb <username> <password>")
      print("\t\t-t Testbedid or Testbedname to be copied should be provided")
      print("\t\t-controller Controller ip where testbed is to be copied")
      print("\t\t-sdb To provide username & password to connect to DB where the script is run.If not provided root/freebsd will be taken by default")
      print("\t\t-ddb To provide username & password to connect to DB where entries are to be copied. If not provided root/freebsd will be taken by default")	           


def local_cmd_call(cmd):

      ret_val = subprocess.call(cmd,shell=True)
     
def gen_dump_scp(session,ip,db_usr,db_pass,db_table,dump_file):

      cmd = exec_cmd(session,'mysqldump -u '+db_usr+' -p'+db_pass+' ATS_MOD '+db_table+' --no-create-info > /tmp/'+dump_file) 
      session['prompt'] = 'assword:'
      cmd = exec_cmd(session,'scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null /tmp/'+dump_file+' atsuser@'+ip+':/tmp/.') 
      session['prompt'] = '\$'
      cmd = exec_cmd(session,'atsuser') 

def read_file(dumpfile):

      lines = open(dumpfile,'r')
      return lines.readlines()

def read_dump_resourcetable(dumpfile):

      cont = read_file(dumpfile)
      resources = set()
      for line in cont:
                if re.match(r'^INSERT',line):
			line = re.split(r'[()]',line)
			line = line[1:]
                        del line[1::2]
			#print line
			for i in range(len(line)):
                                entry = re.split(r',',line[i])
				resources.add(int(entry[2]))		
			break
      return resources

def read_dump_resourcetypetable(dumpfile):

      cont = read_file(dumpfile)
      resources = dict()
      for line in cont:
                if re.match(r'^INSERT',line):
                        line = re.split(r'[()]',line)
                        line = line[1:]
                        del line[1::2]
                        for i in range(len(line)):
                                entry = re.split(r',',line[i])
                                entry[0] = int(entry[0])
				entry[1] = str(entry[1])
                                resources[entry[0]]=entry[1]
                        break      
      return resources

def read_dump_testbedtable(dumpfile):

      cont = read_file(dumpfile)
      resources = list()
      for line in cont:
		if re.match(r'^INSERT',line):
			line = re.split(r'[()]',line)
			line = line[1:]
			del line[1::2]
			for i in range(len(line)):
				entry = re.split(',',line[i])
				resources.extend(entry)
			break
      return resources

def import_new_testbed(session,ip,db_user,db_pass,dump_file):

      session['prompt'] = 'assword:'
      cmd = exec_cmd(session,'scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null atsuser@'+ip+':/tmp/'+dump_file+' /tmp/.')
      session['prompt'] = '\$'
      cmd = exec_cmd(session,'atsuser')
      cmd = exec_cmd(session,'mysql -u '+db_user+' -p'+db_pass+' --force ATS_MOD < /tmp/'+dump_file)

def main():

      testbedid = ''
      testbedname = ''
      sdb_user = 'root' 
      sdb_pass = 'freebsd'
      ddb_user = 'root'
      ddb_pass = 'freebsd'
      ip = str(get_ip())     
      ip_i = ''

      if '-t' not in sys.argv:
      		usage()
      		exit()
      ind = sys.argv.index('-t')
      if re.match(r'^\d+$',sys.argv[ind+1]):
      		logger.info("TestbedId is provided as input")
		testbedid = sys.argv[ind+1]
      else:
		logger.info("TestbedName is provided as input")	
		testbedname = sys.argv[ind+1] #testbedname wont contain spaces so no need to add chck for space

      if '-controller' not in sys.argv:
		usage()
		exit()
      ind = sys.argv.index('-controller')
      if re.match(r'^(\d+\.)+\d+$',sys.argv[ind+1]):
		ip_i = sys.argv[ind+1]
      else:
		logger.info("Please provide controller ip where testbed is to be exported")
		usage()
		exit()

      if '-newtid' not in sys.argv:
		usage()
		exit()
      ind = sys.argv.index('-newtid')
      if re.match(r'^\d+$',sys.argv[ind+1]):
		newtid = sys.argv[ind+1]
      else:
		logger.info("Please provide new testbed ID")
		usage()
		exit()

      if '-sdb' in sys.argv:
		ind = sys.argv.index('-sdb')
                sdb_user = sys.argv.index([ind+1])
                sdb_pass = sys.argv.index([ind+2])

      if '-ddb' in sys.argv:
                ind = sys.argv.index('-ddb') 		
		ddb_user = sys.argv.index([ind+1])
		ddb_pass = sys.argv.index([ind+2])

      session = ssh_login(ip_i,'atsuser','atsuser','\$') 
      cmd = 'mysqldump -u '+sdb_user+' -p'+sdb_pass+' ATS_MOD testbed --no-create-info --where=testbedId=\"'+testbedid+'\" > /tmp/dump_testbed.sql' 
      local_cmd_call(cmd)
      cmd = 'sed -i \'s/('+testbedid+'/('+newtid+'/g\' /tmp/dump_testbed.sql'
      local_cmd_call(cmd)
      cmd = 'sed -i \'s/='+testbedid+'/='+newtid+'/g\' /tmp/dump_testbed.sql'
      local_cmd_call(cmd)
      gen_dump_scp(session,ip,ddb_user,ddb_pass,'testbed','dump_whole_testbed_i.sql')
      cmd = 'mysqldump -u '+sdb_user+' -p'+sdb_pass+' ATS_MOD resource --no-create-info --where=testbedId=\"'+testbedid+'\" > /tmp/dump_resource_testbed.sql'
      local_cmd_call(cmd)
      cmd = 'sed -i \'s/,'+testbedid+'/,'+newtid+'/g\' /tmp/dump_resource_testbed.sql' 
      local_cmd_call(cmd)
      cmd = 'sed -i \'s/='+testbedid+'/='+newtid+'/g\' /tmp/dump_resource_testbed.sql'
      local_cmd_call(cmd)
      cmd = 'mysqldump -u '+sdb_user+' -p'+sdb_pass+' ATS_MOD resourcetype --no-create-info > /tmp/dump_whole_resourcetype.sql'
      local_cmd_call(cmd) 
      gen_dump_scp(session,ip,ddb_user,ddb_pass,'resource --where=testbedId='+testbedid,'dump_resource_testbed_i.sql')
      resources_testbed_i = read_dump_resourcetable('/tmp/dump_resource_testbed_i.sql') 
      resources_testbed = read_dump_resourcetable('/tmp/dump_resource_testbed.sql') #gets set of resource used in particular testbed
      whole_resources = read_dump_resourcetypetable('/tmp/dump_whole_resourcetype.sql') #gets dictionary of all resourcetype mappings
      gen_dump_scp(session,ip,ddb_user,ddb_pass,'resourcetype','dump_whole_resourcetype_i.sql') 
      whole_resources_i = read_dump_resourcetypetable('/tmp/dump_whole_resourcetype_i.sql') #resources on importing controller 
      for i in resources_testbed:
		if i in whole_resources :
                        if i in whole_resources_i:
			        if whole_resources[i] != whole_resources_i[i]:
					print "Mismatch in mapping of resourctype in controllers\nResourceID :"+str(i)+" on "+ip+" is "+str(whole_resources[i])+"\nResourceID :"+str(i)+" on "+ip+i+" is "+str(whole_resources_i[i])
			else:
				print "ResourceID :"+str(i)+" is not present on controller "+ip_i
		else:
			if i in whole_resources_i: 
				print "ResourceID :"+str(i)+" is neither present on controller "+ip+" nor on "+ip_i
			else:
				print "ResourceID :"+str(i)+" is not present on controller "+ip
      testbed_details = read_dump_testbedtable('/tmp/dump_testbed.sql')
      #print testbed_details
      whole_testbed_details_i = read_dump_testbedtable('/tmp/dump_whole_testbed_i.sql')
      #print whole_testbed_details_i
      if testbed_details[0] in whole_testbed_details_i:
      		logger.info("Testbed id :"+testbedid+" is alrady present on controller "+ip_i)
		ind = whole_testbed_details_i.index(testbed_details[0])
		if testbed_details[1] != whole_testbed_details_i[ind+1]:
			logger.info("Testbed present with a different name : "+whole_testbed_details_i[ind+1]+" on controller "+ip_i)
		else:
			logger.info("Testbed already present with same testbedId and testbedname")
			if not resources_testbed_i:	
				logger.info("Copying testbed resources")
				import_new_testbed(session,ip,ddb_user,ddb_pass,'dump_resource_testbed.sql')
				logger.info("Done")
			else:
				logger.info("Resources already present for testbedId :"+testbedid+" on controller "+ip_i)
      else:
		logger.info("Testbed id :"+testbedid+" is not present on controller "+ip_i+"\nCopying testbed")
		import_new_testbed(session,ip,ddb_user,ddb_pass,'dump_testbed.sql')
		logger.info("Copying testbed resources")
		import_new_testbed(session,ip,ddb_user,ddb_pass,'dump_resource_testbed.sql')
		logger.info("Done!")		
	
if __name__ == '__main__':
    main() 
