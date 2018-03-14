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

def ssh_login(ip,username,password,prompt='#',timeout=300):
    
    try:
        obj = dict()
        obj['ip'] = ip
        obj['username'] = username
        obj['password'] = password
        obj['prompt'] = prompt
        obj['expect_session'] = ''
        logger.info("Connecting to the Xenserver - " + ip)
        cmd = "ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " +  str(username) + "@" + str(ip)
        s = pexpect.spawn(cmd, timeout=timeout)
        pexpect_log = file(LOG_FILENAME, 'w+')
        s.logfile_read = pexpect_log
        i = s.expect ([pexpect.TIMEOUT, pexpect.EOF, 'yes/no', 'assword:', '#'])
        if i ==0:
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
        elif i == 4:
            obj['expect_session'] = s
            return(obj)
        else:
            logger.error("Unexpected Prompt\n")
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

    xen = ssh_login(sys.argv[1],'root','freebsd')
    if not xen:
        logger.error("Either the creadentials are incorrect or Xenserver "+sys.argv[1]+" is not reachable")
    else:    
        out=exec_cmd(xen,"xe vm-list params=name-label,uuid,networks,power-state,VCPUs-number,VCPUs-max,VCPUs-utilisation")
        out=re.sub(r'; 0/ipv6/0: \w+.*?:(:\w+){4}','',out)
        out=re.sub(r'networks \(MRO\):(?! 0/ip:)','networks (MRO): NA',out)
        fields=re.split(r'\s*[:\r]\s*',out)
        fields=[x for x in fields if x!='0/ip']
        fields.remove('Control domain on host') 
        for i in range(len(fields)):
            if i==len(fields):
                break
            if fields[i]=='networks (MRO)':
                j=i+2
                while fields[j]!='uuid ( RO)' and j<len(fields):
                    del fields[j]
                    if j==len(fields):
                        break       
        n=(len(fields)-4)/14
        vms=[]
        xenserver={}
        for i in xrange(n):
            vm={}
            vm['name-label']=fields[5+14*i]
            vm['uuid']=fields[3+14*i]
            if fields[7+14*i]=='running':
                vm['power-state']='ON'
            else:
                vm['power-state']='OFF'    
            vm['VCPUs-number']=int(fields[11+14*i])
            vm['VCPUs-max']=fields[9+14*i]  
            vm['VCPUs-utilisation']=fields[13+14*i]
            vm['ip']=fields[15+14*i]
            vm['xen_ip']=sys.argv[1]
            if vm['power-state'] != 'halted': 
                memory=exec_cmd(xen,'xe vm-data-source-query data-source=memory uuid='+vm['uuid'])
                memory=re.findall(r'\d*?\.\d+',memory)   
                if len(memory)==1:
                    vm['memory']=int(round(float(memory[0])/(1024*1024*1024)))  #in GB
                memory_free=exec_cmd(xen,'xe vm-data-source-query data-source=memory_internal_free uuid='+vm['uuid'])
                memory_free=re.findall(r'\d*?\.\d+',memory_free)
                if len(memory_free)==1:
                    vm['memory_free']=int(round(float(memory_free[0])/(1024*1024))) #in MB
            os=exec_cmd(xen,'xe vm-list params=os-version uuid='+vm['uuid'])
            os=re.split(r'[:;|]',os)
            temp='Not Available'
            if os[1]==' name':
            	temp=os[2].strip()
            vm['os']=temp       
            vms.append(vm)  
        disk_cmd=exec_cmd(xen,"xe vm-disk-list vdi-params=virtual-size --multiple")
        disk_cmd=re.split(r'\s*[:\r]\s*',disk_cmd)
        n=int((len(disk_cmd)-3)/10)
        for i in xrange(n):
        	for items in vms:
        		if items['name-label']==disk_cmd[5+10*i]:
        			items['disk']=int(round(float(disk_cmd[10+10*i])/(1024*1024*1024))) #in GB  
        for items in vms:
            if 'disk' not in items:
            	items['disk']='0000'
        cmd=exec_cmd(xen,"xe host-list")
        cmd=re.split(r'\s*[:\r]\s*',cmd)
        xenserver['uuid']=cmd[2]
        xenserver['name-label']=cmd[4]  
        cmd=exec_cmd(xen,"xe sr-list params=physical-size")
        cmd=re.split(r'\s*[:\r]\s*',cmd)
        n=int((len(cmd)-3)/2)
        mem_size=0
        for i in xrange(n):
            mem_size+=int(cmd[2+2*i]) 
        xenserver['disk']=int(round(float(mem_size)/(1024*1024*1024)))      		   		                 
        cmd=exec_cmd(xen,"xl info")
        cmd=exec_cmd(xen,"xl info")
        cmd=cmd.split()
        n=cmd.index('total_memory') 
        xenserver['memory']=int(round(float(cmd[n+2])/1024)) #in GB
        n=cmd.index('free_memory') 
        xenserver['free_memory']=int(round(float(cmd[n+2])/1024)) #in GB
        n=cmd.index('nr_cpus')
        xenserver['VCPUs-number']=int(cmd[n+2]) #in GB
        xenserver['os']='Not Available'
        xenserver['power-state']='ON'
        if 'xen_version' in cmd:
            n=cmd.index('xen_version')
            xenserver['os']=cmd[n+2]
        else:
            xenserver['os']='Not Available'  
        xenserver['ip']=sys.argv[1]
        xenserver['xen_ip']=xenserver['ip']
        vms.append(xenserver)
	for l in vms:
            if re.search(r'netscaler',l['os'],flags=re.IGNORECASE):
                logger.info(l)
	'''
        db = MySQLdb.connect(host="localhost",user="root",passwd="freebsd",db="lab_autobot1")
        print 'Connection made to DB'
        cursor = db.cursor()
        for items in vms:
            try:    
                cursor.execute("""INSERT INTO vm
                               (id,name,state,operating_system,cpu,memory,disk,mgmt_ip,parent_xen_ip)
                               VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s);""",
                               (items['uuid'],items['name-label'],items['power-state'],items['os'],items['VCPUs-number'],items['memory'],items['disk'],items['ip'],items['xen_ip']))                  
                db.commit()

            except:
                db.rollback()
        #try:
        #cursor.execute("""""")
        print 'Written to DB!'
        db.close()''' 


if __name__ == '__main__':
    main()  


            

        
