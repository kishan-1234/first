from flask import Flask, request, jsonify
import os
import re
import pexpect 
import sys
import subprocess

app = Flask(__name__)

@app.route("/results")
def doc():

    controller= request.args.get('controller')
    user = request.args.get('user')
    password = request.args.get('password')
    tid = request.args.get('tid')
    path = '/home/'
    if user != None:
    	path = path+str(user)+'/Result/'
    if tid != None:
	path = path+str(tid)
    session = ssh_login(controller,user,password,'\$')
    if session != None: 
        cmd = exec_cmd(session," if test -d "+path+"; then echo \"exist\"; fi  ")
	cmd = cmd.split()
    	if 'exist' in cmd:
		if not os.path.exists('/tmp/'+tid):
			os.makedirs('/tmp/'+tid)
		else:
			cmd = 'rm -rf /tmp/'+tid+'/*'
			subprocess.call(cmd,shell=True)     
		cmd = 'scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null '+user+'@'+controller+':'+path+'/*'+' /tmp/'+tid+'/.'
		host_session = pexpect.spawn(cmd)
		host_session.expect('assword:')
		host_session.sendline(password)
		host_session.expect(pexpect.EOF)
		ls = os.listdir('/tmp/'+tid)
		global_testcase_dict = {}
		wrong_testcase_dict = {}
		res = list()
		for i in ls:
			file_dict = {}
			if not re.search(r'\.',i): #only parse check files having .result in the end
				continue		
			if i.split('.')[1] != 'result':
				continue
			script_name = i.split('.')[0]
			file_dict['script'] = script_name
 			file1 = open("/tmp/"+tid+"/"+i,"r")
                	lines = file1.readlines()
			file1.close()
			temp = []
			c = 0
			for line in lines:
				c = c +1
				fulltestcaseid = 'NA'
				iterationid = 'NA'
				testcaseid = 'NA'
				description = 'NA'
				result = 'NA'
				comment = 'NA'
				result_dict = {}
				if re.match(r'^(\d+\.){3}\d+(\.\d+)?',line):
					y = re.search(r'(^((\d+\.){3}\d+)(\.(\d+))?)',line)
					fulltestcaseid = y.group(1)
					if fulltestcaseid in global_testcase_dict:
						global_testcase_dict[fulltestcaseid].append({'filename' : i, 'line_number' : c})												
					else:
						global_testcase_dict[fulltestcaseid] = list()
						global_testcase_dict[fulltestcaseid].append({'filename' : i, 'line_number' : c})
					testcaseid = y.group(2)
					if y.group(5):
	    					iterationid = y.group(5)
				elif re.match(r'^\d.*?\.\d+:',line):
					y = re.search(r'^(\d.*?\.\d+):',line)
					fulltestcaseid = y.group(1)
					res.append({fulltestcaseid:[{'filename' : i, 'line_number' : c}],'reason':'Invalid TestcaseId'})	
				if re.search(r'\d\s*:.*?(?=:\s*(PASSED|FAILED))',line):
					y = re.search(r'\d\s*:(.*?)(?=:\s*(PASSED|FAILED))',line)
					description = y.group(1)
					description = description.strip()
					if re.search(r':',description):
						if fulltestcaseid in wrong_testcase_dict:
							wrong_testcase_dict[fulltestcaseid].append({'filename' : i, 'line_number' : c})
						else:
							wrong_testcase_dict[fulltestcaseid] = list()
							wrong_testcase_dict[fulltestcaseid].append({'filename' : i, 'line_number' : c})
					if description == "":
						description = 'NA'
				if re.search(r':\s*(PASSED|FAILED)',line,re.IGNORECASE):
    					y = re.search(r':\s*(PASSED|FAILED)',line,re.IGNORECASE)
    					result = y.group(1)
				if re.search(r'(?<=(PASSED|FAILED))\s*:\s*\S.*',line):	
					y = re.search(r'(?<=(PASSED|FAILED))\s*:\s*(\S.*)',line)
					comment = y.group(2)
				#result_dict['testcaseid'] = testcaseid
				#result_dict['iterationid'] = iterationid
				#result_dict['description'] = description
				#result_dict['result'] = result
				#result_dict['comment'] = comment
				#temp.append(result_dict)
			#file_dict['details'] = temp 
			#file1.close()
			#res.append(file_dict)
		cmd = 'rm -rf /tmp/'+tid+'/'
                subprocess.call(cmd,shell=True)
        	for i in global_testcase_dict:
			if len(global_testcase_dict[i])>1:
				res.append({'testcase id':i,'files':global_testcase_dict[i],'reason':"Duplicate TestcaseId"})
		for i in wrong_testcase_dict:
			res.append({'testcase id':i,'files':wrong_testcase_dict[i],'reason':"Invalid Description"})
		return jsonify(res)
		
	else:
		return jsonify([{'Error':str("Cant find testinstance folder at :"+path)}])
    else:
    	return jsonify([{'Error': 'Cant SSH.Please provide correct arguments are provided.'}])

def ssh_login(ip,username,password,prompt,Timeout=15):
    
        obj = dict()
        obj['ip'] = ip
        obj['username'] = username
        obj['password'] = password
        obj['prompt'] = prompt
        obj['expect_session'] = ''
        cmd = "ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " +  str(username) + "@" + str(ip)
        s = pexpect.spawn(cmd, timeout=Timeout)
        i = s.expect ([pexpect.TIMEOUT, pexpect.EOF, 'yes/no', 'assword:',prompt])
        if i == 0:
            obj['expect_session'] = None
            return(None)
        elif i == 1:
            obj['expect_session'] = None
            return(None)
        elif i == 2:
            s.sendline('yes')
            s.expect ('assword:')
            s.sendline(password)
        elif i == 3:
            s.sendline(password)
	    j = s.expect([prompt,'assword:',pexpect.TIMEOUT,pexpect.EOF])
	    if j == 0:
	    	obj['expect_session'] = s
	    	return(obj)
	    elif j == 1:
		return None
	    elif j == 2 or j == 3:
		return None
        elif i == 4:
            obj['expect_session'] = s
            return(obj)   
        s.expect(prompt)
        obj['expect_session'] = s
        return(obj)

def exec_cmd(obj,command):

    obj['expect_session'].sendline(command)
    try:
        obj['expect_session'].expect(obj['prompt'])
    except:
        logger.info("Exception found!")
    out = obj['expect_session'].before
    return out

if __name__ == '__main__':
    app.run(host='0.0.0.0',port=5002)
