#!/usr/bin/python
# -*- coding: UTF-8 -*-
import sys
import paramiko
import os
import re
import json
import time
import telnetlib
import pymysql
import logging
import difflib
from paramiko.ssh_exception import NoValidConnectionsError,AuthenticationException

global tftpServer

# 获得备份文件名称,在checkpoint网络设备上用，其实现方式是:间隔一定时间发送'show backup status'命令，
# 一直到出现 'Backup file location:'为止。然后获取此标志后面的备份文件名称。
# > show backup status
# Tftp backup succeeded.
# Backup file uploaded to: 192.168.31.23
# Backup file location: backup_--_gw-a1ba5b_13_Nov_2023_16_10_05.tgz
# Backup process finished in 02:20 minutes
# Backup Date: 13-Nov-2023 16:12:25
def s_getBackupfile(chan, lineEndMark, checkBackupFile):
    if(checkBackupFile is None):
        return None
    
    excmd = checkBackupFile[0]
    backupfileMark = checkBackupFile[1]
    times = checkBackupFile[2]   # 重试次数
    secs = checkBackupFile[3]    # 每次重试之间的间隔时间，单位秒
 
    logging.info("excmd=%s, backupfileMark=%s, times=%d, secs=%d"%(excmd,backupfileMark,times,secs))
    count = 0
    backupfile = ''
    while count < times:
        chan.send(excmd + '\n')
        line = s_readline(chan, lineEndMark, None, None, None)      
        # print("line=" + line)
        index = line.find(backupfileMark)
        if ( index >= 0):
            start = index + len(backupfileMark) + 1
            end = start
            for end in range(start, len(line)):
                if(line[end] == '\n'):
                    break
            backupfile = line[start:end].strip()
            break
        count += 1
        time.sleep(secs)
    logging.info("count=%d, backupfile=%s"%(count, backupfile))
    return backupfile

# 判断设备返回字符串是否出现 命令行提示字符
def matchPS1(line, PS1):
    # print("matchPS1 line=%s" %(line))
    isFindPS1 = False
    # line = line.strip()
    if (line is not None) and len(line) > 0 and (PS1 is not None) and (len(PS1) > 0):
        for i in range(len(PS1)):
            #print("matchPS1:" + PS1[i] + ",line=" + line)
            if re.match(PS1[i], line):
                # print("success. matchPS1:" + PS1[i] + ",line=" + line)
                isFindPS1 = True
                break
    else:
        isFindPS1 = True
    # logging.debug("isFindPS1=%d" %(int(isFindPS1)))
    return isFindPS1

# 判断设备返回信息中是否包括需要回答的问题
def matchQuestion(line, question):
    if len(line) >= 5 and (question is not None) and len(question) > 0:
        for i in range(len(question)):
            # print("MatchQuestion:" + question[i] + ",line=" + line)
            if (re.match(question[i],line.lower())):
                # logging.debug("success. index=%d, Question=[%s], line=[%s]"%(i,question[i],line))
                return i
    return -1

# 把回答问题的答案的字符串替换成参数值
def fanswer(s, tftpServer, fileName, username, password): 
    if s is None:
        return ""
    elif re.match("{.*}", s, flags=0):
        qs = s[1:len(s)-1]
        #print("s=" +s +", qs=" +qs)
        if(qs == "tftpServer"):
            a = s.format(tftpServer=tftpServer)
        elif(qs == "fileName"):
            a = s.format(fileName=fileName)
        elif(qs == "username"):
            a = s.format(username=username)
        elif(qs == "password"):
            a = s.format(password=password)
        else:
            a = s
    else:
        a = s
    # logging.debug("fanswer: q=%s,a=%s"%(s,a))
    return a

# 判断设备返回信息中是否包括出错提示
def matchFailPrompt(line, failPrompt, failCode):
    if len(line) >= 5 and (failPrompt is not None) and len(failPrompt) > 0:
        for i in range(len(failPrompt)):
            #print("matchFailPrompt:%s,line='%s'"%(failPrompt[i],line.lower()))
            if (re.match(failPrompt[i], line.lower())):
                logging.debug("success. index=%d, failPrompt=[%s], line=[%s]"%(i,failPrompt[i],line))
                return failCode[i]
    return -1

# 判断设备返回信息是否包括一行
def matchLineEndMark(line, lineEndMark):
    if len(line) >= 5 and (lineEndMark is not None) and len(lineEndMark) > 0:
        for i in range(len(lineEndMark)):
            # print("MatchLineEndMark:" + lineEndMark[i] + ",line=" + line)
            if (re.match(lineEndMark[i],line.lower())):
                # logging.debug("success. lineEndMark:" + lineEndMark[i] + ",line=" + line)
                return True
    return False


# 读取一行信息
def s_readline(chan, lineEndMark, question, failPrompt, failCode): 
    line = ''
    count = 0
    while count < 8:
        ch = chan.recv(1).decode('ISO-8859-1')
        line += ch
        # print("ch=%s, ready=%d"%(ch , int(chan.recv_ready())))
        if chan.recv_ready() == False and (matchLineEndMark(line, lineEndMark) or matchQuestion(line,question) >= 0) \
            or matchFailPrompt(line, failPrompt, failCode) >= 0:
            break
        elif line is None or len(line) == 0:
            count += 1
    # logging.debug("line=[" + line + "]")
    return line


# 读取一行信息
def t_readline(tn, lineEndMark, question, failPrompt, failCode): 
    line = ''
    count = 0
    while count < 8:
        ch = tn.read_some().decode("ascii")
        line += ch
        #print("count=%d,line='%s'"%(count,line))
        if matchLineEndMark(line, lineEndMark) or matchQuestion(line, question) >= 0 or matchFailPrompt(line, failPrompt, failCode) >= 0:
            break
        elif line is None or len(line) == 0:
            count += 1
      
    #logging.debug("line=[" + line + "]")
    return line

# 通过ssh 方式备份 网络设备的配置
def sshconfig(cmds, replies, ip, port, username, password, isSecondConfirm, fileName):
    
    global tftpServer
    backupfile = None
    # 实例化SSHClient
    client = paramiko.SSHClient()
    # 自动添加策略，保存服务器的主机名和密钥信息
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
   
    # 连接SSH服务端，以用户名和密码进行认证
    try:
        cmd = cmds["cmd"]
        question = replies["question"]
        answer = replies["answer"]
        lineEndMark = replies["lineEndMark"]
        PS1 = replies["PS1"]
        failPrompt = replies["failPrompt"]
        failCode = replies["failCode"]

        checkBackupFile = None
        if("checkBackupFile" in cmds):
            checkBackupFile = cmds["checkBackupFile"]
            
        client.connect(hostname=ip, port=port, username=username, password=password, allow_agent=False, look_for_keys=False, timeout = 30000)
        chan = client.invoke_shell()
        chan.settimeout(60000)

        if (isSecondConfirm is not None) and isSecondConfirm == 1:
            # 处理二次登录，要求重新输入用户名和密码
            logininfo = "Second Confirm \n"
            while True:
                line = s_readline(chan, lineEndMark, question, failPrompt, failCode)
                logininfo += line

                error = matchFailPrompt(line, failPrompt, failCode)
                if error > 0:
                    return error
                
                qindex = matchQuestion(line, question)
                if qindex >= 0:
                    fas = fanswer(answer[qindex], tftpServer, fileName, username, password)
                    chan.send(fas + '\n')

                if matchPS1(line, PS1):
                    break
            logging.info(logininfo) 

        # 获取登陆后的显示消息
        welcomeinfo = ''
        while True:
            line = s_readline(chan, lineEndMark, question, failPrompt, failCode)
            welcomeinfo += line

            error = matchFailPrompt(line, failPrompt, failCode)
            if error > 0:
                return error
            
            #登录的时候也可能有提问信息
            qindex = matchQuestion(line, question)
            if qindex >= 0:
                fas = fanswer(answer[qindex], tftpServer, fileName, username, password)
                chan.send(fas + '\n')
            if matchPS1(line, PS1):
                break
        logging.info(welcomeinfo) 

        # 开始执行命令获取交换机配置文件
        for k in range(len(cmd)):
            excmd = cmd[k]
            if("tftp" in excmd and "{ip}" in excmd and "{fileName}" in excmd):
                excmd = excmd.format(ip=tftpServer, fileName=fileName)
            elif("tftp" in excmd and "{ip}" in excmd):
                excmd = excmd.format(ip=tftpServer)
            logging.info("cmd:" + excmd)
            chan.send(excmd + '\n')
            
            showInfo = ''
            while True:
                line = s_readline(chan, lineEndMark, question, failPrompt, failCode)

                error = matchFailPrompt(line, failPrompt, failCode)
                if error > 0:
                    return error
            
                qindex = matchQuestion(line, question)
                if qindex >= 0:
                    fas = fanswer(answer[qindex], tftpServer, fileName, username, password)
                    chan.send(fas + '\n')
                showInfo += line
                if matchPS1(line, PS1):
                    break
            logging.info(showInfo)
        
        backupfile = s_getBackupfile(chan, lineEndMark, checkBackupFile)
    except NoValidConnectionsError as e:
        logging.error('host %s connect fail!' %(ip))
        return 1001, None
    except AuthenticationException as e:
        logging.error('host %s password error!' %(ip))
        return 1002, None
    except Exception as e:
        logging.error('host %s unknow error!' %(ip) + str(e))
        return 1003, None
    client.close() 

    return 0, backupfile

# 通过telnet方式备份 网络设备的配置
def telnetconfig(cmds, replies, ip, port, username, password, fileName):
    global tftpServer
    try:
        cmd = cmds["cmd"]
        # PS1 = cmds["PS1"]
        question = replies["question"]
        answer = replies["answer"]
        lineEndMark = replies["lineEndMark"]
        PS1 = replies["PS1"]
        failPrompt = replies["failPrompt"]
        failCode = replies["failCode"]

        # 连接Telnet服务器
        tn = telnetlib.Telnet(ip, port=port, timeout=20)
        tn.set_debuglevel(0)
        # 登录，输入用户名和密码
        if (username is not None) and len(username) > 1:
            loginInfo = ''
            while True:
                line = t_readline(tn, lineEndMark, question, failPrompt, failCode)
                loginInfo += line
                
                error = matchFailPrompt(line, failPrompt, failCode)
                if error > 0:
                    return error
                
                qindex = matchQuestion(line, question)
                if qindex >= 0:
                    fas = fanswer(answer[qindex], tftpServer, fileName, username, password)
                    tn.write(fas.encode('ascii') + '\n'.encode())
                
                if matchPS1(line, PS1):
                    break
            logging.info(loginInfo)
        else:
            # 没有用户名和密码,直接获取登陆后的消息
            welcomeinfo = ""
            while True:
                line = t_readline(tn, lineEndMark, question, failPrompt, failCode)
                welcomeinfo += line

                error = matchFailPrompt(line, failPrompt,failCode)
                if error > 0:
                    return error
                
                if matchPS1(line, PS1):
                    break
            logging.info(welcomeinfo)
        for k in range(len(cmd)):
            excmd = cmd[k] 
            if("tftp" in excmd and "{ip}" in excmd and "{fileName}" in excmd):
                excmd = excmd.format(ip=tftpServer, fileName=fileName)
            elif("tftp" in excmd and "{ip}" in excmd):
                excmd = excmd.format(ip=tftpServer)
            logging.info("cmd:" + excmd)
            tn.write(excmd.encode('ascii') + '\n'.encode())
            
            showInfo = ''
            while True:
                line = t_readline(tn, lineEndMark, question, failPrompt, failCode)

                error = matchFailPrompt(line, failPrompt,failCode)
                if error > 0:
                    return error
                
                qindex = matchQuestion(line, question)
                if qindex >= 0:
                    fas = fanswer(answer[qindex], tftpServer, fileName, username, password)
                    tn.write(fas.encode('ascii') + '\n'.encode())
                showInfo += line
                if matchPS1(line, PS1):
                    break
            logging.info(showInfo)
        tn.close()
    except Exception as e:
        logging.error('host %s unknow error!' %(ip) + str(e))
        return 1003
    
    return 0

# 检查日志文件大小，如果超过8M，则把旧的日志文件重命名为  xx.old
def checkLogFileMaxSize(fileName):
    if os.path.exists(fileName):
        size = os.path.getsize(fileName)
        #最多日志文件大小只存8M 8*1024*1024
        if size > 8*1024*1024:
            os.rename(fileName, fileName + ".old")

    # # 如果文件存在,则追加模式
    # if os.path.exists(fileName):
    #     file = open(fileName, 'a+')
    # else:
    #     file = open(fileName, 'w+')
    # file.write(fileContent)

# 从备份文件中获取版本号
def getBackupVersion(filePath, verMark):
    if( verMark is None):
        return ''
    try:
        file = open(filePath)               # 返回一个文件对象 
        line = file.readline()              # 调用文件的 readline()方法 
        while line: 
            if len(line) >= 5 and (verMark is not None) and len(verMark) > 0:
                for i in range(len(verMark)):
                    # print("BackupVersion:" + verMark[i] + ",line=" + line)
                    line = line.strip()
                    if (line.startswith(verMark[i])):
                        version = line[len(verMark[i])+1:].strip()
                        file.close()
                        logging.debug("success. verMark:" + verMark[i] + ",line=" + line +", version=" +version)
                        return version 
            line = file.readline()
        file.close()
    except Exception as e:
        return ''
        
    return ''


# 获取不同版本文件的内容差异
def getTextDiff(filePath1,filePath2):
    try:
        file1 = open(filePath1)
        text1 = file1.read()
        file1.close()

        text2 = ''
        if os.access(filePath2, os.F_OK) and os.path.getsize(filePath2) > 56:
            file2 = open(filePath2)
            text2 = file2.read()
            file2.close()
        else:
            return ''

        text1lines = text1.splitlines()
        text2lines = text2.splitlines()

        #只返回有变更的行
        result = difflib.unified_diff(text1lines, text2lines)
        result = "\n".join(result)
    except Exception as e:
        return ''
    return result

# 清除过期的备份配置数据
def clearExpiredBackup(retain_days, cursorlog):
    if(retain_days < 7):
       retain_days = 7
    e_time = int(time.time()) - retain_days*24*3600 + 3600    
    e_datetime = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(e_time))
    logging.info("retain_days=%d, e_datetime=%s"%(retain_days,e_datetime))
    
    sql = "SELECT backup_file,status FROM backup_device_log WHERE create_time < '{e_datetime}';".format(e_datetime=e_datetime)
    logging.info("sql: %s"%(sql))
    cursorlog.execute(sql)
    results_log = cursorlog.fetchall()
    for row in results_log:
        filePath = row[0]
        status = row[1]
        logging.info("status=%d, removefile=%s"%(status,filePath))
        if os.path.exists(filePath):
            os.remove(filePath)
    sql = "DELETE FROM backup_device_log WHERE create_time < '{e_datetime}';".format(e_datetime=e_datetime)
    logging.info("sql: %s"%(sql))
    cursorlog.execute(sql)
    return

def initLog(logMode):
    logFileName = "/usr/local/tognix/data/tognix_backup_device.log"
    
    #logging.basicConfig(filename=logFileName,
    #                  format = '%(asctime)s-%(name)s-%(funcName)s-%(levelname)s: %(message)s',
    #                  level=logging.DEBUG)
    logging.basicConfig(format = '%(asctime)s-%(name)s-%(funcName)s-%(levelname)s: %(message)s',
                      level=logging.DEBUG)
    log = logging.getLogger()
    formatter = logging.Formatter('%(asctime)s-%(name)s-%(funcName)s-%(levelname)s: %(message)s')
    #if(logMode == 0):
    #    shd = logging.StreamHandler(sys.stdout)
    #    shd.setFormatter(formatter)
    #    shd.setLevel(logging.DEBUG)
    #    log.addHandler(shd)
    if(logMode == 1):
        checkLogFileMaxSize(logFileName)
        fhd = logging.FileHandler(logFileName)
        fhd.setLevel(logging.DEBUG)
        fhd.setFormatter(formatter)
        log.addHandler(fhd)

def main():
    
    argc = len(sys.argv)
    testDeviceIp = None
    if(argc > 1):
        testDeviceIp = sys.argv[1]
    
    global tftpServer
    useJsonConfig = False
    enable = 1
    initLog(0)
    logging.info("begin backup device config...")
    if(useJsonConfig):  # 从配置文件读取配置信息
        file = open("device_config.json", "rb")
        cJson = json.load(file)
        dbhost=cJson["DBHost"]
        dbport=cJson["DBPort"]
        dbuser=cJson["DBUser"]
        dbpasswd=cJson["DBPassword"]
        dbname=cJson["DBName"]
    else: # 从数据库读取配置信息
        dbhost="127.0.0.1"
        dbport=3306
        dbuser="TognixAdmin"
        dbpasswd="Bzy8@9Irgd"
        dbname="tognix"
        conncfg = pymysql.connect(host=dbhost, port=dbport, user=dbuser, passwd=dbpasswd, db=dbname)
        cursor_cfg = conncfg.cursor()
        cursor_cfg.execute("select value from tognix_config where tag = 'backup_device'")
        results = cursor_cfg.fetchall()
        cJson = None
        for row in results:
            cfg_content = row[0]
            cJson = json.loads(cfg_content)
        conncfg.close()
        if cJson is None:
            logging.error("get device config error from db!")
            sys.exit(0)

    logMode = cJson["logMode"]
    if logMode is not None and logMode == 1:
        initLog(1)

    cmdlist = cJson["cmds"]
    tftpServer = cJson["tftpServer"]
    tftpPath = cJson["tftpPath"]
    replies = cJson["replies"]
    retain_days = cJson["retain_days"]

    enable = cJson["enable"]
    # 禁止使用备份,则不执行
    if enable is not None and enable == 0:
        logging.error("disable backup device!")
        sys.exit(0)

    isFindBackupFile = False
    isCheckDiff = 1
    status = 1003

    connlog = pymysql.connect(host=dbhost, port=dbport, user=dbuser, passwd=dbpasswd, db=dbname)
    cursorlog = connlog.cursor()

    conn = pymysql.connect(host=dbhost, port=dbport, user=dbuser, passwd=dbpasswd, db=dbname)
    cursor = conn.cursor()
    if(testDeviceIp is not None): #对某台设备执行备份配置
        cursor.execute("select b.hostname, b.ip,c.port,b.device_type,b.isSecondConfirm,c.type,c.user,c.password from backup_device_config b join credentials c on c.id = b.credentialid where b.ip = '%s'"%(testDeviceIp))
    else:
        cursor.execute("select b.hostname, b.ip,c.port,b.device_type,b.isSecondConfirm,c.type,c.user,c.password from backup_device_config b join credentials c on c.id = b.credentialid where b.enable = 1")
    results = cursor.fetchall()
    for row in results:
        hostname = row[0]
        ip = row[1]
        port = row[2]
        device_type = row[3]
        isSecondConfirm = row[4]
        type = row[5]
        user = row[6]
        password = row[7]
        
        version = ''
        config_type = ""
        fileName = "config_{}_{}_{}.cfg".format(device_type, ip, time.strftime("%Y.%m.%d.%H.%M.%S",time.localtime()))
        filePath = tftpPath + fileName

        logging.info(" backup: ip={}, port={}, type={}, device_type={}, user={}, isSecondConfirm={}" \
            .format( ip, port, type, device_type, user, isSecondConfirm))

        isFindCmd = False
        # 找到该设备对应的命令集
        for i in range(len(cmdlist)):
            if re.search(device_type, cmdlist[i]["type"], re.IGNORECASE):
                cmds = cmdlist[i]
                isFindCmd = True
                break
        
        if isFindCmd:
            verMark = None
            config_type = cmds["config_type"]
            if("verMark" in cmds):
                verMark = cmds["verMark"]

            isCheckFile = 1
            if("isCheckFile" in cmds):
                isCheckFile = cmds["isCheckFile"]

            isCheckDiff = 1
            if("isCheckDiff" in cmds):
                isCheckDiff = cmds["isCheckDiff"]

            backupfile = None
            status = 1003
            if(type is None or len(type) == 0):
                status = 1006
            elif type.lower() == "ssh":
                status, backupfile = sshconfig(cmds, replies, ip, port, user, password, isSecondConfirm, fileName) 
            elif type.lower() == "telnet":
                status = telnetconfig(cmds, replies, ip, port, user, password, fileName)
           
            # 如果备份文件不为空，则用backupfile
            if backupfile is not None and len(backupfile) > 0:
                filePath = tftpPath + backupfile
            
            tryCount = 0
            maxTimes = 9
            isFindBackupFile = False
            # 如果状态是成功的,则尝试判断文件是否存在。因为tft上传需要一定时间，所以这里轮询看看文件是否存在，最长8秒
            while isCheckFile == 1 and status == 0 and tryCount < maxTimes:
                if os.access(filePath, os.F_OK) and os.path.getsize(filePath) > 56:
                    version = getBackupVersion(filePath, verMark)
                    isFindBackupFile = True
                    status = 0
                    break
                elif tryCount < (maxTimes - 1):
                    time.sleep(1)
                elif tryCount == (maxTimes - 1):
                    status = 1004  # 找不到备份的配置文件
                    break
                tryCount += 1
            logging.info("status=%d,fileExist=%s,tryCount=%d,file=%s"%(status,isFindBackupFile,tryCount,filePath))
        else:
            status = 1005  # 找不到该设备品牌的执行命令配置
        
        # 比较这个版本和上个版本的内容的差异
        textDiff = ''
        if(isFindBackupFile and isCheckDiff == 1):
            cursorlog.execute("SELECT backup_file FROM backup_device_log WHERE ip = '{ip}' ORDER BY id desc LIMIT 1;".format(ip=ip))
            results_log = cursorlog.fetchall()
            for row in results_log:
                lastFilePath = row[0]
                textDiff = connlog.escape_string(getTextDiff(lastFilePath, filePath))
                logging.info("lastFilePath=%s, filePath=%s, textDiff: %s"%(lastFilePath,filePath,textDiff))
        
        # 备份配置没有成功,则把配置文件路径设置为空
        if status != 0 and status != 1004:
            filePath = ''
        #插入日志数据
        now_time = time.strftime("%Y-%m-%d %H:%M:%S",time.localtime())
        log_sql = "INSERT INTO backup_device_log (hostname, ip, version, config_type, backup_file, diff_text, status, create_time) " \
                "VALUES ('{hostname}', '{ip}', '{version}', '{config_type}', '{backup_file}', '{diff_text}',{status}, '{create_time}');" \
                .format(hostname=hostname,ip=ip,version=version,config_type=config_type,backup_file=filePath,diff_text=textDiff, status=status,create_time=now_time)
        logging.info("sql: %s"%(log_sql))
        cursorlog.execute(log_sql)
        connlog.commit()
    
    clearExpiredBackup(retain_days, cursorlog)
    connlog.commit()

    conn.close()
    connlog.close()
    sys.exit(0)

if __name__ == '__main__':
    main()
