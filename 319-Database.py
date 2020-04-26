#!/usr/bin/env python3
import mysql.connector
import os
import utmp
import gzip
from progress.bar import Bar


mydb = ""
cur = ""

def createCase(caseName):

   cur.execute("create database {};".format(caseName))

   cur.execute("use {};".format(caseName))

   tables=dict()
   tables["filesTable"]="""create table files (
   AccessDate datetime not null,
   ModifyDate datetime not null,
   CreateDate datetime not null,
   Permissions int not null,
   UserId bigint not null,
   GroupId bigint not null,
   FileSize bigint not null,
   Filename varchar(2048) not null,
   recno bigint not null auto_increment,
   primary key(recno)
   );"""


   tables["usersTable"]="""create table users (
   username varchar(255) not null,
   passwordHash varchar(255) not null,
   uid int not null,
   gid int not null,
   userInfo varchar(255) not null,
   homeDir varchar(255) not null,
   shell varchar(2048) not null,
   primary key (username)
   );"""


   tables["groupsTable"]="""create table user_groups (
   groupname varchar(255) not null,
   passwordHash varchar(255) not null,
   gid int not null,
   userlist varchar(2048)
   );"""


   tables["historiesTable"]="""create table if not exists histories (
   historyFilename varchar(2048) not null,
   historyCommand varchar(2048) not null,
   recno bigint not null auto_increment,
   primary key(recno)
   );"""


   tables["logsTable"]="""create table if not exists logs (
   logFilename varchar(2048) not null,
   logentry LONGTEXT not null,
   recno bigint not null auto_increment,
   primary key(recno)
   );"""


   tables["loginsTable"]="""create table logins (
   who_what varchar(8),
   terminal_event varchar(13),
   start datetime,
   stop datetime,
   elapsed varchar(12),
   ip varchar(15),
   recno bigint not null auto_increment,
   primary key(recno)
   );"""


   tables["login_failsTable"]="""create table login_fails (
   who_what varchar(8),
   terminal_event varchar(13),
   start datetime,
   stop datetime,
   elapsed varchar(12),
   ip varchar(15),
   recno bigint not null auto_increment,
   primary key(recno)
   );"""


   tables["timelineTable"]="""create table timeline (
   Operation char(1),
   Date datetime not null,
   recno bigint not null);"""


   for tableName, tableCommand in tables.items():
       print("\t {} table created.".format(tableName) )
       cur.execute(tableCommand)




def getMacTimes(evidencePath):
    removePath=len(evidencePath.split('/'))

    for dirpath,_,filenames in os.walk(evidencePath):
        for f in filenames:
            try:
                fileName=os.path.abspath(os.path.join(dirpath, f))
                fileMeta=os.stat(fileName)
            except:
                continue
            sqlCommand="INSERT INTO files (AccessDate, ModifyDate, CreateDate, Permissions, UserId, GroupId, FileSize, FileName) VALUES (FROM_UNIXTIME({}), FROM_UNIXTIME({}), FROM_UNIXTIME({}), {}, {}, {}, {}, '{}')".format(int(fileMeta.st_atime), int(fileMeta.st_mtime), int(fileMeta.st_ctime), fileMeta.st_mode, fileMeta.st_uid, fileMeta.st_gid, fileMeta.st_size, '/'+'/'.join( (fileName.split('/')[removePath:]) ))
            cur.execute(sqlCommand)


def getUsers(evidencePath):

    with open(evidencePath+"/etc/passwd") as passwdFile:
        passwd=passwdFile.readlines()

    with open(evidencePath+"/etc/shadow") as shadowFile:
        shadow=shadowFile.readlines()

    for passwdEntry, shadowEntry in zip(passwd,shadow):
       passwdEntry=passwdEntry.replace('\n','').split(':')
       shadowEntry=shadowEntry.replace('\n','').split(':')
       passwdEntry[1]=shadowEntry[1]
       sqlCommand="INSERT INTO users (username, passwordHash, uid, gid,userInfo, homeDir, shell) VALUES ('{0}','{1}',{2},{3},'{4}','{5}','{6}')".format(*passwdEntry)
       cur.execute(sqlCommand)




def getGroups(evidencePath):

    with open(evidencePath+"/etc/group") as groupsFile:
        groups=groupsFile.readlines()

    for record in groups:
       record=record.replace('\n','').split(':')
       sqlCommand="INSERT INTO user_groups (groupname, passwordHash, gid, userlist) VALUES ('{0}','{1}',{2},'{3}')".format(*record)
       cur.execute(sqlCommand)


def getBashHistory(evidencePath):

    cur.execute('SELECT filename from files where filename like "%bash_history%"')

    bashHistoryPathList=cur.fetchall()
    bar = Bar('Processing Bash History Files', max=len(bashHistoryPathList))

    for bashHistoryPath in bashHistoryPathList:
        bashHistoryPath=bashHistoryPath[0]
        with open(evidencePath+bashHistoryPath,'r') as bashHistoryFile:
            bashHistory=bashHistoryFile.readlines()

        for bashCommand in bashHistory:
            bashCommand=bashCommand.replace("\n","").replace("\\","\\\\").replace("'","\\'")
            sqlCommand="INSERT INTO histories (historyFilename, historyCommand) VALUES ( '{0}','{1}' )".format(bashHistoryPath, bashCommand)
            cur.execute(sqlCommand)
        bar.next()
    bar.finish()


def getLogins(evidencePath):
    cur.execute('SELECT filename from files where filename like "/var/log/atmp%"')
    wtempPathList=cur.fetchall()
    for wtempPath in wtempPathList:
      wtempPath=wtempPath[0]
      with open(evidencePath+wtempPath,'rb') as fd:
          buf=fd.read()
          for entry in utmp.read(buf):
              who_what=entry.user
              terminal_event=str(entry.type).split(".")[1]
              start=entry.sec
              host=entry.host
              elapsed=entry.usec
              if elapsed != 0 and len(host) < 15 and len(host) >= 7:
                  stop=start+elapsed
                  sqlCommand="INSERT INTO logins (who_what, terminal_event, start, stop, elapsed,ip) VALUES ( '{}', '{}',FROM_UNIXTIME({}), FROM_UNIXTIME({}),{}, '{}') ".format(who_what,terminal_event,start,stop,elapsed,host)
              elif elapsed == 0 and len(host) < 15 and len(host) >=7:
                  sqlCommand="INSERT INTO logins (who_what, terminal_event, start, ip) VALUES ( '{}', '{}',FROM_UNIXTIME({}), '{}') ".format(who_what,terminal_event,start,host)
              else:
                  sqlCommand="INSERT INTO logins (who_what, terminal_event, start) VALUES ( '{}', '{}',FROM_UNIXTIME({}) ) ".format(who_what,terminal_event,start)

              cur.execute(sqlCommand)



def getFailLogins(evidencePath):
    cur.execute('SELECT filename from files where filename like "/var/log/btmp%"')
    wtempPathList=cur.fetchall()
    for wtempPath in wtempPathList:
      with open(evidencePath+wtempPath[0],'rb') as fd:
          buf=fd.read()
          for entry in utmp.read(buf):
              who_what=entry.user
              terminal_event=str(entry.type).split(".")[1]
              start=entry.sec
              host=entry.host
              elapsed=entry.usec
              if elapsed != 0 and len(host) < 15 and len(host) >= 7:
                  stop=start+elapsed
                  sqlCommand="INSERT INTO login_fails (who_what, terminal_event, start, stop, elapsed,ip) VALUES ( '{}', '{}',FROM_UNIXTIME({}), FROM_UNIXTIME({}),{}, '{}') ".format(who_what,terminal_event,start,stop,elapsed,host)
              elif elapsed == 0 and len(host) < 15 and len(host) >=7:
                  sqlCommand="INSERT INTO login_fails (who_what, terminal_event, start, ip) VALUES ( '{}', '{}',FROM_UNIXTIME({}), '{}') ".format(who_what,terminal_event,start,host)
              else:
                  sqlCommand="INSERT INTO login_fails (who_what, terminal_event, start) VALUES ( '{}', '{}',FROM_UNIXTIME({}) ) ".format(who_what,terminal_event,start)

              cur.execute(sqlCommand)



def getLogs(evidencePath):

    cur.execute('SELECT filename from files where filename like "/var/log%" and filename not like "/var/log/btmp%" and filename not like "/var/log/atmp%"')

    logFilePathList=cur.fetchall()

    bar = Bar('Processing Log Files', max=len(logFilePathList))
    for logFilePath in logFilePathList:
        logFilePath=logFilePath[0]
        try:
            with gzip.open(evidencePath+logFilePath) as logFile:
                logFileEntries=logFile.readlines()

        except:
            with open(evidencePath+logFilePath,'r',encoding='utf-8', errors='ignore') as logFile:
                logEntries=logFile.readlines()

        for logEntry in logEntries:
            if len(logEntry) > 2048:
                logEntry=logEntry[:2048]
            logEntry=logEntry.replace("\n","").replace("\\","\\\\").replace("'","\\'")
            if len(logEntry) == 0:
                continue
            sqlCommand="INSERT INTO logs (logFilename, logentry) VALUES ( '{0}','{1}' )".format(logFilePath, logEntry)
            cur.execute(sqlCommand)
        bar.next()
    bar.finish()

def createTimeLine():
    bar = Bar('Adding Data to Timeline', max=3)
    cur.execute("insert into timeline (Operation, Date, recno) select 'A', accessdate, recno from files")
    bar.next()
    cur.execute("insert into timeline (Operation, Date, recno) select 'M', modifydate, recno from files")
    bar.next()
    cur.execute("insert into timeline (Operation, Date, recno) select 'C', createdate, recno from files")
    bar.next()
    bar.finish()



def main():
    caseName=input("\nEnter a name for your case database (This will be your database name): ")
    evidencePath=input("\nEnter the absolute path to the mount point of your evidence (This should be /medi/part0 if you used the mount script): ")
    mysqlUserName=input("\nEnter your mysql database username: ")
    mysqlPassword=input("\nEnter your mysql database password: ")
    global mydb
    mydb = mysql.connector.connect(host='localhost',user=mysqlUserName, password=mysqlPassword,auth_plugin='mysql_native_password')
    global cur
    cur = mydb.cursor()
    print("\n\nStarting case database creation.\n")
    createCase(caseName)
    print("\nThe Case Database is all setup!!")
    print("\n\nNow to start proccessing those files!")
    print("\n\nGeting MAC Times Now! This Could Take A While....Grab a coffe!")
    getMacTimes(evidencePath)
    print("\n\nGeting User and Group Info Now!")
    getUsers(evidencePath)
    getGroups(evidencePath)
    print("\n\nGeting Bash History Now!")
    getBashHistory(evidencePath)
    print("\n\nGeting Login Data Now!")
    getLogins(evidencePath)
    getFailLogins(evidencePath)
    print("\n\nGeting Login Data Now! This Could Take A While...Drink that coffe!")
    getLogs(evidencePath)
    print("\n\nNow to create that timeline of file MAC times!!")
    createTimeLine()
    mydb.commit()
    print("\n\nProccessing Done!! Have a look! (if you are lazy like me run sudo mysql and remember to select your database with the mysql statment use 'your database name' before running further sql statements!)")
if __name__ == "__main__":
    main()
