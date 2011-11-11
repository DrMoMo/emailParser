# -*- coding: utf-8 -*-

#IMPORT
from imaplib import *
import ConfigParser
import time
import pprint
import email
import re
import os
import couchdb
import hashlib
import smtplib
import simplejson
import urllib
import urllib2
import postfile #this comes with the scripts

config = ConfigParser.ConfigParser()
config.read('emailParser.conf')


def config_map(section):
  dict1 = {}
  options = config.options(section)
  for option in options:
    try:
      dict1[option] = config.get(section, option)
      if dict1[option] == -1:
        DebugPrint("skip: %s" % option)
    except:
      print("exception on %s!" % option)
      dict1[option] = None
  return dict1


def connect_imap(host,port,username,password):
  try:
    connection = IMAP4_SSL(host,port)
  except:
    print"IMAP Server Connection Failed:", host, port
    exit(1)
  try:
    connection.login(username,password)
  except IMAP4.error, e:
    print e
    exit(1)
  return connection


def connect_couch(cdbServer, dbName):
  try:
    couch = couchdb.Server(cdbServer)
    db = couch[dbName]
  except:
    print"CouchDB Server Connection Failed:", cdbServer
    exit(1)
  return db


def calc_md5(content):
  md5hash = hashlib.md5()
  md5hash.update(content)
  return md5hash.hexdigest()


def connect_smtp(serverURL=None, port=''):
  smtp_connection = smtplib.SMTP(serverURL, port)
  return smtp_connection


def send_email(mailServer='', sender='', to='', subject='', text=''):
    headers = "From: %s\r\nTo: %s\r\nSubject: %s\r\n\r\n" % (sender, to, subject)
    message = headers + text
    
    mailServer.sendmail(sender, to, message)
    

def close_smtp(smtp_connection):
  smtp_connection.quit()


def mail_count(connection, mailbox):
  try:
    typ, msg_count = connection.select(mailbox)
  except:
    print "Could not connect to mailbox"
  msg_count = int(msg_count[0])
  return msg_count


def get_email(email_id,connection):
  typ, msg_data = connection.fetch(email_id, '(RFC822)')
  email_body = msg_data[0][1]
  mail = email.message_from_string(email_body)
  mail['id'] = email_id
  mail['attachments'] = []
  for part in mail.walk():
    if part.get_content_maintype() == 'multipart':
      continue
    if part.get('Content-Disposition') is None:
      continue
    attachment = {}
    attachment['filename'] = part.get_filename()
    data = part.get_payload(decode=True)
    if not data:
      continue
    attachment['content'] = part.get_payload(decode=True)
    attachment['md5sum'] = calc_md5(attachment['content'])
    mail['attachments'] += [attachment] 
  return mail


def delete_email(email_id, connection):
  connection.store(email_id, '+FLAGS', '\\Deleted')


def close_email(connection):
  connection.expunge()
  connection.logout()


def check_couch(db,attachment):
  results = db.view('Attachments/by_md5', key=attachment['md5sum'])
  return results.rows


def append_new_instance(dbRecord,email,att):
  instance = {}
  instance['From'] = email['from']
  instance['Subject'] = email['subject']
  instance['Date'] = email['date']
  instance['Filename'] = att['filename']
  if instance not in dbRecord['Instances']:
    dbRecord['Instances'].append(instance)
  return dbRecord


def post_new_couch(db,email,att):
  dbRecord = {}
  dbRecord['Instances'] = []
  dbRecord['MD5'] = att['md5sum']
  dbRecord['Content'] = att['content']
  dbRecord = append_new_instance(dbRecord,email,att)
  try:
    return db.create(dbRecord)
  except Exception as inst:
    return False


def post_existing_couch(db,document,email,att):
  doc = append_new_instance(document,email,att)
  db.create(doc)
  return doc


def check_virustotal(md5, file_to_send, filename):
  parameters = {"resource": md5, "key": config_map("virustotal")['apikey']}
  data = urllib.urlencode(parameters)
  req = urllib2.Request(config_map("virustotal")['geturl'], data)
  response = urllib2.urlopen(req)
  json = response.read()
  datastructure = simplejson.loads(json)
  if datastructure.get("result") == 1:
    virus_count = 0
    av_count = 0
    results = ''  
    for av, virus in datastructure.get("report")[1].iteritems():
      av_count += 1
      if virus:
        virus_count += 1
      else:
        virus = '--'
      results += av + ': ' + virus + '\n'
    avscore = 'Score: ' + str(virus_count) + '/' + str(av_count) +' \n'
    message = str(avscore) + str(results)
  elif datastructure.get("result") == 0: 
    fields = [("key", config_map("virustotal")['apikey'])]
    files = [("file", filename, file_to_send)]
    json = postfile.post_multipart(config_map("virustotal")['host'], config_map("virustotal")['sendurl'], fields, files)
    datastructure = simplejson.loads(json)
    scanid = str(datastructure.get("scan_id"))
    message = '''
    There is no history of a virus scan for this MD5.\n
    One has been submitted to virustotal.com with Scan ID: %s''' % (scanid)
  else: 
    message = "There was an issue with interfacting with virustotal.com.  Error Code:" + str(datastructure.get("result"))
  return message


def main():
  print 'Running main()'
  connection = connect_imap(config_map("imap")['imapserver'], config_map("imap")['imapport'], config_map("imap")['imapusername'], config_map("imap")['imappassword'])
  print 'connection made:', connection
  couchDB = connect_couch(config_map("couchdb")['couchserver'], config_map("couchdb")['dbname'])
  print 'couch connected:', couchDB
  msgCount = mail_count(connection, config_map("imap")['imapmailbox'])
  print 'messages counted:', msgCount
  smtp_connection = connect_smtp(config_map("smtp")['smtpserver'],config_map("smtp")['smtpport'])
  print 'connection made:', smtp_connection

  emails = [get_email(x,connection) for x in range(1,msgCount+1)]
  emails_w_att = [email for email in emails if email['attachments']]
  emails_wo_att = [email for email in emails if not email['attachments']]

  for email in emails_wo_att:
    delete_email(email['id'],connection)
  
  for email in emails_w_att:

    for att in email['attachments']:

      document = check_couch(couchDB,att)
      
      if document:
        post_existing_couch(couchDB,document[0]['value'],email,att)
      else:
        try:
          post_new_couch(couchDB,email,att)
        except: 
          print "Upload to database failed"
          exit()
      
      antivirus_report = check_virustotal(att['md5sum'], att['content'], att['filename'])   

    emailBody = '''
    Hello, \n
    I was sent an email with a suspicious attachment from: %s.  
    Here is some preliminary analysis:\n
    Date: %s
    Sent in by: %s
    Subject: %s
    Filename: %s
    MD5: %s
    File Size: This function is not yet availble. \n
    ''' % (email['from'], email['date'],email['from'],email['subject'],att['filename'],att['md5sum'])

    emailBody += '### Antivirus ###\n'
    emailBody += str(antivirus_report)

    emailBody += '\n\nChecking the database if I have been sent this attachment before:\n'
    if document:
      emailBody += "Yes, we have seen this MD5 before! Here are the previous emails:\n"
      for row in document[0]['value']['Instances']:
        emailBody += '''
        Date: %s
        Sent in by: %s
        Subject: %s
        Filename: %s\n 
        ''' % (row['Date'], row['From'], row['Subject'], row['Filename'])
    else:
        emailBody += "No, this MD5 has never been seen before.\n"  


    emailSubject = config_map("smtp")['emailsubjectprefix'] +' '+ att['filename']
    send_email(smtp_connection,config_map("smtp")['emailfrom'],config_map("smtp")['emailto'],emailSubject,emailBody)

    delete_email(email['id'],connection)
  
  close_email(connection)
  close_smtp(smtp_connection)


if __name__ == '__main__':
  try:
    main()
  except KeyboardInterrupt:
    pass