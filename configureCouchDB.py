import couchdb
import ConfigParser

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

def connect_couch(cdbServer):
  try:
    couch = couchdb.Server(cdbServer)
  except:
    print"CouchDB Server Connection Failed:", cdbServer
    exit(1)
  return couch

def create_db(dbName):
	return something

def main():

	couchDB = connect_couch(config_map("couchdb")['couchserver'])
	print 'couch connected:', couchDB

	try:
		dbName = str(config_map("couchdb")['dbname'])
		db = couchDB.create(dbName)
		print "Database was created:", dbName
	except Exception as inst:
		print inst
		print "Somethign wrong happened, does", dbName, "already exist?"

	try:
		db = couchDB[dbName]
		view = {'_id': '_design/Attachments', 'views': { 'by_md5': { 'map': 'function(doc) { emit(doc[\'MD5\'], doc); }'}}}
		db.create(view)
	except Exception as inst:
		print inst


if __name__ == '__main__':
  try:
    main()
  except KeyboardInterrupt:
    pass