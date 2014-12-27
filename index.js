
var express = require('express')
var app = express();
var bodyParser = require('body-parser')
var jsonParser = bodyParser.json()
var mout = require('mout')
var randomstring = require('randomstring')
var crypto = require('crypto')

var signatureSalt = process.env.SIGNATURE_SALT || 'dnV5aMxmvCVqPCLdG2hw';

var mongodb = require('mongodb')
, MongoClient = mongodb.MongoClient;

var cachedConnection = null;
function ensureMongoConnection(callback) {
  if (cachedConnection) {
    return callback(null, cachedConnection);
  }

  MongoClient.connect(process.env.MONGOLAB_URI, function(error, connection) {
    cachedConnection = connection;
    connection.on('close', function() {
      cachedConnection = null;
    });
    callback(error, connection);
  })
}


app.set('port', (process.env.PORT || 5000))
app.use(express.static(__dirname + '/public'))

var allowCrossDomain = function(req, res, next) {
    res.header('Access-Control-Allow-Origin', '*'); // FIXME: make proper config
    res.header('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE');
    res.header('Access-Control-Allow-Headers', 'Content-Type');

    next();
}
app.use(allowCrossDomain);

function hashString(str) {
  var hash = crypto.createHash('sha1');
  hash.update(str, 'utf8');
  return hash.digest('base64');
}

app.put('/domains', jsonParser, function(request, response) {
  response.header('Access-Control-Allow-Origin', '*'); // TODO: remove
  if (!request.body && mout.lang.isObject(request.body))
    return  response.status(400).send('Must send json body');

  var cleanBody = mout.object.filter(request.body, mout.lang.isString);
  var signature = createSignature(cleanBody);
  })

app.post('/command', jsonParser, function(request, response) {
  response.header('Access-Control-Allow-Origin', '*'); // TODO: remove
  if (!request.body || request.body === {} || !request.body.command)
    return response.status(400).send("Bad Request - Command body missing.");
  try {
    var command = parseCommandFromBody(request.body);
  } catch(error) {
    if (error.type === 'command-parsing') {
      return response.status(400).send('Command parsing failed: '+ error.message);
    } else {
      throw error;
    }
  }
  switch(command.command) {
    case 'query-domains':
      return handleQueryDomains(request, response);
    case 'generate-password':
      return handleGeneratePassword(request, response);
  }
})

function makeError(type, message) {
  if (!type) throw new Error('Must provide type when creating errors');
  var error = new Error(message || 'An ' + type + ' error occured');
  error.type = type;
  return error;
}

function parseCommandFromBody(body, allowedProperties) {
  allowedProperties = (allowedProperties || []).concat(['command', 'username', 'masterPassword'])
  var clean = mout.object.filter(body, function(value, name) {
    return (mout.lang.isString(value) || mout.lang.isNumber(value)) &&
      mout.array.contains(allowedProperties, name)
  })
  if (!clean.username)
    throw makeError('command-parsing', 'username property missing');
  if (!clean.masterPassword)
    throw makeError('command-parsing', 'masterPassword property missing');
  clean.signature = hashString(clean.username + clean.masterPassword + signatureSalt);
  return clean;
}

function handleQueryDomains(request, response) {
  var command = parseCommandFromBody(request.body, ['query']);
  if (!command.query)
    return response.status(400).send("Bad request - query parameter missing");
  if (command.query.length < 3)
    return response.json([]);
  ensureMongoConnection(function(err, db) {
    var collection = db.collection('domains');
    collection.find({
      signature: command.signature,
      domainName: new RegExp('^'+request.body.query+'.*')
    }, function(error, cursor) {
      cursor.toArray(function(error, domains) {
        response.json(domains.map(function(domain){
          return {
            domainName: domain.domainName
          }
        }));
      })
    })
  })
}

function handleGeneratePassword(request, response) {
  var command = parseCommandFromBody(request.body, ['domainName']);

  ensureMongoConnection(function(err, db) {
    var collection = db.collection('domains');
    collection.ensureIndex( { signature: 1, domainName: 1 }, { unique: true } , function() {
      collection.findOne({
        signature: command.signature,
        domainName: command.domainName
      }, function(error, item) {
        if(error) {
          return response.status(500).send("Error:" + error.message);
        }
        if (!item) {
          item = {
            signature: command.signature,
            domainName: command.domainName,
            salt: randomstring.generate(32)
          }
          collection.insert(item, function() {
            response.status(201).send({
              generatedPassword: hashString(command.signature+item.salt)
            })
          })
        } else {
          response.status(200).send({
            generatedPassword: hashString(command.signature+item.salt)
          })
        }
      })
    })
  })
}



app.listen(app.get('port'), function() {
  console.log("Node app is running at localhost:" + app.get('port'))
})
