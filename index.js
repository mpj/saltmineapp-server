
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

app.set('port', (process.env.PORT || 5000))
app.use(express.static(__dirname + '/public'))

function createSignature(body) {
  if (!body.username) throw new Error('No username on body');
  if (!body.masterPassword) throw new Error('No masterPassword on body');
  var str = body.username+body.masterPassword+signatureSalt;
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
  MongoClient.connect(process.env.MONGOHQ_URL, function(err, db) {
    var collection = db.collection('domains');
    collection.ensureIndex( { signature: 1, domain: 1 }, { unique: true } , function() {
      collection.findOne({
        signature: signature,
        domain: cleanBody.domainName
      }, function(error, item) {
        if (!error && !item) {
          collection.insert({
            signature: signature,
            domain: cleanBody.domainName,
            salt: randomstring.generate(32)
          }, function() {})
          response.status(201).send('OK');
        } else if(!error && item) {
          response.send('OK');
        } else {
          response.status(500).send("Error:" + error.message);
        }
      })
    })
  })
})

app.post('/domains', jsonParser, function(request, response) {
  response.header('Access-Control-Allow-Origin', '*'); // TODO: remove
  if (!request.body || !mout.lang.isString(request.body.query)) {
    response.status(400).send("Bad Request");
    return;
  };
  var cleanBody = mout.object.filter(request.body, mout.lang.isString);
  if (cleanBody.query.length < 3) {
    return response.json([]);
  }
  var signature = createSignature(cleanBody);
  MongoClient.connect(process.env.MONGOHQ_URL, function(err, db) {
    var collection = db.collection('domains');
    collection.find({
      signature: signature,
      domain: new RegExp('^'+request.body.query+'.*')
    }, function(error, cursor) {
      cursor.toArray(function(error, domains) {
        response.json(domains.map(function(domain){
          return {
            domainName: domain.domain
          }
        }));
      })
    })
  })
})

// TODO: Regen domain salt

app.listen(app.get('port'), function() {
  console.log("Node app is running at localhost:" + app.get('port'))
})
