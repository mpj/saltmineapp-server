
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

function createSignature(body) {
  if (!body.username) throw new Error('No username on body');
  if (!body.masterPassword) throw new Error('No masterPassword on body');
  var str = body.username+body.masterPassword+signatureSalt;
  return hashString(str);
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
        if(error) {
          return response.status(500).send("Error:" + error.message);
        }
        if (!item) {
          item = {
            signature: signature,
            domain: cleanBody.domainName,
            salt: randomstring.generate(32)
          }
          collection.status(201).insert(item, function() {
            response.status.send({
              generatedPassword: hashString(signature+item.salt)
            })
          })
        } else {
          response.status(200).send({
            generatedPassword: hashString(signature+item.salt)
          })
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
