const express = require('express')
const app = express();
const bodyParser = require('body-parser')
app.use(bodyParser.json());       // to support JSON-encoded bodies
app.use(bodyParser.urlencoded({     // to support URL-encoded bodies
  extended: true
}));

app.post('/', (req, res) => {
  var raw = req.body.log

  var b = raw.split('|')
  var c = b[b.length - 1]
  var d = c.split('=')

  var logObject = []
  d.map(i => {
    var arr = i.split(' ')
    logObject.push(arr[0])
    logObject.push(arr[1])
  })
  var dpt_index = d.findIndex(ele => ele == " sourceTranslatedZoneURI")
  var spt_index = d.findIndex(ele => ele == " destinationZoneURI")


  var timestamp = logObject.findIndex(ele => ele == "art")
  var category = logObject.findIndex(ele => ele == "cs1")
  var action = logObject.findIndex(ele => ele == "act")
  var signature = logObject.findIndex(ele => ele == "categorySignificance")
  var dest_ip = logObject.findIndex(ele => ele == "dst")
  var dest_port = d.findIndex(ele => ele == " sourceTranslatedZoneURI")
  var src_ip = logObject.findIndex(ele => ele == "src")
  var src_port = raw.indexOf("spt")
  var proto = logObject.findIndex(ele => ele == "proto")
  var severity = logObject.findIndex(ele => ele == "severity")
  var direction = logObject.findIndex(ele => ele == "deviceDirection")
  var domain = logObject.findIndex(ele => ele == "domain")
  var host = logObject.findIndex(ele => ele == "dhost")

  var region_name = logObject.findIndex(ele => ele == "region_name")
  var timezone = logObject.findIndex(ele => ele == "timezone")
  var city_name = logObject.findIndex(ele => ele == "city_name")
  var lat = logObject.findIndex(ele => ele == "dlat")
  var country_name = logObject.findIndex(ele => ele == "country_name")
  var lon = logObject.findIndex(ele => ele == "dlong")
  var ip = logObject.findIndex(ele => ele == "dst")

  var tags = 0

  if (!(region_name < 0 && timezone < 0 && city_name < 0 && lat < 0 && country_name < 0 && lon < 0 && ip < 0)) {
    tags = 1
  }

  var json = {}
  json.timestamp = logObject[timestamp + 1]
  json.vendor_id = 'VD.00.01.211'
  json.unit_id = '00.01.133.H26'
  json.sensor_id = 'ad2bd838f1977b46636b81c9'
  json.category = logObject[category + 1]
  json.action = logObject[action + 1]
  json.signature = logObject[signature + 1]
  json.dest_ip = logObject[dest_ip + 1]
  json.dest_port = d[dpt_index + 2].split(' ')[0]
  json.src_ip = logObject[src_ip + 1]
  json.src_port = d[spt_index + 2].split(' ')[0]
  json.proto = logObject[proto + 1]
  json.severity = logObject[severity + 1]
  json.direction = logObject[direction + 1]
  json.domain = logObject[domain + 1]
  json.host = logObject[host + 1]
  json.tags = tags
  json.geoip = {
    region_name: logObject[region_name + 1],
    timezone: logObject[timezone + 1],
    city_name: logObject[city_name + 1],
    lat: logObject[lat + 1],
    country_name: logObject[country_name + 1],
    lon: logObject[lon + 1],
    ip: logObject[ip + 1],
  }

  res.send(json)
})

app.listen(8000, () => {
  console.log('Example app listening on port 8000!')
});