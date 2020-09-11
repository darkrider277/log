const express = require('express')
const app = express();
var axios = require('axios')
var bodyParser = require('body-parser');

app.use(bodyParser.json());       // to support JSON-encoded bodies
app.use(bodyParser.urlencoded({ // to support URL-encoded bodies
  extended: false,
}));

app.listen(4000, () => {
  console.log('Example app listening on port 8000!')
});

app.post('/log',(req, res) => {
  var raw = req.body.log
  var b = raw.split('|')
  var c = b[b.length - 1]
  var d = c.split('=')

  //handle severity
  var exSlice = b.slice(0, b.length - 1)
  var severity = 0
  exSlice.map(ele => {
    switch (ele) {
      case "Low":
        severity = 1;
        break;

      case "Medium":
        severity = 2;
        break;

      case "High":
        severity = 3;
        break;

      case "Critical":
        severity = 4;
        break;

      default:
        break;
    }
  })

  //handling into object, maybe missing some fields
  var logObject = []
  d.map(i => {
    var arr = i.split(' ')
    logObject.push(arr[0])
    logObject.push(arr[1])
  })
  //handling missing fields of logObject
  var dpt_index = d.findIndex(ele => ele.includes(" dpt"))
  var spt_index = d.findIndex(ele => ele.includes(" spt"))
  var dtz_index = d.findIndex(ele => ele.includes("dtz"))

  //handling fields available in logObject
  var timestamp = logObject.findIndex(ele => ele == "rt")
  // var category = logObject.findIndex(ele => ele == "cs4")
  var action = logObject.findIndex(ele => ele == "act")
  var signature = logObject.findIndex(ele => ele == "categorySignificance")
  var dest_ip = logObject.findIndex(ele => ele == "dst")
  var src_ip = logObject.findIndex(ele => ele == "src")
  var proto = logObject.findIndex(ele => ele == "proto")
  var direction = logObject.findIndex(ele => ele == "deviceDirection")
  var domain = logObject.findIndex(ele => ele == "domain")
  var host = logObject.findIndex(ele => ele == "customize")
  var lat = logObject.findIndex(ele => ele == "dlat")
  var lon = logObject.findIndex(ele => ele == "dlong")
  var ip = logObject.findIndex(ele => ele == "dvc")

  /*var indexCate = logObject[category - 1].split('-')[0]
  switch (indexCate) {
    case 'IA':
      category = 1;
      break;

    case 'E':
      category = 2;
      break;

    case 'P':
      category = 3;
      break;

    case 'PE':
      category = 4;
      break;

    case 'DE':
      category = 5;
      break;

    case 'CA':
      category = 6;
      break;

    case 'D':
      category = 7;
      break;

    case 'LM':
      category = 8;
      break;

    case 'C':
      category = 9;
      break;

    case 'CC':
      category = 10;
      break;

    case 'I':
      category = 12;
      break;

    default:
      category = 11;
      break;
  }*/

  //handling tags and geoip
  var tags = 1
  if (
    dtz_index < 0
    && ip < 0
    && lon < 0
    && logObject[lat + 1] == 0
    && lat < 0
    && logObject[lon + 1] == 0) {
    tags = 0
  }

  //handling action
  var jsonAction = 0;
  switch (logObject[action + 1]) {
    case "accept" || "allow":
      jsonAction = 1;
      break;

    case "drop" || "deny":
      jsonAction = 2;
      break;

    case "alert":
      jsonAction = 3;
      break;

    case "suspend":
      jsonAction = 4;
      break;

    case "archive":
      jsonAction = 5;
      break;

    default:
      jsonAction = 6;
      break;
  }


  //handling json server return object 
  var json = {}
  json.timestamp = Number(logObject[timestamp + 1] + ".3590641")
  json.vendor_id = 'MISOFT_01'
  json.unit_id = 'MISOFT_01'
  json.sensor_id = '5f50a0255f627d06738587ee'
  json.category = 1
  json.action = jsonAction
  json.signature = logObject[signature + 1]
  json.severity = Number(severity)
  json.direction = Number(logObject[direction + 1])
  json.dest_ip = logObject[dest_ip + 1]
  json.dest_port = Number(d[dpt_index + 1].split(' ')[0]) > 0 || Number(d[dpt_index + 1].split(' ')[0]) ? Number(d[dpt_index + 1].split(' ')[0]) : 6969
  json.src_ip = logObject[src_ip + 1]
  json.src_port = Number(d[spt_index + 1].split(' ')[0]) > 0 || Number(d[spt_index + 1].split(' ')[0]) ? Number(d[spt_index + 1].split(' ')[0]) : 53
  json.proto = logObject[proto + 1]
  json.domain = logObject[domain + 1]
  json.host = "CYQPTL"
  json.tags = tags
  if (tags == 1) {
    json.geoip = {
      region_name: d[dtz_index + 1].split(' ')[0],
      timezone: d[dtz_index + 1].split(' ')[0],
      city_name: d[dtz_index + 1].split(' ')[0],
      lat: Number(logObject[lat + 1]) > 0 ? Number(logObject[lat + 1]) : 0.1,
      country_name: d[dtz_index + 1].split(' ')[0],
      lon: Number(logObject[lon + 1]) > 0 ? Number(logObject[lon + 1]) : 0.1,
      ip: logObject[ip + 1],
    }
  }

  var statusRespone = ""

  var a = axios.put(
    "https://api.soc.gov.vn/api/v1/alerts",
    json,
    { headers: { "Authorization": "Basic JVWYM92QXPVBGHPP", "Content-Type": "application/json" } }
  )
    .then(r => {
      statusRespone = r.data
      console.log(json)
	  res.send(statusRespone)
    })
    .catch(e => {
      statusRespone = e
      console.log(json)
	  res.send(e)
    })

})