const express = require('express')
const app = express();
var axios = require('axios')
var bodyParser = require('body-parser');
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';

app.use(bodyParser.urlencoded({ // to support URL-encoded bodies
  extended: true
}));
app.use(bodyParser.text());

app.listen(4000, () => {
  console.log('Example app listening on port 4000!')
});

app.post('/',(req, res) => {
  console.log(req.body)
  var raw = req.body
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
  var category1 = logObject.findIndex(ele => ele == "cs6")
  var action = logObject.findIndex(ele => ele == "act")
  //var signature = logObject.findIndex(ele => ele == "fname")
  var dest_ip = logObject.findIndex(ele => ele == "dst")
  var src_ip = logObject.findIndex(ele => ele == "src")
  var proto = logObject.findIndex(ele => ele == "proto")
  var direction = logObject.findIndex(ele => ele == "deviceDirection")
  var domain = logObject.findIndex(ele => ele == "domain")
  var host = logObject.findIndex(ele => ele == "customize")
  var lat = logObject.findIndex(ele => ele == "dlat")
  var lon = logObject.findIndex(ele => ele == "dlong")
  var ip = logObject.findIndex(ele => ele == "dvc")
  
  var signature_index = d.findIndex(ele => ele.includes(" fname"))
  var sign = d[signature_index + 1].split(' ')
  sign!==null&&sign!==undefined&&sign.pop()


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
  var category_raw = logObject[category1+1]
  var category = 1
	if (category_raw.match(/T1078|T1091|T1189|T1190|T1192|T1193|T1200/))
	{
	category = 1;
	}
	if (category_raw.match(/T1028|T1035|T1047|T1053|T1059|T1061|T1064|T1072|T1085|T1086|T1117|T1118|T1121|T1127|T1129|T1151|T1168|T1170|T1173|T1175|T1191|T1196|T1203|T1204|T1216|T1218|T1220|T1223/))
	{
	category = 2;
	}
	if (category_raw.match(/T1031|T1034|T1038|T1050|T1053|T1060|T1078|T1098|T1136|T1168|T1179|T1183|T1215/))
	{
	category = 3;
	}
	if (category_raw.match(/T1055|T1068|T1088/))
	{
	category = 4;
	}
	if (category_raw.match(/T1036|T1045|T1064|T1089|T1090|T1093|T1107|T1112|T1127|T1140/))
	{
	category = 5;
	}
	if (category_raw.match(/T1003|T1040|T1110|T1503/))
	{
	category = 6;
	}
	if (category_raw.match(/T1012|T1016|T1018|T1046|T1057|T1063|T1083|T1087|T1201|T1518/))
	{
	category = 7;
	}
	if (category_raw.match(/T1075|T1076|T1077|T1091|T1210/))
	{
	category = 8;
	}
	if (category_raw.match(/T1039|T1056|T1113|T1114|T1115/))
	{
	category = 9;
	}
	if (category_raw.match(/T1002|T1048|T1052/))
	{
	category = 10;
	}
	if (category_raw.match(/T1132|T1188|T1483/))
	{
	category = 11;
	}
	if (category_raw.match(/T1486|T1489|T1490|T1498/))
	{
	category = 12;
	}


  //handling json server return object 
  var json = {}
  json.timestamp = Number(logObject[timestamp + 1] + ".3590641")
  json.vendor_id = 'MISOFT_01'
  json.unit_id = 'MISOFT_01'
  json.sensor_id = '5f50a0255f627d06738587ee'
  json.category = 1
  json.action = jsonAction
  json.signature = sign===""?sign:sign.join(" ")
  json.severity = Number(severity)
  json.direction = Number(logObject[direction + 1])
  json.dest_ip = logObject[dest_ip + 1]
  json.dest_port = Number(d[dpt_index + 1].split(' ')[0]) > 0 || Number(d[dpt_index + 1].split(' ')[0]) ? Number(d[dpt_index + 1].split(' ')[0]) : 1
  json.src_ip = logObject[src_ip + 1]
  json.src_port = Number(d[spt_index + 1].split(' ')[0]) > 0 || Number(d[spt_index + 1].split(' ')[0]) ? Number(d[spt_index + 1].split(' ')[0]) : 1
  json.proto = logObject[proto + 1]!==""?logObject[proto + 1]:"UNDEFINED"
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
      console.log(statusRespone)
	  res.send(statusRespone)
    })
    .catch(e => {
      statusRespone = e
      console.log(json)
	  console.log(e)
	  res.send(e)
    })
})