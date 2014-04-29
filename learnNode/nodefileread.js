var fs = require('fs');
var jf = require('jsonfile')


fs.readFile('Book2.csv',{encoding: 'utf8'}, function (err, data) {
  if (err) throw err;
  //console.log(data);
});
var jsonObject=[];





var Lazy = require('lazy'),

lazy = new Lazy(fs.createReadStream('tcpdump1.csv'))
    .lines
    .map(String)
    .map(function(lineData){
     	var fields = lineData.trim().split(',', 7);
     	var jsoninput = {
     		DateTime: fields[0],
     		SourceIP: fields[1],
     		SourcePort: fields[2],
     		DestIP: fields[3],
            DestPort: fields[4],
            DestProtocol: fields[5],
            Length: fields[6]
     	};
     	
     	jsonObject.push(jsoninput);
     	console.log(jsonObject);
     	var file = 'data.json';
		jf.writeFile(file, { data : jsonObject }, function(err) {
  
		})

     })
 




 //console.log(jsonObject);
