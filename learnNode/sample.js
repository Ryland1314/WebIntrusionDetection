/*
var Converter=require('csvtojson').core.Converter;
var csvConverter=new Converter(false); 

// The parameter false will turn off final result construction. It can avoid huge memory consumption while parsing. The trade off is final result will not be populated to end_parsed event.

var readStream=require("fs").createReadStream("Book2.csv"); 

var writeStream=require("fs").createWriteStream("outpuData.json");

var started=false;
csvConverter.on("record_parsed",function(rowJSON){
   if (started){
      writeStream.write(",\n");
   }
   writeStream.write(JSON.stringify(rowJSON));  //write parsed JSON object one by one.
   if (started==false){
      started=true;
   }
});

writeStream.write("[\n"); //write array symbol

csvConverter.on("end_parsed",function(){
   writeStream.write("\n]"); //end array symbol
});

csvConverter.from(readStream);
*/
var fs = require('fs');
var jf = require('jsonfile')


fs.readFile('./Book2.csv',{encoding: 'utf8'}, function (err, data) {
  if (err) throw err;
  //console.log(data);
});
var jsonObject=[];

var Lazy = require('lazy'),

lazy = new Lazy(fs.createReadStream('Books2.csv'))
    .lines
    .map(String)
    .map(function(lineData){
     	var fields = lineData.trim().split(',', 4);
     	var jsoninput = {
     		col1: fields[0],
     		col2: fields[1],
     		col3: fields[2],
     		col4: fields[3]
     	};
     	
     	jsonObject.push(jsoninput);
     	console.log(jsonObject);
     	var file = './data.json';
		jf.writeFile(file, { data : jsonObject }, function(err) {
  
		})

     })
 
