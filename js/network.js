List = [];

//Datatable and Detail table div
var main_area_id;

var show_buttons = function() {
    console.log("In show buttons");
    change_button_visibility("inline-block");
    $('.dropdown-toggle').dropdown();
    
}



var view_graph = function() {
    console.log("In scan function");
    var main = document.getElementById('rm-for-graph');
    console.log("main",main);
    main_area_id = document.getElementById('main_area');
    if( main_area_id != null)
    main.removeChild(main_area_id);
    var title = document.getElementById('section_title');
    title.innerHTML = "Graph Visualization";

    show_buttons();
}

function change_button_visibility(value)
{
    var div = document.getElementById('show_buttons');
    var divs = div.getElementsByTagName('div');
    for( var i =0 ; i < divs.length ; i++)
        divs[i].style.display = value;
}

var display_tables = function() {
    change_button_visibility("none");
    var main = document.getElementById('rm-for-graph');
    main.appendChild(main_area_id);

}
/*
var table = document.getElementById("example");
table.addEventListener('click',function (){
    console.log("clicked");
})
*/

// var tbody = document.getElementById("tbody");
// tbody.addEventListener('click',function (){
//     console.log("clicked tbody");
// })

var oTable;

var progress = setInterval(function () {
    var $bar = $('.bar');

    if ($bar.width() >= 400) {
        clearInterval(progress);
        $('.progress').removeClass('active');
    } else {
        $bar.width($bar.width() + 80);
    }
    $bar.text($bar.width() / 4 + "%");

}, 800);


function hex2a(hexx) {
    var hex = hexx.toString();//force conversion
    var str = '';
    for (var i = 0; i < hex.length; i += 2)
        str += String.fromCharCode(parseInt(hex.substr(i, 2), 16));
    return str;
}


var createTable = function (fullData, callback){
    var request = $.getJSON('event_log.json', function(data) {
            $.each(data, function(index, value) {
                  fullData[index] = [];
                  fullData[index] = value;
                  List[index] = [];
                  List[index].push(index+1);
                  List[index].push(value.sig_priority);
                  var myDate = new Date(value.timestamp);
                  myDate = moment(myDate).format('YYYY-MM-DD HH:mm:ss');
                  List[index].push(myDate);
                  List[index].push(numToDot(value.ip_src));
                  List[index].push(FindPortTypes(value,true));
                  List[index].push(numToDot(value.ip_dst));
                  List[index].push(FindPortTypes(value,false));
                  List[index].push(value.sig_name);

                });
         oTable = $('#example').dataTable( {
            "sDom": "<'row'<'span8'l><'span8'f>r>t<'row'<'span8'i><'span8'p>>",
            "aaData": List,
            "aoColumns": [
                            { "sTitle": "Id" },
                            { "sTitle": "Pri"},
                            { "sTitle": "Data/Time" },
                            { "sTitle": "Src IP" },
                            { "sTitle": "SPort"},
                            { "sTitle": "Dst IP" },
                            { "sTitle": "DPort"},
                            { "sTitle": "Event Message"},
                        ]
                    }); 

         $("#example tbody").on('click','tr',function(event) {
                 packetLog = oTable.fnGetData(this);
                 var fullLog = fullData[packetLog[0]];
                 console.log("In click event");
                 document.getElementById('src_ip').innerHTML = packetLog[3];
                 document.getElementById('dst_ip').innerHTML = packetLog[5];
                 document.getElementById('ip_ver').innerHTML = fullLog.ip_ver;
                 document.getElementById('ip_ver').innerHTML = fullLog.ip_ver;
                 document.getElementById('ip_hl').innerHTML = fullLog.ip_hlen;
                 document.getElementById('ip_tos').innerHTML = fullLog.ip_tos;
                 document.getElementById('ip_tos').innerHTML = fullLog.ip_tos;
                 document.getElementById('ip_len').innerHTML = fullLog.ip_tos;
                 document.getElementById('ip_id').innerHTML = fullLog.ip_id;
                 document.getElementById('ip_flags').innerHTML = fullLog.ip_flags;

                 document.getElementById('ip_off').innerHTML = fullLog.ip_off;
                 document.getElementById('ip_ttl').innerHTML = fullLog.ip_ttl;
                 document.getElementById('ip_csum').innerHTML = fullLog.ip_csum;
                 if( fullLog.ip_proto == 1) {
                 //ICMP

                 }
                 else if( fullLog.ip_proto == 6) {
                 //Currently just show for TCP
                    document.getElementById('tcp_sport').innerHTML = fullLog.tcp_sport;
                    document.getElementById('tcp_dport').innerHTML = fullLog.tcp_dport;
                    document.getElementById('tcp_seq').innerHTML = fullLog.tcp_seq;
                    document.getElementById('tcp_ackn').innerHTML = fullLog.tcp_ack;
                    document.getElementById('tcp_off').innerHTML = fullLog.tcp_off;
                    document.getElementById('tcp_res').innerHTML = fullLog.tcp_res;
                    document.getElementById('tcp_win').innerHTML = fullLog.tcp_win;
                    document.getElementById('tcp_urp').innerHTML = fullLog.tcp_urp;
                    document.getElementById('tcp_csum').innerHTML = fullLog.tcp_csum;
                    if(fullLog.data_payload != null) {
                        document.getElementById('packet_data').innerHTML = fullLog.data_payload;
                        document.getElementById('ascii_data').innerHTML = hex2a(fullLog.data_payload);

                    }

                    var flags = parseInt(fullLog.tcp_flags);
                    console.log("flags in dec: " + flags);
                    console.log("flags in log: " + fullLog.tcp_flags);
                    var shifter_iterator = 0;
                    var mask = 1;
                    var tag = { 0:'tcp_fin',1:'tcp_syn',2:'tcp_rst',3:'tcp_psh',4:'tcp_ack',5:'tcp_urg',6:'tcp_r0',7:'tcp_r1'};
                    while( shifter_iterator < 8) {
                        if(flags & (mask << shifter_iterator)) 
                        document.getElementById(tag[shifter_iterator]).innerHTML = 1;
                        else
                        document.getElementById(tag[shifter_iterator]).innerHTML = 0;
                        shifter_iterator++;


                    }

                     
                 }
                 else if( fullLog.ip_proto == 17) {
                 //UDP
                 }


         });

    });

    request.done(function(){
        console.log("After Callback");
        //console.log("list",List);
        window.List = List;
        callback(List);
        // put this into local storage for use in other functions and charts
        // refresh everytime scan occurs
    });

    // getDetails();

}

function storeData (){
    var List=[];
    $.getJSON('event_log.json', function(data) {
            $.each(data, function(index, value) {
                  List[index] = [];
                  List[index].push(index+1);
                  List[index].push(value.sig_priority);
                  var myDate = new Date(value.timestamp);
                  myDate = moment(myDate).format('YYYY-MM-DD HH:mm:ss');
                  List[index].push(myDate);
                  List[index].push(numToDot(value.ip_src));
                  List[index].push(FindPortTypes(value,true));
                  List[index].push(numToDot(value.ip_dst));
                  List[index].push(FindPortTypes(value,false));
                  List[index].push(value.sig_name);

            });
            return data;
    });
}

function draw_graph(graphType) {
    var timestamp = [];
    var element = [];
    for( var i = 0; i < List.length; i++) {
         timestamp = List[i].filter(function(val) {
          console.log(val);
          //element = val.split(" ");
        });
         console.log(timestamp[0]);
    }
    document.getElementById("high_chart").style.display = "block";
     $('#high_chart').highcharts({
        chart: {
            type: 'bar',
            position: 'right',
            marginleft:200
        },
        title: {
            text: 'Fruit Consumption'
        },
        xAxis: {
            categories: ['Apples', 'Bananas', 'Oranges']
        },
        yAxis: {
            title: {
                text: 'Fruit eaten'
            }
        },
        series: [{
            name: 'Jane',
            data: [1, 0, 4]},
        {
            name: 'John',
            data: [5, 20, 3]}]
    });
}
 


var getDetails = function(id){

    console.log("list",List);
}
