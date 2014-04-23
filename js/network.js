var List = [];

var scan_function = function() {
    console.log("In scan function");
    var main = document.getElementById('main_area');
    console.log("main",main);
    var example = document.getElementById('example_wrapper');
    if( example != null)
    main.removeChild(example);

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

         $("#example tbody tr").on("click",function(event) {
                 packetLog = oTable.fnGetData(this);
                 console.log("In click event");
                 var tableid = document.getElementById('detail_table');
                 console.log(tableid.rows);
            });

    });

    request.done(function(){
        console.log("After Callback");
        console.log("list",List);
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


var getDetails = function(id){

    console.log("list",List);
}
