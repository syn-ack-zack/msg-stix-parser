//This function initializes the editable attributes for the asset template. Allows for inplace editing of the asset attributes.
//Each update to a field will perform an AJAX call to /parser/update to update that field in the respective asset ID. 
//The AJAX request contains the following data. {'pk':'','value':'','name':''}
$(function(){

    $('#CuckooModal').on('show.bs.modal', function(e) {
        var $modal = $(this),
            fileName = e.relatedTarget.id;
        $modal.find('.modal-body').html("Would you like to send <strong>" + fileName + "</strong> to Cuckoo for analysis?");    
        $modal.find('.modal-title').attr('id',fileName);

        $('#cuckoobutton').click(function(){
        console.log(fileName)
        $.post( "/cuckoo", { name: fileName })
            .done(function( data ) {
                data = JSON.parse(data);
                url = "https://cuckoo.cardinalhealth.net/analysis/"+data.id;
                $('#CuckooModal').modal('hide');
                $('#CuckooCompleteModal').modal('show');
                $('#CuckooCompleteModal').find('.modal-body').html('View analysis in Cuckoo <a href="'+url+'"> here </a>');
                
            });
        });
    });

    $('#sender').editable();
    $('#subject').editable();
    $('#from_address').editable();
    $('#x_mailer').editable();
    $('#to').editable();
    $('#x_originating_ip').editable();
    $('#date').editable();
    $('#to').editable({
        type: 'textarea'
    });
    $('#reply_to').editable();
    $('#helo').editable();
    $('#message_id').editable();
    $('#subject').editable();
    $('#tlp').editable({
        type: 'select',
        title: 'Mark TLP Color',
        placement: 'right',
        value: 1,
        source: [
            {value: 1, text: 'GREEN'},
            {value: 2, text: 'AMBER'},
            {value: 3, text: 'RED'},

        ],
        url: '/parser/update'
    });

    //index used to create numbered modal ID's. 
    var i = 0;
    update_search_table(i);

});


//This function initializes the DataTable, sets the data population to be obtained by AJAX using the /fetch route. 
function update_search_table(i){


    $('#result-table tfoot th').each( function () {
            var title = $(this).text();
            $(this).html('<input type="text" placeholder="Search '+title+'" />');
        } );


    var result_table = $('#result-table').DataTable({
        scrollY: '50vh',
        scrollX: '50vh',
        scrollCollapse: true,
        autoWidth: false,
        paging: true,
        "ajax": {
            "url":"/fetch",
            "type":"POST",
            "data":function(){
                return {search:$('meta[name=query]').attr("content")}
            }
        },
        columnDefs: [
                {
                    targets:[0,1,2,3],
                    render: function(data,type,row,meta){
                        //increment modal counter, this will allow each button in cell to relate to it's own modal instance
                        i += 1;

                        if (type==='display'){
                            if(meta.col == 3){
                                data = "MD5 File Hash: " + '<a href="/download?hash=' + encodeURIComponent(data) + '">' + data + '</a>';
                            }
                            else if(meta.col == 0){
                                $('#modal-container').append('<div class="modal fade" id="dataTableHeader' + i + '" tabindex="-1" role="dialog" aria-labelledby="myModalLabel"><div class="modal-dialog" role="document"><div class="modal-content"><div class="modal-header"><button type="button" class="close" data-dismiss="modal" aria-label="Close"><span aria-hidden="true">&times;</span></button><h4 class="modal-title" id="myModalLabel">Raw Header</h4></div><div class="modal-body"><pre style="text-align:left">' + data + '</pre></div><div class="modal-footer"><button type="button" class="btn btn-default" data-dismiss="modal">Close</button></div></div></div></div>')
                                data = '<button type="button" class="btn btn-primary" data-toggle="modal" data-target="#dataTableHeader' + i + '">View Raw Header</button>';
                            }
                            else if(meta.col == 1){
                                $('#modal-container').append('<div class="modal fade" id="dataTableBody' + i + '" tabindex="-1" role="dialog" aria-labelledby="myModalLabel"><div class="modal-dialog" role="document"><div class="modal-content"><div class="modal-header"><button type="button" class="close" data-dismiss="modal" aria-label="Close"><span aria-hidden="true">&times;</span></button><h4 class="modal-title" id="myModalLabel">Raw Header</h4></div><div class="modal-body"><pre style="text-align:left">' + data + '</pre></div><div class="modal-footer"><button type="button" class="btn btn-default" data-dismiss="modal">Close</button></div></div></div></div>')
                                data = '<button type="button" class="btn btn-primary" data-toggle="modal" data-target="#dataTableBody' + i + '">View Raw Body</button>';
                            }
                        }

                        return data;
                    }
                }
        ]
    });

    // Apply the search
    result_table.columns().every( function () {
        var that = this;
        $( 'input', this.footer() ).on( 'keyup change', function () {
            if ( that.search() !== this.value ) {
                    that.search( this.value ).draw();
                }
        });
    });
}







