var time=0;

$(document).ready(function () {
	$(".section").hide(time);
	$("#intro").show(time);
});

$(".a").click(function(e){
	$(".section").hide(time);
	var clicked_element_id = this.href.split("#")[1];
	$("#"+clicked_element_id).show(time);
	// window.location=this.href;
    $(document).scrollTop(200); 
    console.log("scrollTop");
});