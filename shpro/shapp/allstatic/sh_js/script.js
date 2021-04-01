$(document).ready(function(){
    $('#mycarousel').carousel({interval: 3000});
});

$("#loginModal").modal("hide");
    $('#loginbutton').click(function(){
        $("#loginModal").modal("show");
    });

$("#signupModal").modal("hide");
    $('#signupbutton').click(function(){
        $("#signupModal").modal("show");
    });
    
$(document).ready(function(){
    $('#bookcarousel').carousel({interval: 3000});
});

$(document).ready(function(){
    $('#bookcarousel1').carousel({interval: 3000});
});