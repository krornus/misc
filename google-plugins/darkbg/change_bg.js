var bodystyle=null

document.onkeypress = function (e){
    var e=window.event || e;

    if (e.ctrlKey && e.keyCode == 26)
    {
        restore();
    }
    else if (e.ctrlKey && e.keyCode == 9)
    {
        invert_nice();
    }
    else if (e.ctrlKey && e.shiftKey && e.keyCode)
    {
        invert_force();
    }
}

function restore() {
    if(bodystyle!=null) {
        document.body.style = bodystyle;
    }

    var sheets = document.styleSheets;
    var sheet = document.styleSheets[0];

    sheet.removeRule(1);
}

function invert_nice() {
    if(bodystyle==null) {
        bodystyle = document.body.style;
    }

    var sheets = document.styleSheets;
    var sheet = document.styleSheets[0];

    sheet.insertRule("img { filter: invert(.95) !important; }", 1);
    sheet.insertRule("svg { filter: invert(.95) !important; }", 1);

    sheet.insertRule("body { filter: invert(.95); }", 1);

    document.body.style.backgroundColor = "#222";
}

function invert_force() {
    if(bodystyle==null) {
        bodystyle = document.body.style;
    }

    document.body.style.filter = "invert(.95)";
    document.body.style.backgroundColor = "#222";
}
