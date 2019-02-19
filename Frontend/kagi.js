(function(){

    var K = { port: 18797, publickeys: [] };

    // Makes API calls with the native app running on the same machine with access to the keys.
    function APICall( call, args, completion )
    {
        call = "http://localhost:" + K.port + call;

        var sendString = "";

        if( typeof args != "undefined" )
        {
                 if( typeof args == 'function' ){ completion = args;                                               }
            else if( typeof args ==   'string' ){ if( sendString != "" ){ sendString += "&"; } sendString += args; }
            else if( typeof args ==   'object' )
            {
                var argString = '';

                for( var key in args )
                {
                    var value = args[key];

                         if( typeof value == 'object' ){ if( argString != "" ){ argString += "&"; } argString += key + "=" + encodeURIComponent(JSON.stringify(value)); }
                    else if(            value == null ){ if( argString != "" ){ argString += "&"; } argString += key;                                                   }
                                                   else{ if( argString != "" ){ argString += "&"; } argString += key + "=" + encodeURIComponent(value);                 }
                }

                sendString += argString;
            }
        }

        if( sendString != "" ){ call = call + "?" + sendString; }

        var xhrCall; if( window.XMLHttpRequest ){ xhrCall = new XMLHttpRequest(); }else{ xhrCall = new ActiveXObject("Microsoft.XMLHTTP"); }
        xhrCall.open( "GET", call, true );

        xhrCall.onreadystatechange = function()
        {
            if( xhrCall.readyState == 4 ){ if( completion ){ completion( xhrCall ); } }
        }

        xhrCall.send();
    }

    // Asks the app for a list of available keys to use for authentication.
    K.list = function( callback )
    {
        APICall( "/list", function( result )
        {
            if( result.status == 200 ){ K.publickeys = JSON.parse( result.response ); }

            if( typeof callback != "undefined" ){ callback( K.publickeys ); }
        } );
    };

    // Asks the app to use the private key for the given public key to sign the given challenge.
    K.sign = function( publickey, challenge, callback )
    {
        // If we don't know about any public keys, ask the server for them.
        if( !Object.keys( K.publickeys ).length )
        {
            K.list( function( publickeys )
            {
                if( Object.keys( publickeys ).length ){ K.sign( publickey, challenge, callback ); }
            } );
        }
        else
        {
            // If given the name of the publickey, use that to look up the actual publickey.
            if( K.publickeys[ publickey ] ){ publickey = K.publickeys[ publickey ]; }

            APICall( "/sign", { 'publickey': publickey, 'challenge': challenge }, function( result )
            {
                if( result.status == 200 )
                {
                    if( typeof callback != "undefined" ){ callback( JSON.parse( result.response ) ); }
                }
            } );
        }
    };

    if( typeof window.Kagi == 'undefined' ){ window.Kagi = K; }

    return K;

}());
