<?php

    class Kagi
    {
        // Creates a random alphanumreic string of the desired length.
        static function random_str( $length, $keyspace = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ' )
        {
            $pieces = [];
            $max = mb_strlen( $keyspace, '8bit' ) - 1;
            for( $i = 0; $i < $length; ++$i ){ $pieces []= $keyspace[ random_int( 0, $max )]; }
            return implode( '', $pieces );
        }

        // Produces the challenge string to give to the client to sign (along with whatever data the client wants to add).
        public static function challenge( $publickey, $secret )
        {
            $randomString = Kagi::random_str( 128 );
            $timestamp    = time();

            return $time . "_" . $randomString . "_" . hash( "sha256", $timestamp . $randomString . $publickey . $secret );
        }

        // Takes the login information and determines if the challenge data has been correctly signed by the private key, was produced by this server for the specified public key and is not expired.
        public static function verify( $publickeyLogin, $secret, $expirySeconds = 30 )
        {
            // Extract parts out of the login structure.
            $publickey = $publickeyLogin['publickey'];
            $prefix    = $publickeyLogin['prefix'];
            $challenge = $publickeyLogin['challenge'];
            $signature = $publickeyLogin['signature'];

            // Extract the parts out of the challenge.
            $parts = explode( '_', $challenge );
            $timestamp      = $parts[0];
            $randomString   = $parts[1];
            $challengehHash = $parts[2];

            // Ensure that this challenge is recent enough. Generated challenges expire after 30 seconds.
            if( $timestamp > strtotime( "-" . $expirySeconds . " seconds" ) )
            {
                // Ensure that the hash in the challenge matches the one that only the server can generate using the timestamp, publickey, the given random data and a secret only the server knows.
                if( $challengehHash == hash( "sha256", $timestamp . $randomString . $publickey . $secret ) )
                {
                    // Construct the full challenge string which includes the prefix that the client generated and the challenge that the server created.
                    $fullChallenge = $prefix . "_" . $challenge;

                    // Format the public key in a way that OpenSSL likes
                    $formattedPublicKey = "-----BEGIN PUBLIC KEY-----\n" . wordwrap( $publickey, 64, "\n", TRUE ) . "\n-----END PUBLIC KEY-----";

                    // Verify that the privatekey for the given publickey created the given signature for the fullChallenge.
                    if( openssl_verify( $fullChallenge, base64_decode( $signature ), $formattedPublicKey, OPENSSL_ALGO_SHA512 ) )
                    {
                        return true;
                    }
                    else{ return "publickey signature failed to check out"; }
                }
                else{ return "publickey challenge hash does not check out"; }
            }
            else{ return "publickey challenge too old"; }
        }
    }

?>
