<?php

/*
 * The function is providing, at least at the systems tested :), 
 * $len bytes of entropy under any PHP installation or operating system.
 * The execution time should be at most 10-20 ms in any system.
 */
function secure_random_bytes($len = 10)
{  
 
   /*
    * Our primary choice for a cryptographic strong randomness function is
    * openssl_random_pseudo_bytes. 
    */
   $SSLstr = '4'; // http://xkcd.com/221/
   if (function_exists('openssl_random_pseudo_bytes') && 
       (version_compare(PHP_VERSION, '5.3.4') >= 0 || 
	substr(PHP_OS, 0, 3) !== 'WIN'))
   {
      $SSLstr = openssl_random_pseudo_bytes($len, $strong);
      if ($strong)
         return $SSLstr;
   }

   /*
    * If mcrypt extension is available then we use it to gather entropy from 
    * the operating system's PRNG. This is better than reading /dev/urandom 
    * directly since it avoids reading larger blocks of data than needed. 
    * Older versions of mcrypt_create_iv may be broken or take too much time 
    * to finish so we only use this function with PHP 5.3 and above.
    */
   if (function_exists('mcrypt_create_iv') && 
      (version_compare(PHP_VERSION, '5.3.0') >= 0 || 
       substr(PHP_OS, 0, 3) !== 'WIN')) 
   {
      $str = mcrypt_create_iv($len, MCRYPT_DEV_URANDOM);
      if ($str !== false)
         return $str;	
   }


   /*
    * No build-in crypto randomness function found. We collect any entropy 
    * available in the PHP core PRNGs along with some filesystem info and memory
    * stats. To make this data cryptographically strong we add data either from 
    * /dev/urandom or if its unavailable, we gather entropy by measuring the 
    * time needed to compute a number of SHA-1 hashes. 
    */
   $str = '';
   $bits_per_round = 2; // bits of entropy collected in each clock drift round
   $msec_per_round = 400; // expected running time of each round in microseconds
   $hash_len = 20; // SHA-1 Hash length
   $total = $len; // total bytes of entropy to collect

   $handle = @fopen('/dev/urandom', 'rb');   
   if ($handle && function_exists('stream_set_read_buffer'))
      @stream_set_read_buffer($handle, 0);

   do
   {
      $bytes = ($total > $hash_len)? $hash_len : $total;
      $total -= $bytes;

      //collect any entropy available from the PHP system and filesystem
      $entropy = rand() . uniqid(mt_rand(), true) . $SSLstr;
      $entropy .= implode('', @fstat(@fopen( __FILE__, 'r')));
      $entropy .= memory_get_usage();
      if ($handle) 
      {
         $entropy .= @fread($handle, $bytes);
      }
      else
      {	           	
         // Measure the time that the operations will take on average
         for ($i = 0; $i < 3; $i ++) 
         {
            $c1 = microtime(true);
            $var = sha1(mt_rand());
            for ($j = 0; $j < 50; $j++)
            {
               $var = sha1($var);
            }
            $c2 = microtime(true);
    	    $entropy .= $c1 . $c2;
         }

         // Based on the above measurement determine the total rounds
         // in order to bound the total running time.	
         $rounds = (int)($msec_per_round*50 / (int)(($c2-$c1)*1000000));

         // Take the additional measurements. On average we can expect
         // at least $bits_per_round bits of entropy from each measurement.
         $iter = $bytes*(int)(ceil(8 / $bits_per_round));
         for ($i = 0; $i < $iter; $i ++)
         {
            $c1 = microtime();
            $var = sha1(mt_rand());
            for ($j = 0; $j < $rounds; $j++)
            {
               $var = sha1($var);
            }
            $c2 = microtime();
            $entropy .= $c1 . $c2;
         }
            
      } 
      // We assume sha1 is a deterministic extractor for the $entropy variable.
      $str .= sha1($entropy, true);
   } while ($len > strlen($str));
   
   if ($handle) 
      @fclose($handle);
   
   return substr($str, 0, $len);
}


$c1 =  microtime(true);
if (isset($_GET['l']))
   $t = secure_random_bytes($_GET['l']);
else
   $t = secure_random_bytes();
$c2 = microtime(true);
    
echo "Token: $t<br>Execution time: " . (int)(($c2-$c1)*1000000);
?>

