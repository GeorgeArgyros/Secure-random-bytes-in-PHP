<?php
/**
 * Demo of usage secyre_random_bytes() function
 *  
 */
require_once 'srand.php';

$c1 =  microtime(true);
if (isset($_GET['l'])) {
   $t = secure_random_bytes($_GET['l']);
} else {
   $t = secure_random_bytes();
}
$c2 = microtime(true);
    
echo "Token: $t<br>Execution time: " . (int)(($c2-$c1)*1000000);
