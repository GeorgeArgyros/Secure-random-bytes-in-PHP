<?php
namespace SrandTest;

require_once '../srand.php';

class SrandTest extends \PHPUnit_Framework_TestCase
{
    
    public function testRandBytes()
    {
        for ($length = 1; $length < 4096; $length++) {
            $rand = secure_random_bytes($length);
            $this->assertTrue($rand !== false);
            $this->assertEquals($length, strlen($rand));
        }
    }
    
}

