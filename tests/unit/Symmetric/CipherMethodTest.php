<?php
/**
 * Sikker is a PHP 7.0+ Security package that contains security related implementations.
 *
 * @package    NorseBlue\Sikker
 * @version    0.2
 * @author     NorseBlue
 * @license    MIT License
 * @copyright  2016 NorseBlue
 * @link       https://github.com/NorseBlue/Sikker
 */
declare(strict_types = 1);

namespace NorseBlue\Sikker\Tests\Symmetric;

use Codeception\Specify;
use Codeception\Test\Unit;
use NorseBlue\Sikker\Symmetric\CipherMethod;

class CipherMethodTest extends Unit
{
    use Specify;

    protected function _after()
    {
    }

    protected function _before()
    {
    }

    // tests

    /**
     * Tests the type names
     */
    public function testCipherMethods()
    {
        $this->specify('Gets all available cipher methods.', function () {
            if (extension_loaded('openssl')) {
                $this->assertInternalType('array', CipherMethod::allAvailable());
            }
        });

        // RC4 is the default cipher method used by openssl so it should be available on most if not all platform stacks with openssl.
        $this->specify('Verifies that RC4 cipher method is available.', function () {
            if (extension_loaded('openssl')) {
                $this->assertTrue(CipherMethod::isAvailable(CipherMethod::RC4));
            }
        });
    }
}
