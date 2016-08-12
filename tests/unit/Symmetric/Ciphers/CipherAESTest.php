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

namespace NorseBlue\Sikker\Tests\Symmetric\Ciphers;

use Codeception\Specify;
use Codeception\Test\Unit;
use InvalidArgumentException;
use NorseBlue\Sikker\Symmetric\CipherBlockSize;
use NorseBlue\Sikker\Symmetric\Ciphers\CipherAES;

class CipherAESTest extends Unit
{
    use Specify;

    /**
     * @var string Helper payload to encrypt.
     */
    const PAYLOAD = 'You know nothing Jon Snow! Winter is coming!';

    /**
     * @var string Helper password to encrypt.
     */
    const PASSWORD = 'The White Wolf';

    /**
     * @var string The password as hex string.
     */
    const PASSWORD_HEX = '54686520576869746520576F6c66';

    /**
     * @var string An initialization vector.
     */
    const IV = 'Ygritte';

    /**
     * @var string The payload encrypted with AES128 and the password.
     */
    const ENCRYPTED_PAYLOAD_AES128_BASE64 = '70AJbc54tRj1kyxniCpy4fv+ZDLor7xXwZryXbU0NH4sA7xt5yDZYOEQY8FW8AZN';

    /**
     * @var string The payload encrypted with AES128, the password and the IV.
     */
    const ENCRYPTED_PAYLOAD_AES128_BASE64_IV = 'FkByoFaxK/mKRD8PCTnIbH8nKGPy5XHipLSVARqbAVcfVTdfZDH6kjxRbr9gwGVZ';

    /**
     * @var string The payload encrypted with AES192 and the password.
     */
    const ENCRYPTED_PAYLOAD_AES192_BASE64 = '6yaCFel9uCrnJ1y+fQHMr1lIYJHcCgUdu11voRKY4m+o5tMZA3iXwIO0yFR7O0A3';

    /**
     * @var string The payload encrypted with AES192, the password and the IV.
     */
    const ENCRYPTED_PAYLOAD_AES192_BASE64_IV = 'RTiQ69I/6XOILFq2mj8biRRNOnq46zQ2487kB0HT+GgtxoEjtXAz/IEu7amWHhMl';

    /**
     * @var string The payload encrypted with AES256 and the password.
     */
    const ENCRYPTED_PAYLOAD_AES256_BASE64 = '8gobe8amPhCn9eDqWb6rn/GaLpMCVePhTlNEuTMhsA2aTiQyMy+BgSjZupic5/V5';

    /**
     * @var string The payload encrypted with AES256, the password and the IV.
     */
    const ENCRYPTED_PAYLOAD_AES256_BASE64_IV = 'cnnPKgDaPFeBwIS0/bK+K5b80ooj3MzYc09LodWC44OhRDdu5bS7dDAYUav5IFcL';

    protected function _after()
    {
    }

    protected function _before()
    {
    }

    // tests

    public function testIncorrectBlockSize()
    {
        $this->specify('', function () {
            $this->expectException(InvalidArgumentException::class);
            $cipher = new CipherAES(3);
        });
    }

    /**
     * Tests the type names
     */
    public function testEncryptionDecryption()
    {
        $this->specify('Encrypts and decrypts the payload with AES128', function () {
            if (extension_loaded('openssl')) {
                $cipher = new CipherAES(CipherBlockSize::_128);
                $encrypted = $cipher->encrypt(self::PAYLOAD, self::PASSWORD);
                $this->assertInternalType('array', $encrypted);
                $this->assertEquals(5, count($encrypted));
                $this->assertEquals(self::ENCRYPTED_PAYLOAD_AES128_BASE64, $encrypted[0]);
                $this->assertEquals(strtolower(self::PASSWORD_HEX), strtolower($encrypted[1]));
                $this->assertEquals(0, $encrypted[2]);
                $this->assertEquals('', $encrypted[3]);

                $decrypted = $cipher->decrypt(self::ENCRYPTED_PAYLOAD_AES128_BASE64, self::PASSWORD);
                $this->assertEquals(self::PAYLOAD, $decrypted);
            }
        });

        $this->specify('Encrypts and decrypts the payload with AES128 and an IV.', function () {
            if (extension_loaded('openssl')) {
                $cipher = new CipherAES(CipherBlockSize::_128, self::IV);
                $encrypted = $cipher->encrypt(self::PAYLOAD, self::PASSWORD);
                $this->assertInternalType('array', $encrypted);
                $this->assertEquals(5, count($encrypted));
                $this->assertEquals(self::ENCRYPTED_PAYLOAD_AES128_BASE64_IV, $encrypted[0]);
                $this->assertEquals(strtolower(self::PASSWORD_HEX), strtolower($encrypted[1]));
                $this->assertEquals(0, $encrypted[2]);
                $this->assertEquals(self::IV, $encrypted[3]);

                $decrypted = $cipher->decrypt(self::ENCRYPTED_PAYLOAD_AES128_BASE64_IV, self::PASSWORD);
                $this->assertEquals(self::PAYLOAD, $decrypted);
            }
        });

        $this->specify('Encrypts and decrypts the payload with AES192', function () {
            if (extension_loaded('openssl')) {
                $cipher = new CipherAES(CipherBlockSize::_192);
                $encrypted = $cipher->encrypt(self::PAYLOAD, self::PASSWORD);
                $this->assertInternalType('array', $encrypted);
                $this->assertEquals(5, count($encrypted));
                $this->assertEquals(self::ENCRYPTED_PAYLOAD_AES192_BASE64, $encrypted[0]);
                $this->assertEquals(strtolower(self::PASSWORD_HEX), strtolower($encrypted[1]));
                $this->assertEquals(0, $encrypted[2]);
                $this->assertEquals('', $encrypted[3]);

                $decrypted = $cipher->decrypt(self::ENCRYPTED_PAYLOAD_AES192_BASE64, self::PASSWORD);
                $this->assertEquals(self::PAYLOAD, $decrypted);
            }
        });

        $this->specify('Encrypts and decrypts the payload with AES192 and an IV.', function () {
            if (extension_loaded('openssl')) {
                $cipher = new CipherAES(CipherBlockSize::_192, self::IV);
                $encrypted = $cipher->encrypt(self::PAYLOAD, self::PASSWORD);
                $this->assertInternalType('array', $encrypted);
                $this->assertEquals(5, count($encrypted));
                $this->assertEquals(self::ENCRYPTED_PAYLOAD_AES192_BASE64_IV, $encrypted[0]);
                $this->assertEquals(strtolower(self::PASSWORD_HEX), strtolower($encrypted[1]));
                $this->assertEquals(0, $encrypted[2]);
                $this->assertEquals(self::IV, $encrypted[3]);

                $decrypted = $cipher->decrypt(self::ENCRYPTED_PAYLOAD_AES192_BASE64_IV, self::PASSWORD);
                $this->assertEquals(self::PAYLOAD, $decrypted);
            }
        });

        $this->specify('Encrypts and decrypts the payload with AES256', function () {
            if (extension_loaded('openssl')) {
                $cipher = new CipherAES(CipherBlockSize::_256);
                $encrypted = $cipher->encrypt(self::PAYLOAD, self::PASSWORD);
                $this->assertInternalType('array', $encrypted);
                $this->assertEquals(5, count($encrypted));
                $this->assertEquals(self::ENCRYPTED_PAYLOAD_AES256_BASE64, $encrypted[0]);
                $this->assertEquals(strtolower(self::PASSWORD_HEX), strtolower($encrypted[1]));
                $this->assertEquals(0, $encrypted[2]);
                $this->assertEquals('', $encrypted[3]);

                $decrypted = $cipher->decrypt(self::ENCRYPTED_PAYLOAD_AES256_BASE64, self::PASSWORD);
                $this->assertEquals(self::PAYLOAD, $decrypted);
            }
        });

        $this->specify('Encrypts and decrypts the payload with AES256 and an IV.', function () {
            if (extension_loaded('openssl')) {
                $cipher = new CipherAES(CipherBlockSize::_256, self::IV);
                $encrypted = $cipher->encrypt(self::PAYLOAD, self::PASSWORD);
                $this->assertInternalType('array', $encrypted);
                $this->assertEquals(5, count($encrypted));
                $this->assertEquals(self::ENCRYPTED_PAYLOAD_AES256_BASE64_IV, $encrypted[0]);
                $this->assertEquals(strtolower(self::PASSWORD_HEX), strtolower($encrypted[1]));
                $this->assertEquals(0, $encrypted[2]);
                $this->assertEquals(self::IV, $encrypted[3]);

                $decrypted = $cipher->decrypt(self::ENCRYPTED_PAYLOAD_AES256_BASE64_IV, self::PASSWORD);
                $this->assertEquals(self::PAYLOAD, $decrypted);
            }
        });
    }
}
