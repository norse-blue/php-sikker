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

namespace NorseBlue\Sikker\Tests\Keys;

use Codeception\Specify;
use Codeception\Test\Unit;
use NorseBlue\Sikker\Asymmetric\CryptoKey;
use NorseBlue\Sikker\Asymmetric\CryptoKeyType;
use NorseBlue\Sikker\Asymmetric\CryptoKeyTypeException;
use NorseBlue\Sikker\Asymmetric\PrivateKey;
use NorseBlue\Sikker\Asymmetric\PublicKey;
use NorseBlue\Sikker\OpenSSL\OpenSSLNotAvailableException;
use RuntimeException;

class CryptoKeySubclass extends CryptoKey
{
    public function decrypt(string $encryptedData) : string
    {
        return '';
    }

    public function encrypt(string $rawData) : string
    {
        return '';
    }

    public function getPEM(string $passphrase = null) : string
    {
        return '';
    }

    public function isPairOf(CryptoKey $pairedKey) : bool
    {
        return true;
    }

    public function save(string $path, string $passphrase = null) : bool
    {
        return true;
    }
}

class CryptoKeyTest extends Unit
{
    use Specify;

    /**
     * @var string The path to the DSA Private Key example file.
     */
    const DSA_PRIVATE_KEY_EXAMPLE_FILE = 'tests/_data/DSA_private_key_example.pem';

    /**
     * @var string The path to the DSA Public Key example file.
     */
    const DSA_PUBLIC_KEY_EXAMPLE_FILE = 'tests/_data/DSA_public_key_example.pem';

    /**
     * @var string The path to the RSA Private Key example file.
     * @see http://phpseclib.sourceforge.net/rsa/examples.html phpseclib: RSA Examples and Notes
     */
    const RSA_PRIVATE_KEY_EXAMPLE_FILE = 'tests/_data/RSA_private_key_example.pem';

    /**
     * @var string The path to the RSA Public Key example file.
     * @see http://phpseclib.sourceforge.net/rsa/examples.html phpseclib: RSA Examples and Notes
     */
    const RSA_PUBLIC_KEY_EXAMPLE_FILE = 'tests/_data/RSA_public_key_example.pem';

    /**
     * @var string The path to the DH Private Key example file.
     */
    const DH_PRIVATE_KEY_EXAMPLE_FILE = 'tests/_data/DH_private_key_example.pem';

    /**
     * @var string The path to the DH Public Key example file.
     */
    const DH_PUBLIC_KEY_EXAMPLE_FILE = 'tests/_data/DH_public_key_example.pem';

    /**
     * @var string The path to the EC Private Key example file.
     */
    const EC_PRIVATE_KEY_EXAMPLE_FILE = 'tests/_data/EC_private_key_example.pem';

    /**
     * @var string The path to the EC Public Key example file.
     */
    const EC_PUBLIC_KEY_EXAMPLE_FILE = 'tests/_data/EC_public_key_example.pem';

    /**
     * @var string The path to a temp file to be saved.
     */
    const SAVE_FILE_PATH = 'tests/_temp/cryptokey_example.pem';

    protected function _after()
    {
    }

    protected function _before()
    {
    }

    // tests

    /**
     * Tests the generate function.
     */
    public function testConstructor()
    {
        $this->specify('Throws an RuntimeException if the passed value is not a resource when constructing the object.',
            function () {
                if (extension_loaded('openssl')) {
                    $this->expectException(RuntimeException::class);
                    $key = new CryptoKeySubclass(998);
                } else {
                    $this->expectException(OpenSSLNotAvailableException::class);
                    $key = new CryptoKeySubclass(998);
                }
            });
    }

    /**
     * Tests the getters functions.
     */
    public function testGetters()
    {
        $this->specify('Gets the RSA private key in PEM format.', function () {
            if (extension_loaded('openssl')) {
                $privateKeyContents = str_replace("\r", "",
                    trim(file_get_contents(self::RSA_PRIVATE_KEY_EXAMPLE_FILE)));
                $privateKey = PrivateKey::fromPEM($privateKeyContents);
                $this->assertInternalType('resource', $privateKey->getResource());
                $this->assertEquals(CryptoKey::DEFAULT_CONFIG, $privateKey->getConfig());
                $this->assertEquals(4, count($privateKey->getDetails()));
                $this->assertEquals(1024, $privateKey->getBits());
                $this->assertEquals(CryptoKeyType::RSA, $privateKey->getType());
                $this->assertEquals('rsa', CryptoKeyType::toName($privateKey->getType()));
                $this->assertEquals('f0e293a34da5883dcfbffe35dad2699e6644373a', sha1($privateKey->getModulus()));
                $this->assertEquals($privateKeyContents, $privateKey->getPEM());
                $this->assertTrue($privateKey->isRSA());
                $this->assertFalse($privateKey->isDSA());
                $this->assertFalse($privateKey->isDH());
                $this->assertFalse($privateKey->isEC());
            }
        });

        $this->specify('Gets the RSA public key in PEM format.', function () {
            if (extension_loaded('openssl')) {
                $publicKeyContents = str_replace("\r", "", trim(file_get_contents(self::RSA_PUBLIC_KEY_EXAMPLE_FILE)));
                $publicKey = PublicKey::fromPEM($publicKeyContents);
                $this->assertInternalType('resource', $publicKey->getResource());
                $this->assertEquals(CryptoKey::DEFAULT_CONFIG, $publicKey->getConfig());
                $this->assertEquals(4, count($publicKey->getDetails()));
                $this->assertEquals(1024, $publicKey->getBits());
                $this->assertEquals(CryptoKeyType::RSA, $publicKey->getType());
                $this->assertEquals('rsa', CryptoKeyType::toName($publicKey->getType()));
                $this->assertEquals('f0e293a34da5883dcfbffe35dad2699e6644373a', sha1($publicKey->getModulus()));
                $this->assertEquals($publicKeyContents, $publicKey->getPEM());
                $this->assertTrue($publicKey->isRSA());
                $this->assertFalse($publicKey->isDSA());
                $this->assertFalse($publicKey->isDH());
                $this->assertFalse($publicKey->isEC());
            }
        });

        $this->specify('Gets the DSA private key in PEM format.', function () {
            if (extension_loaded('openssl')) {
                $privateKeyContents = str_replace("\r", "",
                    trim(file_get_contents(self::DSA_PRIVATE_KEY_EXAMPLE_FILE)));
                $privateKey = PrivateKey::fromPEM($privateKeyContents);
                $this->assertInternalType('resource', $privateKey->getResource());
                $this->assertEquals(CryptoKey::DEFAULT_CONFIG, $privateKey->getConfig());
                $this->assertEquals(4, count($privateKey->getDetails()));
                $this->assertEquals(1024, $privateKey->getBits());
                $this->assertEquals(CryptoKeyType::DSA, $privateKey->getType());
                $this->assertEquals('dsa', CryptoKeyType::toName($privateKey->getType()));
                $this->assertEquals('8196c7dd65b518f9e555fb3683f8d0b68a8edbf2', sha1($privateKey->getModulus()));
                $this->assertEquals($privateKeyContents, $privateKey->getPEM());
                $this->assertFalse($privateKey->isRSA());
                $this->assertTrue($privateKey->isDSA());
                $this->assertFalse($privateKey->isDH());
                $this->assertFalse($privateKey->isEC());
            }
        });

        $this->specify('Gets the DSA public key in PEM format.', function () {
            if (extension_loaded('openssl')) {
                $publicKeyContents = str_replace("\r", "", trim(file_get_contents(self::DSA_PUBLIC_KEY_EXAMPLE_FILE)));
                $publicKey = PublicKey::fromPEM($publicKeyContents);
                $this->assertInternalType('resource', $publicKey->getResource());
                $this->assertEquals(CryptoKey::DEFAULT_CONFIG, $publicKey->getConfig());
                $this->assertEquals(4, count($publicKey->getDetails()));
                $this->assertEquals(1024, $publicKey->getBits());
                $this->assertEquals(CryptoKeyType::DSA, $publicKey->getType());
                $this->assertEquals('dsa', CryptoKeyType::toName($publicKey->getType()));
                $this->assertEquals('8196c7dd65b518f9e555fb3683f8d0b68a8edbf2', sha1($publicKey->getModulus()));
                $this->assertEquals($publicKeyContents, $publicKey->getPEM());
                $this->assertFalse($publicKey->isRSA());
                $this->assertTrue($publicKey->isDSA());
                $this->assertFalse($publicKey->isDH());
                $this->assertFalse($publicKey->isEC());
            }
        });

        $this->specify('Gets the DH private key in PEM format.', function () {
            if (extension_loaded('openssl')) {
                $privateKeyContents = str_replace("\r", "",
                    trim(file_get_contents(self::DH_PRIVATE_KEY_EXAMPLE_FILE)));
                $privateKey = PrivateKey::fromPEM($privateKeyContents);
                $this->assertInternalType('resource', $privateKey->getResource());
                $this->assertEquals(CryptoKey::DEFAULT_CONFIG, $privateKey->getConfig());
                $this->assertEquals(4, count($privateKey->getDetails()));
                $this->assertEquals(1024, $privateKey->getBits());
                $this->assertEquals(CryptoKeyType::DH, $privateKey->getType());
                $this->assertEquals('dh', CryptoKeyType::toName($privateKey->getType()));
                $this->assertEquals('f7283e410b026753f6b11aad228c907600adf5ef', sha1($privateKey->getModulus()));
                $this->assertEquals($privateKeyContents, $privateKey->getPEM());
                $this->assertFalse($privateKey->isRSA());
                $this->assertFalse($privateKey->isDSA());
                $this->assertTrue($privateKey->isDH());
                $this->assertFalse($privateKey->isEC());
            }
        });

        $this->specify('Gets the DH public key in PEM format.', function () {
            if (extension_loaded('openssl')) {
                $publicKeyContents = str_replace("\r", "", trim(file_get_contents(self::DH_PUBLIC_KEY_EXAMPLE_FILE)));
                $publicKey = PublicKey::fromPEM($publicKeyContents);
                $this->assertInternalType('resource', $publicKey->getResource());
                $this->assertEquals(CryptoKey::DEFAULT_CONFIG, $publicKey->getConfig());
                $this->assertEquals(4, count($publicKey->getDetails()));
                $this->assertEquals(1024, $publicKey->getBits());
                $this->assertEquals(CryptoKeyType::DH, $publicKey->getType());
                $this->assertEquals('dh', CryptoKeyType::toName($publicKey->getType()));
                $this->assertEquals('f7283e410b026753f6b11aad228c907600adf5ef', sha1($publicKey->getModulus()));
                $this->assertEquals($publicKeyContents, $publicKey->getPEM());
                $this->assertFalse($publicKey->isRSA());
                $this->assertFalse($publicKey->isDSA());
                $this->assertTrue($publicKey->isDH());
                $this->assertFalse($publicKey->isEC());
            }
        });

        $this->specify('Gets the EC private key in PEM format.', function () {
            if (extension_loaded('openssl')) {
                $privateKeyContents = str_replace("\r", "",
                    trim(file_get_contents(self::EC_PRIVATE_KEY_EXAMPLE_FILE)));
                $privateKey = PrivateKey::fromPEM($privateKeyContents);
                $this->assertInternalType('resource', $privateKey->getResource());
                $this->assertEquals(CryptoKey::DEFAULT_CONFIG, $privateKey->getConfig());
                $this->assertEquals(4, count($privateKey->getDetails()));
                $this->assertEquals(256, $privateKey->getBits());
                $this->assertEquals(CryptoKeyType::EC, $privateKey->getType());
                $this->assertEquals('ec', CryptoKeyType::toName($privateKey->getType()));
                $this->assertEquals($privateKeyContents, $privateKey->getPEM());
                $this->assertFalse($privateKey->isRSA());
                $this->assertFalse($privateKey->isDSA());
                $this->assertFalse($privateKey->isDH());
                $this->assertTrue($privateKey->isEC());
                $this->expectException(CryptoKeyTypeException::class);
                $modulus = $privateKey->getModulus();
            }
        });

        $this->specify('Gets the EC public key in PEM format.', function () {
            if (extension_loaded('openssl')) {
                $publicKeyContents = str_replace("\r", "", trim(file_get_contents(self::EC_PUBLIC_KEY_EXAMPLE_FILE)));
                $publicKey = PublicKey::fromPEM($publicKeyContents);
                $this->assertInternalType('resource', $publicKey->getResource());
                $this->assertEquals(CryptoKey::DEFAULT_CONFIG, $publicKey->getConfig());
                $this->assertEquals(4, count($publicKey->getDetails()));
                $this->assertEquals(256, $publicKey->getBits());
                $this->assertEquals(CryptoKeyType::EC, $publicKey->getType());
                $this->assertEquals('ec', CryptoKeyType::toName($publicKey->getType()));
                $this->assertEquals($publicKeyContents, $publicKey->getPEM());
                $this->assertFalse($publicKey->isRSA());
                $this->assertFalse($publicKey->isDSA());
                $this->assertFalse($publicKey->isDH());
                $this->assertTrue($publicKey->isEC());
                $this->expectException(CryptoKeyTypeException::class);
                $modulus = $publicKey->getModulus();
            }
        });
    }

    /**
     * Tests the save function.
     */
    public function testSave()
    {
        $this->specify('Saves the private key in PEM format.', function () {
            if (extension_loaded('openssl')) {
                @unlink(self::SAVE_FILE_PATH);
                $this->assertFalse(file_exists(self::SAVE_FILE_PATH));
                $privateKeyContents = str_replace("\r", "",
                    trim(file_get_contents(self::RSA_PRIVATE_KEY_EXAMPLE_FILE)));
                $privateKey = PrivateKey::fromPEM($privateKeyContents);
                $privateKey->save(self::SAVE_FILE_PATH);
                $this->assertTrue(file_exists(self::SAVE_FILE_PATH));
                $this->assertEquals($privateKeyContents,
                    str_replace("\r", "", trim(file_get_contents(self::SAVE_FILE_PATH))));
                @unlink(self::SAVE_FILE_PATH);
            }
        });

        $this->specify('Saves the public key in PEM format.', function () {
            if (extension_loaded('openssl')) {
                @unlink(self::SAVE_FILE_PATH);
                $this->assertFalse(file_exists(self::SAVE_FILE_PATH));
                $publicKeyContents = str_replace("\r", "", trim(file_get_contents(self::RSA_PUBLIC_KEY_EXAMPLE_FILE)));
                $publicKey = PublicKey::fromPEM($publicKeyContents);
                $publicKey->save(self::SAVE_FILE_PATH);
                $this->assertTrue(file_exists(self::SAVE_FILE_PATH));
                $this->assertEquals($publicKeyContents, file_get_contents(self::SAVE_FILE_PATH));
                @unlink(self::SAVE_FILE_PATH);
            }
        });
    }
}
