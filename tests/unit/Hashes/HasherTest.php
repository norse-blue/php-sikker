<?php
/**
 * Sikker is a PHP 7.0+ Security package that contains security related implementations.
 *
 * @package    NorseBlue\Sikker
 * @version    0.3.8
 * @author     NorseBlue
 * @license    MIT License
 * @copyright  2016 NorseBlue
 * @link       https://github.com/NorseBlue/Sikker
 */
declare(strict_types = 1);

namespace NorseBlue\Sikker\Tests\Hashes;

use Codeception\Specify;
use Codeception\Test\Unit;
use NorseBlue\Sikker\FileNotFoundException;
use NorseBlue\Sikker\Hashes\HashAlgorithm;
use NorseBlue\Sikker\Hashes\HashAlgorithmNotAvailableException;
use NorseBlue\Sikker\Hashes\Hasher;
use RuntimeException;

class HasherTest extends Unit
{
    use Specify;

    /**
     * @var string Helper payload to hash.
     */
    const PAYLOAD = 'You know nothing Jon Snow! Winter is coming!';

    /**
     * @var string Helper payload file path to hash.
     */
    const PAYLOAD_FILE = 'tests/_data/hash_payload.txt';

    protected function _after()
    {
    }

    protected function _before()
    {
    }

    // tests

    /**
     * Tests getter and setter of the algorithm property.
     */
    public function testGetSetAlgorithm()
    {
        $this->specify('Sets the algorithm and returns the same instance for fluent usage.', function () {
            $hasher = new Hasher();
            $this->assertSame($hasher, $hasher->setAlgorithm(HashAlgorithm::SHA1));
            $this->assertEquals(HashAlgorithm::SHA1, $hasher->getAlgorithm());
        });
    }

    /**
     * Tests the exceptions thrown in the setAlgorithm method through the constructor.
     */
    public function testSetAlgorithmExceptions()
    {
        $this->specify('Throws an AlgorithmNotAvailableException if algorithm is not available.', function () {
            $this->expectException(HashAlgorithmNotAvailableException::class);
            $hasher = new Hasher('NonexistentAlgorithm');
        });
    }

    /**
     * Tests the hash function.
     */
    public function testHash()
    {
        $this->specify('Hashes payload with SHA256.', function () {
            $hasher = new Hasher();
            $this->assertEquals('9465277d715c827ec7a3f6fd014717fc115f69f77ed738aa19ff2e245796214b',
                $hasher->hash(self::PAYLOAD));
        });

        $this->specify('Hashes payload with MD5.', function () {
            $hasher = new Hasher(HashAlgorithm::MD5);
            $this->assertEquals('cf842df7b7d9d50d566644da3e38a7f1',
                $hasher->hash(self::PAYLOAD));
        });

        $this->specify('Hashes payload with SHA1.', function () {
            $hasher = new Hasher(HashAlgorithm::SHA1);
            $this->assertEquals('68dd4f4f681bfc8c194239126fd8b8d5ec765593',
                $hasher->hash(self::PAYLOAD));
        });

        $this->specify('Hashes payload with SHA512.', function () {
            $hasher = new Hasher(HashAlgorithm::SHA512);
            $this->assertEquals('56e09da12c430865ce440ee1fc258f6133c1dc6de84197aaaf9917d308eac7753c19d07ba130bc14a39217137a5bec92e43b615bec39da98e12f88e4d3f39794',
                $hasher->hash(self::PAYLOAD));
        });

        $this->specify('Hashes payload with Whirpool after changing the algorithm.', function () {
            $hasher = new Hasher();
            $this->assertEquals(Hasher::DEFAULT_ALGORITHM, $hasher->getAlgorithm());
            $hasher->setAlgorithm(HashAlgorithm::WHIRLPOOL);
            $this->assertEquals(HashAlgorithm::WHIRLPOOL, $hasher->getAlgorithm());
            $this->assertEquals('6f20f4b3e3713e3c96e53b2d57079d8d126f913348915b96ae8c74feb078a4db3b316e600de1fd268e683fa05ae18c525e676c82449d61aeda0fce4b1eeeb54f',
                $hasher->hash(self::PAYLOAD));
        });
    }

    /**
     * Tests the hashFile function.
     */
    public function testHashFile()
    {
        $this->specify('Hashes payload file contents with SHA256.', function () {
            $hasher = new Hasher();
            $this->assertEquals('9465277d715c827ec7a3f6fd014717fc115f69f77ed738aa19ff2e245796214b',
                $hasher->hashFile(self::PAYLOAD_FILE));
        });

        $this->specify('Hashes payload file contents with MD5.', function () {
            $hasher = new Hasher(HashAlgorithm::MD5);
            $this->assertEquals('cf842df7b7d9d50d566644da3e38a7f1',
                $hasher->hashFile(self::PAYLOAD_FILE));
        });

        $this->specify('Hashes payload file contents with SHA1.', function () {
            $hasher = new Hasher(HashAlgorithm::SHA1);
            $this->assertEquals('68dd4f4f681bfc8c194239126fd8b8d5ec765593',
                $hasher->hashFile(self::PAYLOAD_FILE));
        });

        $this->specify('Hashes payload file contents with SHA512.', function () {
            $hasher = new Hasher(HashAlgorithm::SHA512);
            $this->assertEquals('56e09da12c430865ce440ee1fc258f6133c1dc6de84197aaaf9917d308eac7753c19d07ba130bc14a39217137a5bec92e43b615bec39da98e12f88e4d3f39794',
                $hasher->hashFile(self::PAYLOAD_FILE));
        });

        $this->specify('Hashes payload file contents with Whirpool after changing the algorithm.', function () {
            $hasher = new Hasher();
            $this->assertEquals(Hasher::DEFAULT_ALGORITHM, $hasher->getAlgorithm());
            $hasher->setAlgorithm(HashAlgorithm::WHIRLPOOL);
            $this->assertEquals(HashAlgorithm::WHIRLPOOL, $hasher->getAlgorithm());
            $this->assertEquals('6f20f4b3e3713e3c96e53b2d57079d8d126f913348915b96ae8c74feb078a4db3b316e600de1fd268e683fa05ae18c525e676c82449d61aeda0fce4b1eeeb54f',
                $hasher->hashFile(self::PAYLOAD_FILE));
        });
    }

    /**
     * Tests the exceptions thrown in the hashFile function.
     */
    public function testHashFileExceptions()
    {
        $this->specify('Throws a FileNotFoundException if the given file does not exist.', function () {
            $this->expectException(FileNotFoundException::class);
            $hasher = new Hasher();
            $hasher->hashFile('nonexistentFile');
        });
    }

    /**
     * Tests the exceptions thrown in the hashFileInfo function.
     *
     * This tests do their best to validate the exceptions thrown in the hashFileInfo function,
     * but the results are unreliable as the function relies on the underlying platform used and
     * every small change on a file (e.g. last modified datetime) changes the resulting hash.
     */
    public function testHashFileInfoExceptions()
    {
        if (!extension_loaded('finfo')) {
            // Run this test only if the FileInfo module is not available.
            $this->specify('Throws a RuntimeException if the FileInfo module is not available.', function () {
                $this->expectException(RuntimeException::class);
                $hasher = new Hasher();
                $hasher->hashFileInfo(self::PAYLOAD_FILE);
            });
        } else {
            // Run this test only if the FileInfo module is available.
            // Testing for UnexpectedValueException if opening the FileInfo database failed is unreliable so the test is omitted.

            $this->specify('Throws a FileNotFoundException if the given file does not exist.', function () {
                $this->expectException(FileNotFoundException::class);
                $hasher = new Hasher();
                $hasher->hashFileInfo('nonexistentFile');
            });
        }
    }
}
