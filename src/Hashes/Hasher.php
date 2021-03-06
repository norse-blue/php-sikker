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

namespace NorseBlue\Sikker\Hashes;

use NorseBlue\Sikker\FileNotFoundException;
use RuntimeException;
use UnexpectedValueException;

/**
 * Class Hasher
 *
 * @package NorseBlue\Sikker\Hashes
 * @uses NorseBlue\Sikker\Hashes\Algorithm
 * @since 0.1
 */
class Hasher
{
    /**
     * @var string The default hashing algorithm.
     */
    const DEFAULT_ALGORITHM = HashAlgorithm::SHA256;

    /**
     * @var string The hashing algorithm to use. Defaults to SHA256.
     */
    protected $algorithm;

    /**
     * Hasher constructor.
     *
     * @param string|null $algorithm The selected algorithm or null to use the default.
     * @since 0.1
     */
    public function __construct(string $algorithm = self::DEFAULT_ALGORITHM)
    {
        $this->setAlgorithm($algorithm);
    }

    /**
     * Gets the Hasher algorithm.
     *
     * @return string Returns the Hasher selected algorithm.
     * @since 0.1
     */
    public function getAlgorithm() : string
    {
        return $this->algorithm;
    }

    /**
     * Sets the Hasher algorithm.
     *
     * @param string|null $algorithm The algorithm to select for the Hasher. If null is given, the default algorithm will be used.
     * @throws HashAlgorithmNotAvailableException When the given algorithm is not available to be used.
     * @return Hasher Returns this instance for fluent interface.
     * @since 0.1
     */
    public function setAlgorithm(string $algorithm = null) : Hasher
    {
        $algorithm = $algorithm ?? self::DEFAULT_ALGORITHM;
        if (!HashAlgorithm::isAvailable($algorithm)) {
            throw new HashAlgorithmNotAvailableException($algorithm,
                'The given hash algorithm is not available in the current platform stack.');
        }
        $this->algorithm = $algorithm;
        return $this;
    }

    /**
     * Generates a hash value from the given payload using the Hasher selected algorithm.
     *
     * @param string $payload The payload to hash.
     * @param bool $raw_output When set to true, outputs raw binary data. False outputs lowercase hexits. {@link http://php.net/manual/en/function.hash.php hash() function}
     * @return string Returns the message digest generated with the selected hash algorithm.
     * @since 0.1
     */
    public function hash(string $payload, bool $raw_output = false) : string
    {
        return hash($this->algorithm, $payload, $raw_output);
    }

    /**
     * Generates a hash value using the contents of a given file and the Hasher selected algorithm.
     *
     * @param string $file The file to read it's content and generated the hash from it.
     * @param bool $raw_output When set to true, outputs raw binary data. False outputs lowercase hexits. {@link http://php.net/manual/en/function.hash.php hash() function}
     * @return string Returns the message digest generated with the selected hash algorithm.
     * @throws FileNotFoundException When the file is not found.
     * @since 0.1
     */
    public function hashFile(string $file, bool $raw_output = false) : string
    {
        if (!file_exists($file)) {
            throw new FileNotFoundException($file, "The given file does not exist.");
        }

        return hash_file($this->algorithm, $file, $raw_output);
    }

    /**
     * Generates a hash value from the given file's metadata and the Hasher selected algorithm.
     *
     * @param string $file The file to generate the hash from.
     * @param bool $raw_output When set to true, outputs raw binary data. False outputs lowercase hexits. {@link http://php.net/manual/en/function.hash.php hash() function}
     * @return string Returns the message digest generated for the file's info.
     * @throws RuntimeException When the FileInfo module is not available.
     * @throws UnexpectedValueException When opening the FileInfo database failed.
     * @throws FileNotFoundException When the file is not found.
     * @since 0.1
     * @codeCoverageIgnore Testing this function is unreliable as the hash can potentially change due to changes on the filesystem (e.g. last modified datetime)
     */
    public function hashFileInfo(string $file, bool $raw_output = false) : string
    {
        if (class_exists('\finfo')) {
            throw new RuntimeException("The FileInfo module is not available.");
        }

        if (!($finfo = new \finfo(FILEINFO_MIME | FILEINFO_PRESERVE_ATIME))) {
            throw new UnexpectedValueException('Opening the FileInfo database failed.');
        }

        if (!file_exists($file)) {
            throw new FileNotFoundException($file, "The given file does not exist.");
        }

        $payload = $finfo->file($file);
        return $this->hash($payload, $raw_output);
    }
}
