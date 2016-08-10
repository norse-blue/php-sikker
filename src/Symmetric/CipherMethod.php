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

namespace NorseBlue\Sikker\Symmetric;

use NorseBlue\Sikker\OpenSSL\OpenSSL;

/**
 * Class CipherMethod
 *
 * @package NorseBlue\Sikker\Symmetric
 * @see http://php.net/manual/en/function.openssl-get-cipher-methods.php openssl_get_cipher_methods function reference.
 * @since 0.3
 */
abstract class CipherMethod
{
    const AES_128_CBC = 'aes-128-cbc';
    const AES_128_CCM = 'aes-128-ccm';
    const AES_128_CFB = 'aes-128-cfb';
    const AES_128_CFB1 = 'aes-128-cfb1';
    const AES_128_CFB8 = 'aes-128-cfb8';
    const AES_128_CTR = 'aes-128-ctr';
    const AES_128_ECB = 'aes-128-ecb';
    const AES_128_GCM = 'aes-128-gcm';
    const AES_128_OFB = 'aes-128-ofb';
    const AES_128_XTS = 'aes-128-xts';
    const AES_192_CBC = 'aes-192-cbc';
    const AES_192_CCM = 'aes-192-ccm';
    const AES_192_CFB = 'aes-192-cfb';
    const AES_192_CFB1 = 'aes-192-cfb1';
    const AES_192_CFB8 = 'aes-192-cfb8';
    const AES_192_CTR = 'aes-192-ctr';
    const AES_192_ECB = 'aes-192-ecb';
    const AES_192_GCM = 'aes-192-gcm';
    const AES_192_OFB = 'aes-192-ofb';
    const AES_256_CBC = 'aes-256-cbc';
    const AES_256_CCM = 'aes-256-ccm';
    const AES_256_CFB = 'aes-256-cfb';
    const AES_256_CFB1 = 'aes-256-cfb1';
    const AES_256_CFB8 = 'aes-256-cfb8';
    const AES_256_CTR = 'aes-256-ctr';
    const AES_256_ECB = 'aes-256-ecb';
    const AES_256_GCM = 'aes-256-gcm';
    const AES_256_OFB = 'aes-256-ofb';
    const AES_256_XTS = 'aes-256-xts';
    const BF_CBC = 'bf-cbc';
    const BF_CFB = 'bf-cfb';
    const BF_ECB = 'bf-ecb';
    const BF_OFB = 'bf-ofb';
    const CAMELLIA_128_CBC = 'camellia-128-cbc';
    const CAMELLIA_128_CFB = 'camellia-128-cfb';
    const CAMELLIA_128_CFB1 = 'camellia-128-cfb1';
    const CAMELLIA_128_CFB8 = 'camellia-128-cfb8';
    const CAMELLIA_128_ECB = 'camellia-128-ecb';
    const CAMELLIA_128_OFB = 'camellia-128-ofb';
    const CAMELLIA_192_CBC = 'camellia-192-cbc';
    const CAMELLIA_192_CFB = 'camellia-192-cfb';
    const CAMELLIA_192_CFB1 = 'camellia-192-cfb1';
    const CAMELLIA_192_CFB8 = 'camellia-192-cfb8';
    const CAMELLIA_192_ECB = 'camellia-192-ecb';
    const CAMELLIA_192_OFB = 'camellia-192-ofb';
    const CAMELLIA_256_CBC = 'camellia-256-cbc';
    const CAMELLIA_256_CFB = 'camellia-256-cfb';
    const CAMELLIA_256_CFB1 = 'camellia-256-cfb1';
    const CAMELLIA_256_CFB8 = 'camellia-256-cfb8';
    const CAMELLIA_256_ECB = 'camellia-256-ecb';
    const CAMELLIA_256_OFB = 'camellia-256-ofb';
    const CAST5_CBC = 'cast5-cbc';
    const CAST5_CFB = 'cast5-cfb';
    const CAST5_ECB = 'cast5-ecb';
    const CAST5_OFB = 'cast5-ofb';
    const DES_CBC = 'des-cbc';
    const DES_CFB = 'des-cfb';
    const DES_CFB1 = 'des-cfb1';
    const DES_CFB8 = 'des-cfb8';
    const DES_ECB = 'des-ecb';
    const DES_EDE = 'des-ede';
    const DES_EDE_CBC = 'des-ede-cbc';
    const DES_EDE_CFB = 'des-ede-cfb';
    const DES_EDE_OFB = 'des-ede-ofb';
    const DES_EDE3 = 'des-ede3';
    const DES_EDE3_CBC = 'des-ede3-cbc';
    const DES_EDE3_CFB = 'des-ede3-cfb';
    const DES_EDE3_CFB1 = 'des-ede3-cfb1';
    const DES_EDE3_CFB8 = 'des-ede3-cfb8';
    const DES_EDE3_OFB = 'des-ede3-ofb';
    const DES_OFB = 'des-ofb';
    const DESX_CBC = 'desx-cbc';
    const GOST_28147_89 = 'gost 28147-89';
    const GOST89 = 'gost89';
    const GOST89_CNT = 'gost89-cnt';
    const ID_AES128_CCM = 'id-aes128-ccm';
    const ID_AES128_GCM = 'id-aes128-gcm';
    const ID_AES128_WRAP = 'id-aes128-wrap';
    const ID_AES192_CCM = 'id-aes192-ccm';
    const ID_AES192_GCM = 'id-aes192-gcm';
    const ID_AES192_WRAP = 'id-aes192-wrap';
    const ID_AES256_CCM = 'id-aes256-ccm';
    const ID_AES256_GCM = 'id-aes256-gcm';
    const ID_AES256_WRAP = 'id-aes256-wrap';
    const ID_SMIME_ALG_CMS3DESWRAP = 'id-smime-alg-cms3deswrap';
    const IDEA_CBC = 'idea-cbc';
    const IDEA_CFB = 'idea-cfb';
    const IDEA_ECB = 'idea-ecb';
    const IDEA_OFB = 'idea-ofb';
    const RC2_40_CBC = 'rc2-40-cbc';
    const RC2_64_CBC = 'rc2-64-cbc';
    const RC2_CBC = 'rc2-cbc';
    const RC2_CFB = 'rc2-cfb';
    const RC2_ECB = 'rc2-ecb';
    const RC2_OFB = 'rc2-ofb';
    const RC4 = 'rc4';
    const RC4_40 = 'rc4-40';
    const RC4_HMAC_MD5 = 'rc4-hmac-md5';
    const SEED_CBC = 'seed-cbc';
    const SEED_CFB = 'seed-cfb';
    const SEED_ECB = 'seed-ecb';
    const SEED_OFB = 'seed-ofb';

    /**
     * @var null|array List of the available methods or null if not initialized.
     */
    private static $availableMethods = null;

    /**
     * Verifies if the given method is available.
     *
     * @param string $method The method to check for.
     * @return bool Returns true if the method is available, false otherwise.
     * @since 0.1
     */
    public static function isAvailable(string $method) : bool
    {
        OpenSSL::isAvailable(true);
        return (in_array($method, self::allAvailable()));
    }

    /**
     * Gets all the supported cipher methods.
     *
     * @return array Returns a numerically indexed array containing the list of supported cipher methods.
     * @since 0.1
     */
    public static function allAvailable() : array
    {
        OpenSSL::isAvailable(true);
        if (self::$availableMethods === null) {
            self::$availableMethods = openssl_get_cipher_methods();
        }

        return self::$availableMethods;
    }
}