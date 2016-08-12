<?php
/**
 * Created by PhpStorm.
 * User: APardemann
 * Date: 12/08/2016
 * Time: 12:35 PM
 */

namespace NorseBlue\Sikker\Symmetric\Ciphers;


class InitVector
{
    /**
     * Pads the given IV string  with \0 up to the block size.
     *
     * @param string $iv The initialization vector to pad.
     * @param int $blockSize The block size in bytes.
     * @return string Returns the padded string.
     */
    public static function pad(string $iv, int $blockSize = 16)
    {
        $padded = $iv;
        for ($i = (strlen($iv) % $blockSize); $i < $blockSize; $i += 2) {
            $padded .= '\0';
        }
        return $padded;
    }
}