# Installation

To install the Sikker package using [Composer](http://getcomposer.org) use the following instructions (if you haven't read the [Composer Documentation](http://getcomposer.org/doc/) please do so before you continue):

1. Download composer if you haven't already done so (use your preferred method). Example:

   ```shell
   curl -s https://getcomposer.org/installer | php
   ```

2. Place a `require` statement inside your `composer.json` file and replace ```<version>``` with the desired version. Example:

   ```json
   {
      "require": {
         "NorseBlue/Sikker": "<version>"
      }
   }
   ```

3. Run composer update to resolve dependencies and download the packages. Example:

   ```shell
     php composer.phar update
   ```

4. In order to use the packages you have to include the autoloader that was generated by composer (if you are using a framework, chance are this is already done automatically). Example:

   ```php
   require "vendor/autoload.php";
   ```

5. Finally just use the package classes as needed. Example:

   ```php
   NorseBlue\Sikker\[<sub-namespace>\...]<class>::<function>(<params>);
   ```

   ​