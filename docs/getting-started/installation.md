# Installation

To install the Sikker package we recommend using [Composer](http://getcomposer.org). Use the following instructions (if you haven't read the [Composer Documentation](http://getcomposer.org/doc/) please do so before you continue):

Download composer if you haven't already done so (use your preferred method).

```bash
curl -s https://getcomposer.org/installer | php
```

Place a `require` statement inside your `composer.json` file and replace `<version>` with the desired [version](https://getcomposer.org/doc/articles/versions.md).

```json
{
   "require": {
      "NorseBlue/Sikker": "^0.3.5"
   }
}
```

Run composer update to resolve dependencies and download the packages.

```bash
php composer.phar update
```