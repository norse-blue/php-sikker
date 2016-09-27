# Usage

In order to use the packages you have to include the need files for them to be available in your script. We will be using composer for the examples.

You need to reference the autoloader that was generated (if you are using a framework, chances are this is already done automatically).

```php
require "path/to/vendor/autoload.php";
```

Finally just use the package classes as needed. Example:

```php
<?php
require "path/to/vendor/autoload.php";

use NorseBlue\Sikker\Hashes\Hasher;

$data = 'You know nothing Jon Snow!';
$hasher = new Hasher();
echo $hasher->hash($data);
```