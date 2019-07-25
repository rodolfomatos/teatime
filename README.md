# teatime
Adaptation of xWAF - Web Application Firewall to be used with composer.

# Sample Usage
```bash
composer require rodolfomatos/teatime:dev-master
```

# Including this project in Mautic
just add in app/autoload.php after:
```php
$loader = require __DIR__.'/../vendor/autoload.php';
```
the following:
```php
// Web Application Firewall
use rodolfomatos\teatime\cup;
$waf = new cup();
$waf->html_headers();
$waf->start();
//Done, Protection enabled.
```

# Other requisites
- www-data write access to /var/log/teatime.log
- 418.php available in html document root
```bash

```
