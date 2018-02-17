# php-security

https://infosec.mozilla.org/guidelines/web_security  

OWASP.org:  
https://www.owasp.org/index.php/PHP_Security_Cheat_Sheet  
https://www.owasp.org/index.php/PHP_Object_Injection  
https://www.owasp.org/index.php/Code_Injection  
https://www.owasp.org/index.php/PHP_Top_5  
https://www.owasp.org/index.php/PHP_CSRF_Guard  
https://www.owasp.org/index.php/PHP_Security_for_Developers  
https://www.owasp.org/index.php/OWASP_PHP_Security_Project  
https://www.owasp.org/images/6/6b/PHPMagicTricks-TypeJuggling.pdf  
https://www.owasp.org/index.php/PHP_Configuration_Cheat_Sheet  
https://www.owasp.org/index.php/PHP_Project_Authentication  

PHP.net:  
http://php.net/manual/en/session.security.php  
http://php.net/manual/en/security.php  
http://php.net/security-note.php  

Articles about attacks:  
https://blog.ripstech.com/2018/cubecart-admin-authentication-bypass/  
http://www.acros.si/papers/session_fixation.pdf  

TODO: proxy flag, directory/file exclude .inc  

## Headers

```
header("Referrer-Policy: no-referrer");
header("Strict-Transport-Security: max-age=63072000; includeSubDomains");
header("X-Content-Type-Options: nosniff");
header("X-Frame-Options: deny");
header("X-Permitted-Cross-Domain-Policies: none");
header("X-XSS-Protection: 1; mode=block");

header("Content-Security-Policy: script-src 'self'; object-src 'none'");
header("X-Content-Security-Policy: script-src 'self'; object-src 'none'");
header("X-WebKit-CSP: script-src 'self'; object-src 'none'");
```

## CSRF

CSRF tokens (one per user session) on state changes (POST, ...), maybe plus CAPTCHAs (user annoyance, I hate CAPTCHAs).  
```
$csrf_token = random_bytes(64);
hash_equals($token_from_session, $token_from_request);
```

## Session

Save and check IP address with session to prevent some hijacking.  
Maybe not to stay TOR compatible.  

TODO: referer/origin checking although they can be spoofed!

## Cookies

Deleting cookies safely:  
```
setcookie($name, "", 1);
setcookie($name, false);
unset($_COOKIE[$name]);
```

Setting cookies:
```
$expire = 0;
$path = "/application/path/";
$domain = "full.qualified.domain.name";
$secure = true;
$httponly = true;
setcookie($name, $value, $expire, $path, $domain, $secure, $httponly);
```

## Escaping

For HTML: ```htmlspecialchars($data, \ENT_QUOTES, $encoding);```  
For URL: ```urlencode($data);```

## Database

Many new attack vectors rely on encoding bypassing. Use UTF-8 as your database and application charset unless you have a mandatory requirement to use another encoding.  
Use PDO and prepared statements or stored procedures!  
Use whitelisting instead of black-listing for table/column/LIMIT specifiers!  
Don't rely on escaping input with mysql_real_escape_string or addslashes!
```
$whitelisted_limit = '10';
switch ($_GET['limit']) {
    case '20': $whitelisted_limit = '20'; break;
    case '30': $whitelisted_limit = '30'; break;
}
$sth = $dbh->prepare('SELECT name, colour FROM fruit WHERE colour = :colour LIMIT ' . $whitelisted_limit);
$sth->execute(array(':colour' => 'yellow'));
```
Set connection to blow up on errors, and not let the script keep going silently.
```
$dbh->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
```
or
```
$dbh = new PDO($dsn, $user, $password, array(PDO::ATTR_ERRMODE => PDO::ERRMODE_WARNING));
```

Hashing passwords:  
```password_hash($password, \PASSWORD_ARGON2I);```
or
```password_hash($password, \PASSWORD_BCRYPT);```  
Using the PASSWORD_BCRYPT as the algorithm, will result in the password parameter being truncated to a maximum length of 72 characters.

Check passwords:
```password_verify($password, $hash);```

Every now and then it is necessary to strengthen the hashing process.  
```password_needs_rehash($hash, \PASSWORD_ARGON2I);```  
or  
```password_needs_rehash($hash, \PASSWORD_BCRYPT);```  
Then prompt user to set a new password.

\PASSWORD_BCRYPT:
Save as CHAR(60)

\PASSWORD_ARGON2I:
Save as ??

\PASSWORD_DEFAULT:
255 is the recomended width


Never save credit card information!

## httpd.conf or .htaccess

```
<ifModule headers_module>
    Header set Referrer-Policy no-referrer
    Header set Strict-Transport-Security "max-age=63072000;includeSubDomains"
    Header set X-Content-Type-Options nosniff
    Header set X-Frame-Options deny
    Header set X-Permitted-Cross-Domain-Policies none
    Header set X-XSS-Protection "1; mode=block"

    Header set Content-Security-Policy "\
base-uri 'self';\
child-src 'none';\
connect-src 'self';\
default-src 'self';\
font-src 'self';\
form-action 'self';\
frame-ancestors 'none';\
frame-src 'none';\
img-src 'self';\
media-src 'self';\
object-src 'none';\
script-src 'self';\
style-src 'self'"
    Header set X-Content-Security-Policy "\
base-uri 'self';\
child-src 'none';\
connect-src 'self';\
default-src 'self';\
font-src 'self';\
form-action 'self';\
frame-ancestors 'none';\
frame-src 'none';\
img-src 'self';\
media-src 'self';\
object-src 'none';\
script-src 'self';\
style-src 'self'"
    Header set X-WebKit-CSP "\
base-uri 'self';\
child-src 'none';\
connect-src 'self';\
default-src 'self';\
font-src 'self';\
form-action 'self';\
frame-ancestors 'none';\
frame-src 'none';\
img-src 'self';\
media-src 'self';\
object-src 'none';\
script-src 'self';\
style-src 'self'"

    Header unset X-Powered-By
</ifModule>

<ifModule ModSecurity.c>
    SecServerSignature ''
</ifModule>

<IfModule rewrite_module>
    RewriteEngine On
    RewriteCond %{HTTPS} off
    RewriteRule ^ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]
</IfModule>
```

## httpd.conf

```
ServerSignature Off
ServerTokens Prod
```

## .htaccess
```
php_flag  allow_call_time_pass_reference Off
php_flag  allow_url_fopen        Off
php_flag  allow_url_include      Off
php_flag  allow_webdav_methods   Off
php_flag  asp_tags               Off
php_value default_socket_timeout 60
php_value disable_functions      "system, exec, shell_exec, passthru, phpinfo, show_source, popen, proc_open"
php_value disable_functions      "fopen_with_path, dbmopen, dbase_open, putenv, move_uploaded_file"
php_value disable_functions      "chdir, mkdir, rmdir, chmod, rename"
php_value disable_functions      "filepro, filepro_rowcount, filepro_retrieve, posix_mkfifo"
php_value disable_functions      "highlight_file, curl_exec, curl_multi_exec"
php_value disable_functions      "addslashes, mysql_escape_string, mysql_real_escape_string"
php_value disable_functions      "preg_replace, ini_set"
php_flag  display_errors         Off
php_flag  display_startup_errors Off
php_value error_reporting        -1
php_flag  expose_php             Off
php_flag  file_uploads           Off
php_flag  html_errors            Off
php_flag  ignore_repeated_errors Off
php_flag  ignore_repeated_source Off
php_flag  log_errors             On
php_flag  magic_quotes_gpc       Off
php_flag  magic_quotes_runtime   Off
php_flag  magic_quotes_sybase    Off
php_value max_execution_time     60
php_value memory_limit           32M
php_value post_max_size          32M
php_flag  register_argc_argv     Off
php_flag  register_globals       Off
php_flag  register_long_arrays   Off
php_flag  report_memleaks        On
php_value request_order          GP
php_flag  short_open_tag         Off
php_flag  track_errors           Off
php_value variables_order        GPCS
php_flag  y2k_compliance         On

php_flag  session.auto_start              Off
php_flag  session.bug_compat_42           Off
php_flag  session.bug_compat_warn         On
php_value session.cache_expire            30
php_value session.cache_limiter           nocache
php_value session.cookie_domain           full.qualified.domain.name
php_flag  session.cookie_httponly         On
php_value session.cookie_lifetime         0
php_value session.cookie_path             /application/path/
php_flag  session.cookie_secure           On
php_value session.hash_bits_per_character 6
php_value session.hash_function           1
php_value session.name                    myPHPSESSID
php_value session.referer_check           https://full.qualified.domain.name/application/path/
php_value session.sid_bits_per_character  6
php_value session.sid_length              48
#php_value session.trans_sid_tags
php_flag  session.use_cookies             On
php_flag  session.use_only_cookies        On
php_flag  session.use_strict_mode         On
php_flag  session.use_trans_sid           Off
```

## php.ini

```
[PHP]
allow_call_time_pass_reference = Off
allow_url_fopen        = Off
allow_url_include      = Off
allow_webdav_methods   = Off
asp_tags               = Off
default_socket_timeout = 60
disable_functions      = system, exec, shell_exec, passthru, phpinfo, show_source, popen, proc_open
disable_functions      = fopen_with_path, dbmopen, dbase_open, putenv, move_uploaded_file
disable_functions      = chdir, mkdir, rmdir, chmod, rename
disable_functions      = filepro, filepro_rowcount, filepro_retrieve, posix_mkfifo
disable_functions      = highlight_file, curl_exec, curl_multi_exec
disable_functions      = addslashes, mysql_escape_string, mysql_real_escape_string
disable_functions      = preg_replace, ini_set
display_errors         = Off
display_startup_errors = Off
doc_root               = /path/DocumentRoot/PHP-scripts/
enable_dl              = Off
error_reporting        = E_ALL
expose_php             = Off
file_uploads           = Off
html_errors            = Off
ignore_repeated_errors = Off
ignore_repeated_source = Off
log_errors             = On
magic_quotes_gpc       = Off
magic_quotes_runtime   = Off
magic_quotes_sybase    = Off
max_execution_time     = 60
memory_limit           = 32M
open_basedir           = /path/DocumentRoot/PHP-scripts/
post_max_size          = 32M
register_argc_argv     = Off
register_globals       = Off
register_long_arrays   = Off
report_memleaks        = On
request_order          = GP
short_open_tag         = Off
track_errors           = Off
variables_order        = GPCS
y2k_compliance         = On

[Session]
session.auto_start              = Off
session.bug_compat_42           = Off
session.bug_compat_warn         = On
session.cache_expire            = 30
session.cache_limiter           = nocache
session.cookie_domain           = full.qualified.domain.name
session.cookie_httponly         = On
session.cookie_lifetime         = 0
session.cookie_path             = /application/path/
session.cookie_secure           = On
session.hash_bits_per_character = 6
session.hash_function           = 1
session.name                    = myPHPSESSID
session.referer_check           = https://full.qualified.domain.name/application/path/
session.sid_bits_per_character  = 6
session.sid_length              = 48
session.trans_sid_tags          =
session.use_cookies             = On
session.use_only_cookies        = On
session.use_strict_mode         = On
session.use_trans_sid           = Off
```
