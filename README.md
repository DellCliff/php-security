# php-security

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

CSRF tokens (one per user session) on state changes (POST, ...), maybe plus CAPTCHAs.  
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

## httpd.conf

```
<ifModule headers_module>  
    Header set Referrer-Policy no-referrer  
    Header set Strict-Transport-Security "max-age=63072000; includeSubDomains"  
    Header set X-Content-Type-Options nosniff  
    Header set X-Frame-Options deny  
    Header set X-Permitted-Cross-Domain-Policies none  
    Header set X-XSS-Protection "1; mode=block"  
    
    Header set Content-Security-Policy "script-src 'self'; object-src 'none'"  
    Header set X-Content-Security-Policy "script-src 'self'; object-src 'none'"  
    Header set X-WebKit-CSP "script-src 'self'; object-src 'none'"  
    
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

ServerSignature Off  
ServerTokens Prod  
```

TODO: proxy flag


## .htaccess
```
<ifModule mod_headers.c>  
    Header set Referrer-Policy no-referrer  
    Header set Strict-Transport-Security "max-age=63072000; includeSubDomains"  
    Header set X-Content-Type-Options nosniff  
    Header set X-Frame-Options deny  
    Header set X-Permitted-Cross-Domain-Policies none  
    Header set X-XSS-Protection "1; mode=block"  
    
    Header set Content-Security-Policy "script-src 'self'; object-src 'none'"  
    Header set X-Content-Security-Policy "script-src 'self'; object-src 'none'"  
    Header set X-WebKit-CSP "script-src 'self'; object-src 'none'"  
    
    Header unset X-Powered-By  
</ifModule>  

<ifModule ModSecurity.c>  
    SecServerSignature ''  
</ifModule>  

<ifModule mod_rewrite.c>  
    RewriteEngine On  
    RewriteCond %{HTTPS} off  
    RewriteRule ^ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]  
</ifModule>
```
TODO: proxy flag, maybe php_flag


## php.ini

```
allow_url_fopen        = Off  
allow_url_include      = Off  
allow_webdav_methods   = Off  
asp_tags               = Off  
default_socket_timeout = 60  

disable_functions = system, exec, shell_exec, passthru, phpinfo, show_source, popen, proc_open  
disable_functions = fopen_with_path, dbmopen, dbase_open, putenv, move_uploaded_file  
disable_functions = chdir, mkdir, rmdir, chmod, rename  
disable_functions = filepro, filepro_rowcount, filepro_retrieve, posix_mkfifo  
disable_functions = parse_ini_file, highlight_file, curl_exec, curl_multi_exec  
; Use prepared statements and whitelisted table/column/LIMIT specifiers!  
disable_functions = addslashes, mysql_escape_string, mysql_real_escape_string  
; preg_replace executes payload!  
disable_functions = preg_replace, ini_set  

display_errors         = Off  
display_startup_errors = Off  
doc_root               = /path/DocumentRoot/PHP-scripts/  
enable_dl              = Off  
error_reporting        = E_ALL  
expose_php             = Off  
file_uploads           = Off  
html_errors            = Off  
ignore_repeated_errors = Off  
log_errors             = On  
magic_quotes_gpc       = Off  
magic_quotes_runtime   = Off  
max_execution_time     = 60  
memory_limit           = 32M  
open_basedir           = /path/DocumentRoot/PHP-scripts/  
post_max_size          = 32M  
register_globals       = Off  
report_memleaks        = On  

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
; Referer can be spoofed!   
session.referer_check           = https://full.qualified.domain.name/application/path/  
session.sid_bits_per_character  = 6  
session.sid_length              = 48  
session.trans_sid_tags          =  
session.use_cookies             = On  
session.use_only_cookies        = On  
session.use_strict_mode         = On  
session.use_trans_sid           = Off  

short_open_tag  = Off  
track_errors    = Off  
variables_order = "GPSE"  
```
