# php-security

## Headers

header("X-Frame-Options: deny");  
header("Strict-Transport-Security: max-age=63072000; includeSubDomains");  
header("X-Content-Type-Options: nosniff");  
header("X-XSS-Protection: 1; mode=block");  
header("Referrer-Policy: no-referrer");  
header("X-Permitted-Cross-Domain-Policies: none");  
header("Content-Security-Policy: script-src 'self'; object-src 'none'");  
header("X-WebKit-CSP: script-src 'self'; object-src 'none'");  
header("X-Content-Security-Policy: script-src 'self'; object-src 'none'");

## CSRF

CSRF tokens on state changes (POST, ...), maybe plus CAPTCHAs.  
$csrf_token = random_bytes(64);  
hash_equals($token_from_session, $token_from_request);

## Session

Save and check IP address with session to prevent hijacking.

## Cookies

Deleting cookies safely:  
setcookie ($name, "", 1);  
setcookie ($name, false);  
unset($_COOKIE[$name]);

Cookies: set http-only, secure, path, domain  
$secure = true;  
$httponly = true;  
setcookie($name, $value, $expire, $path, $domain, $secure, $httponly);

## Sanatizing

For HTML: htmlspecialchars($data, \ENT_QUOTES, $encoding);  
For URL: urlencode($data);

## Database

Many new attack vectors rely on encoding bypassing. Use UTF-8 as your database and application charset unless you have a mandatory requirement to use another encoding.  
Use PDO and prepared statements. Use white-listing instead of black-listing for table/column/LIMIT specifiers.  
Don't rely on escaping input with mysql_real_escape_string or addslashes!

## httpd.conf

ServerSignature Off  
ServerTokens Prod

## php.ini

expose_php              = Off
error_reporting         = E_ALL
display_errors          = Off
display_startup_errors  = Off
log_errors              = On
ignore_repeated_errors  = Off
allow_url_fopen         = Off
allow_url_include       = Off
variables_order         = "GPSE"
allow_webdav_methods    = Off
default_socket_timeout  = 60
magic_quotes_gpc        = Off
magic_quotes_runtime    = Off
register_globals        = 0

memory_limit            = 32M
post_max_size           = 32M
max_execution_time      = 60
report_memleaks         = On
track_errors            = Off
html_errors             = Off
short_open_tag          = Off
asp_tags                = Off

file_uploads            = Off

enable_dl               = Off
disable_functions       = system, exec, shell_exec, passthru, phpinfo, show_source, popen, proc_open
disable_functions       = fopen_with_path, dbmopen, dbase_open, putenv, move_uploaded_file
disable_functions       = chdir, mkdir, rmdir, chmod, rename
disable_functions       = filepro, filepro_rowcount, filepro_retrieve, posix_mkfifo
; Use prepared statements and white-listed table/column/LIMIT specifiers!
disable_functions       = addslashes, mysql_escape_string, mysql_real_escape_string
; preg_replace executes payload!
disable_functions       = preg_replace, ini_set

session.auto_start      = Off
session.name            = myPHPSESSID
session.hash_function   = 1
session.hash_bits_per_character = 6
session.use_trans_sid   = 0
session.cookie_domain   = full.qualified.domain.name
session.cookie_path     = /application/path/
session.cookie_lifetime = 0
session.cookie_secure   = On
session.cookie_httponly = 1
session.use_only_cookies= 1
session.cache_expire    = 30
session.use_strict_mode = 1
;session.referer_check   = /application/path
session.bug_compat_42 = 0
session.bug_compat_warn = 1
