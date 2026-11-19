/*
 * btwaf_ce Webshell 基础规则
 *
 * 仅用于本站插件的只读 Webshell 查杀，不随扫描上传文件内容。
 * 规则保持保守，避免把正常业务代码大面积标记为风险。
 */

rule webshell_php_eval_request
{
    meta:
        description = "PHP eval/assert 直接处理请求变量"
        severity = "high"
    strings:
        $eval = /\beval\s*\(/ nocase
        $assert = /\bassert\s*\(/ nocase
        $req = /\$_(GET|POST|REQUEST|COOKIE)\s*\[/ nocase
    condition:
        filesize < 2097152 and ($eval or $assert) and $req
}

rule webshell_php_base64_eval
{
    meta:
        description = "base64_decode 后执行"
        severity = "high"
    strings:
        $decode = /\bbase64_decode\s*\(/ nocase
        $exec = /(\beval|\bassert|\bcreate_function)\s*\(/ nocase
        $req = /\$_(GET|POST|REQUEST|COOKIE)\s*\[/ nocase
    condition:
        filesize < 2097152 and $decode and $exec and $req
}

rule webshell_php_gzinflate_eval
{
    meta:
        description = "gzinflate/gzuncompress 后执行"
        severity = "high"
    strings:
        $decode = /(\bgzinflate|\bgzuncompress|\bstr_rot13)\s*\(/ nocase
        $exec = /(\beval|\bassert)\s*\(/ nocase
        $req = /\$_(GET|POST|REQUEST|COOKIE)\s*\[/ nocase
    condition:
        filesize < 2097152 and $decode and $exec and $req
}

rule webshell_php_dangerous_request
{
    meta:
        description = "命令执行函数直接使用请求变量"
        severity = "high"
    strings:
        $danger = /(\bsystem|\bexec|\bshell_exec|\bpassthru|\bpopen|\bproc_open)\s*\(/ nocase
        $req = /\$_(GET|POST|REQUEST|COOKIE)\s*\[/ nocase
    condition:
        filesize < 2097152 and $danger and $req
}

rule webshell_php_variable_call_request
{
    meta:
        description = "变量函数调用结合请求变量"
        severity = "medium"
    strings:
        $call = /\$[A-Za-z_][A-Za-z0-9_]*\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)\s*\[/ nocase
    condition:
        filesize < 2097152 and $call
}

rule webshell_php_long_encoded_eval
{
    meta:
        description = "超长编码串参与执行"
        severity = "medium"
    strings:
        $blob = /[A-Za-z0-9+\/]{240,}={0,2}/
        $exec = /(\beval|\bassert|\bbase64_decode)\s*\(/ nocase
        $req = /\$_(GET|POST|REQUEST|COOKIE)\s*\[/ nocase
    condition:
        filesize < 2097152 and $blob and $exec and $req
}

rule webshell_php_assert_superglobal
{
    meta:
        description = "assert 直接使用外部输入"
        severity = "high"
    strings:
        $assert = /\bassert\s*\(/ nocase
        $input = /(\$_(GET|POST|REQUEST|COOKIE)|php:\/\/input)/ nocase
    condition:
        filesize < 2097152 and $assert and $input
}

