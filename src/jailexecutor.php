<?php
declare(strict_types = 1);

if (posix_geteuid() !== 0) {
    fprintf(STDERR, "this script must run as root (only root can chroot)\n");
    die();
}
if (! chdir("/jail")) {
    fprintf(STDERR, "failed to chdir to \"\jail\" !\n");
    die();
}

class Config
{

    // 8 megabytes, no particular reason for this default
    public static $output_max_bytes = 8 * 1024 * 1024;

    // -1 is "keep reading until EOF
    public static $code_byte_length = - 1;

    public static $runtime_max_seconds = 5;

    public static $stdin = "";

    public static $run_steps = array(
        '/usr/bin/env php %code_filename%'
    );

    public static $code_filename = "code.php";

    public static function init_from_json(string $json): void
    {
        $decoded = json_decode($json, true);
        foreach ($decoded as $prop => $val) {
            if (! property_exists("Config", $prop)) {
                throw new \InvalidArgumentException("unknown property \"{$prop}\"");
            }
            if ($prop === "code_filename") {
                if ($val !== basename($val)) {
                    throw new \LogicException("FIXME code_filename attempted directory traversal and/or absolute path! currently not supported..");
                }
                // TODO: more validation, does it include null bytes? is it over 100 characters long? etc
            }
            Config::$prop = $val;
        }
    }
}

$protocol_version = stream_get_contents(STDIN, 1);
if ($protocol_version !== "\x01") {
    // ..................................................
    die("protocol version error. supported 0x01, but got 0x" . bin2hex($protocol_version));
}
$config_json_length = from_little_uint32_t(stream_get_contents(STDIN, 4));
Config::init_from_json(stream_get_contents(STDIN, $config_json_length), true);
$code = stream_get_contents(STDIN, Config::$code_byte_length);
if (! is_string($code)) {
    throw new \RuntimeException('failed to read the code from stdin! (stream_get_contents failed)');
}
$jail_user = "jailuser" . get_jail_user();

$code_file = "/jail/home/{$jail_user}/" . Config::$code_filename;
@unlink($code_file);
if (strlen($code) !== file_put_contents($code_file, $code, LOCK_EX)) {
    throw new \RuntimeException('failed to write the code to disk! (out of diskspace?)');
}
if (! chmod($code_file, 0700)) {
    throw new \RuntimeException('failed to chmod! (0700)');
}
if (! chown($code_file, $jail_user)) {
    throw new \RuntimeException('failed to chown! (' . $jail_user . ')');
}
if (! chgrp($code_file, "jailgroup")) {
    throw new \RuntimeException('failed to chgrp! (jailgroup)');
}

$starttime = microtime(true);
$descriptorspec = array(
    0 => array(
        "pipe",
        "rb"
    ), // stdin, by default it is INHERITED from parent (us), we don't want that, so create one and close it.
    1 => array(
        "pipe",
        "wb"
    ), // stdout
    2 => array(
        "pipe",
        "wb"
    ) // stderr
);
$pipes = [];
// basically: chroot --userspec=jailuser123:jailgroup /jail /bin/sh -c 'cd /home/jailuser123; /usr/bin/env php code.php'
// real example: chroot --userspec='jailuser1':'jailgroup' '/jail' /bin/sh -c 'cd '\''/home/jailuser1'\''; /usr/bin/env php '\''code.php'\''; '
$chroot_cmd_inner = "";
$premature_optimization_code_filename = escapeshellarg(Config::$code_filename);
foreach (Config::$run_steps as $tmp) {
    $chroot_cmd_inner .= strtr($tmp, array(
        '%code_filename%' => $premature_optimization_code_filename
    )) . "; ";
}
unset($tmp, $premature_optimization_code_filename);
$chroot_cmd = implode(" ", array(
    'chroot',
    '--userspec=' . escapeshellarg($jail_user) . ":" . escapeshellarg("jailgroup"),
    escapeshellarg('/jail'),
    '/bin/sh -c ' . escapeshellarg(implode(" ", array(
        'cd ' . escapeshellarg("/home/{$jail_user}") . ";",
        $chroot_cmd_inner
    )))
));
var_dump("chroot cmd: ", $chroot_cmd) & die();
$ph = proc_open($chroot_cmd, $descriptorspec, $pipes);
if (false === $ph) {
    throw new RuntimeException("failed to start chroot!  cmd: {$chroot_cmd}");
}
if (strlen(Config::$stdin) > 0) {
    fwrite($pipes[0], Config::$stdin);
}
fclose($pipes[0]);
unset($pipes[0]);
$terminated = false; // < protection against running pkilltree() twice
                     // OPTIMIZE ME: use stream_select() or something instead of sleep-loop
$output_bytes = 0;
$proxy_out = function (bool &$output_max_bytes_exceeded = null) use (&$pipes, &$output_bytes): bool {
    $output_max_bytes_exceeded = ($output_bytes > Config::$output_max_bytes);
    if ($output_max_bytes_exceeded) {
        return false;
    }
    $max = 0xFFF;
    $ret = false;
    for ($i = 0; $i < $max; ++ $i) {
        $tmp = fread($pipes[1], 8 * 1024);
        if ($tmp === false || strlen($tmp) < 1) {
            break;
        }
        // var_dump("FROM STDOUT: {$tmp}");
        $ret = true;
        fwrite(STDOUT, $tmp);
        $output_bytes += strlen($tmp);
        $output_max_bytes_exceeded = ($output_bytes > Config::$output_max_bytes);
        if ($output_max_bytes_exceeded) {
            return false;
        }
    }
    for ($i = 0; $i < $max; ++ $i) {
        $tmp = fread($pipes[2], 8 * 1024);
        if ($tmp === false || strlen($tmp) < 1) {
            break;
        }
        // var_dump("FROM STDERR: {$tmp}");
        $ret = true;
        fwrite(STDERR, $tmp);
        $output_bytes += strlen($tmp);
        $output_max_bytes_exceeded = ($output_bytes > Config::$output_max_bytes);
        if ($output_max_bytes_exceeded) {
            return false;
        }
    }
    return $ret;
};

$output_max_bytes_exceeded = false;
while (($status = proc_get_status($ph))['running']) {
    usleep(100 * 1000); // *1000 = ms
    if (! $terminated && ((microtime(true) - $starttime) > Config::$runtime_max_seconds)) {
        $terminated = true;
        fwrite(STDERR, PHP_EOL . 'max runtime reached (' . (Config::$runtime_max_seconds) . ' seconds), terminating...');
        pkilltree((int) ($status['pid']));
        // proc_terminate ( $ph, SIGKILL );
    }
    $proxy_out($output_max_bytes_exceeded);
    if (! $terminated && $output_max_bytes_exceeded) {
        $terminated = true;
        pkilltree((int) ($status['pid']));
        // proc_terminate ( $ph, SIGKILL );
        fwrite(STDERR, PHP_EOL . 'max output bytes exceeded! (' . ((string) Config::$output_max_bytes) . "), terminating...");
    }
}
if (! $terminated) {
    // make sure descendants are killed, like in North Korea
    pkilltree((int) ($status['pid']));
}
while (false !== $proxy_out($output_max_bytes_exceeded));
if ($output_max_bytes_exceeded) {
    fwrite(STDERR, PHP_EOL . 'max output bytes exceeded! (' . ((string) Config::$output_max_bytes) . "), output probably truncated...");
}
// echo "\nexit status: " . $status['exitcode'];
proc_close($ph);
// now to clean up..
// find "/jail/home/jailuser123/" -mindepth 1 -delete | find /jail/tmp -user jailuser123 -delete
shell_exec("find " . escapeshellarg("/jail/home/{$jail_user}/") . " -mindepth 1 -delete | find " . escapeshellarg("/jail/tmp") . " -user " . escapeshellarg($jail_user) . " -delete");

exit($status['exitcode']);

// ...
function strsignal(int $signo): ?string
{
    foreach (get_defined_constants(true)['pcntl'] as $name => $num) {
        // the _ is to ignore SIG_IGN and SIG_DFL and SIG_ERR and SIG_BLOCK and SIG_UNBLOCK and SIG_SETMARK, and maybe more, who knows
        if ($num === $signo && substr($name, 0, 3) === "SIG" && $name[3] !== "_") {
            return $name;
        }
    }
    return null;
}

function get_jail_user(): int
{
    // TODO: rewrite it in SQLite + PDO rather than manual json db...
    static $cached = NULL;
    if ($cached !== NULL) {
        return $cached;
    }
    if (false === ($fp = fopen("jailaccounts.json", "r+b"))) {
        throw new \RuntimeException("failed to open jailaccounts.json!");
    }
    while (true) {
        if (true !== flock($fp, LOCK_EX)) {
            throw new \RuntimeException("failed to flock jaildb.txt! (LOCK_EX)");
        }
        $accounts = json_decode(stream_get_contents($fp), true);
        $found = null;
        foreach ($accounts as $accountnumber => $data) {
            if (! $data['busy']) {
                $found = $accountnumber;
                $cached = $found;
                break;
            }
        }
        if ($found !== null) {
            break;
        } else {
            // dammit, all accounts are busy, need to wait...
            error_log("all jail accounts are busy! need to wait... number of jail accounts: " . ((string) count($accounts)));
            flock($fp, LOCK_UN);
            rewind($fp);
            sleep(2); // dunno how long is sensible to wait before checking again...
            continue; // re-check if any acounts are available after finished sleeping..
        }
    }
    $accounts[$found]['busy'] = true;
    $accounts[$found]['since'] = date(DateTime::ATOM);
    rewind($fp);
    $new_data = json_encode($accounts);
    fwrite($fp, $new_data);
    ftruncate($fp, strlen($new_data));
    flock($fp, LOCK_UN);
    fclose($fp);
    unset($new_data);
    register_shutdown_function(function () use (&$cached) {
        if (false === ($fp = fopen("jailaccounts.json", "r+b"))) {
            throw new \RuntimeException("failed to open jailaccounts.json!");
        }
        if (true !== flock($fp, LOCK_EX)) {
            throw new \RuntimeException("failed to flock jaildb.txt! (LOCK_EX)");
        }
        $accounts = json_decode(stream_get_contents($fp), true);
        assert($accounts[$cached]['busy'] === true, "the account we assinged to ourself must be busy!");
        $accounts[$cached]['busy'] = false;
        $accounts[$cached]['since'] = date(DateTime::ATOM);
        rewind($fp);
        $new_data = json_encode($accounts);
        fwrite($fp, $new_data);
        ftruncate($fp, strlen($new_data));
        flock($fp, LOCK_UN);
        unset($new_data);
        fclose($fp);
    });
    return $cached;
}

function pkilltree(int $pid)
{
    shell_exec("kill -s STOP " . $pid . " 2>&1"); // stop it first, so it can't make any more children
    $children = shell_exec('pgrep -P ' . $pid);
    if (is_string($children)) {
        $children = trim($children);
    }
    if (! empty($children)) {
        $children = array_filter(array_map('trim', explode("\n", $children)), function ($in) {
            return false !== filter_var($in, FILTER_VALIDATE_INT); // shouldn't be necessary, but just to be safe..
        });
        foreach ($children as $child) {
            pkilltree((int) $child);
        }
    }
    shell_exec("kill -s KILL " . $pid . " 2>&1");
}

function to_little_uint32_t(int $i): string
{
    return pack('V', $i);
}

function from_little_uint32_t(string $i): int
{
    $arr = unpack('Vuint32_t', $i);
    return $arr['uint32_t'];
}
