#!/usr/bin/env php
<?php
declare(strict_types = 1);
init();

const JAIL_USERS = 100;
/** @var int $argc */
/** @var string[] $argv */

if (is_dir("/jail") || ($argc >= 2 && $argv[1] == "--uninstall")) {
    echo "removing pre-existing installation...";
    $commands = array(
        'umount /jail/bin',
        'umount /jail/lib',
        'umount /jail/lib64',
        'umount /jail/usr',
        'umount /jail/etc/alternatives',
        'umount /jail/etc/php',
        // 'umount /jail/etc/',
        // 'umount /jail/dev/pts',
        // 'umount /jail/dev',
        // 'sleep 100',
        'rm -rf /jail'
    );
    foreach ($commands as $command) {
        echo "executing: \"{$command}\".. ";
        $stdout = $stderr = "";
        $ret = my_shell_exec($command, "", $stdout, $stderr);
        if ($ret === 0 && empty($stdout) && empty($stderr)) {
            echo "ok.\n";
        } else {
            echo "{$ret} stdout:" . (return_var_dump($stdout)) . " - stderr: " . (return_var_dump($stdout)) . "\n";
        }
    }
    if (0) {
        echo "deleting jailuser{1-" . JAIL_USERS . "}\n";
        for ($i = 1; $i <= JAIL_USERS; ++ $i) {
            shell_exec("deluser jailuser{$i}");
        }
    }
    if (file_exists('/jail')) {
        throw new \LogicException('FAILED TO DELETE /jail');
    }
    echo "uninstall complete.\n";
    if ($argc >= 2 && $argv[1] == "--uninstall") {
        echo "thanks to --uninstall , that's all folks\n";
        exit(0);
    }
}

$commands = <<<'COMMANDS'
mkdir /jail /jail/bin /jail/lib /jail/lib64 /jail/usr /jail/etc /jail/etc/alternatives /jail/home /jail/tmp
#mkdir /jail/dev
mkdir /jail/etc/php
#everybody can execute
chmod -R 0711 /jail
#everybody can read and execute
chmod -R 0755 /jail/etc/php
# everybody can execute and write (but not read)
chmod -R 0733 /jail/tmp
chown -R root:root /jail
#mount -o bind,ro /dev /jail/dev
#mount -o bind,ro /dev/pts /jail/dev/pts
mount -o bind,ro /bin /jail/bin
mount -o bind,ro /lib /jail/lib
mount -o bind,ro /lib64 /jail/lib64
mount -o bind,ro /usr /jail/usr
#mount -o bind,ro /etc/ /jail/etc/
mount -o bind,ro /etc/php /jail/etc/php
mount -o bind,ro /etc/alternatives /jail/etc/alternatives
#adduser jailgroup
COMMANDS;
$commands = array_filter(array_map("trim", explode("\n", $commands)), function (string $str) {
    return ! (strlen($str) <= 0 || $str[0] === "#");
});

foreach ($commands as $command) {
    echo "executing: \"{$command}\".. ";
    $stdout = $stderr = "";
    $ret = my_shell_exec($command, "", $stdout, $stderr);
    if ($ret === 0 && empty($stdout) && empty($stderr)) {
        echo "ok.\n";
    } else {
        echo "{$ret} stdout: " . (return_var_dump($stdout)) . " - stderr: " . (return_var_dump($stderr)) . "\n";
    }
}
my_shell_exec("addgroup jailgroup");
echo "creating jailuser{0-" . JAIL_USERS . "}..";
for ($i = 1; $i <= JAIL_USERS; ++ $i) {
    // useradd --home /jailuser1 --shell /bin/false --gid jailgroup -M jailuser1
    shell_exec("useradd --home /home/jailuser{$i} --shell /bin/false --gid jailgroup -M jailuser{$i} 2>&1");
    mkdir("/jail/home/jailuser{$i}", 0700);
    chown("/jail/home/jailuser{$i}", "jailuser{$i}");
    chgrp("/jail/home/jailuser{$i}", "jailgroup");
}
echo "done!\n";
if (false) {
    // TODO: rewrite it in SQLite instead of json
    echo "now creating jailaccounts.db3..";
    call_user_func(function () {
        if (is_file("/jail/jailaccounts.db3")) {
            unlink("/jail/jailaccounts.db3");
        }
        $db = new \PDO('sqlite:/jail/jailaccounts.db3', '', '', array(
            \PDO::ATTR_EMULATE_PREPARES => false,
            \PDO::ATTR_ERRMODE => \PDO::ERRMODE_EXCEPTION
        ));
        $db->exec("CREATE TABLE jailaccounts (id INTEGER PRIMARY KEY, busy TINYINT(1), since TEXT);");
        $db->beginTransaction();
        $stm = $db->prepare("INSERT INTO jailaccounts (id,busy,since) VALUES(?,?,?);");
        for ($i = 1; $i <= JAIL_USERS; ++ $i) {
            $stm->execute(array(
                $i,
                0,
                date(DateTime::ATOM, 0) // 1970-01-01
            ));
        }
        $db->commit();
    });
    echo " done.\n";
}
echo "now creating jailaccounts.json..";
$db = [];
for ($i = 1; $i <= JAIL_USERS; ++ $i) {
    $db[$i] = [
        "busy" => false,
        "since" => date(DateTime::ATOM, 0)
    ];
}
file_put_contents("/jail/jailaccounts.json", json_encode($db), LOCK_EX);
echo " done.\n";
echo "creating /etc/sudoers.d/www-data-jailexecutor with >> www-data ALL = (root) NOPASSWD: /usr/bin/php /jail/jailexecutor.php..";
file_put_contents("/etc/sudoers.d/www-data-jailexecutor", "www-data ALL = (root) NOPASSWD: /usr/bin/php /jail/jailexecutor.php\n", LOCK_EX);
chmod('/etc/sudoers.d/www-data-jailexecutor', 0400);
echo " done.\n";
echo "copying jailexecutor.php to /jail..";
if (true !== copy("./jailexecutor.php", "/jail/jailexecutor.php")) {
    throw new \RuntimeException("FAILED TO COPY JAILEXECUTOR TO /jail/jailexecutor.php");
}
chmod("/jail/jailexecutor.php", 0400);
echo " done.\n";
echo "setup complete!\n";

function return_var_dump(): string
{
    $args = func_get_args();
    ob_start();
    call_user_func_array('var_dump', $args);
    return ob_get_clean();
}

function my_shell_exec(string $cmd, string $stdin = null, string &$stdout = null, string &$stderr = null): int
{
    // echo "executing \"{$cmd}\"...";
    // use a tmpfile in case stdout is so large that the pipe gets full before we read it, which would result in a deadlock.
    $stdout_handle = tmpfile();
    $stderr_handle = tmpfile();
    $descriptorspec = array(
        // stdin is *inherited* by default, so even if $stdin is empty, we should create a stdin pipe just so we can close it.
        0 => array(
            "pipe",
            "rb"
        ),
        1 => $stdout_handle,
        2 => $stderr_handle
    );
    $pipes = [];
    $proc = proc_open($cmd, $descriptorspec, $pipes);
    if (! $proc) {
        throw \RuntimeException("proc_exec failed!");
    }

    // TODO: fwrite returns < strlen($stdin) ?
    if (! is_null($stdin) && strlen($stdin) > 0) {
        fwrite($pipes[0], $stdin);
    }
    fclose($pipes[0]);
    $ret = proc_close($proc);
    rewind($stdout_handle); // stream_get_contents can seek but it has let me down earlier, https://bugs.php.net/bug.php?id=76268
    rewind($stderr_handle); //
    $stdout = stream_get_contents($stdout_handle);
    fclose($stdout_handle);
    $stderr = stream_get_contents($stderr_handle);
    fclose($stderr_handle);
    // echo "done!\n";
    return $ret;
}

function init()
{
    if (posix_getuid() !== 0) {
        echo ("only root can run this script!\n");
        exit(1);
    }
    hhb_init();
}

function hhb_init()
{
    static $firstrun = true;
    if ($firstrun !== true) {
        return;
    }
    $firstrun = false;
    error_reporting(E_ALL);
    set_error_handler("hhb_exception_error_handler");
    // ini_set("log_errors",'On');
    // ini_set("display_errors",'On');
    // ini_set("log_errors_max_len",'0');
    // ini_set("error_prepend_string",'<error>');
    // ini_set("error_append_string",'</error>'.PHP_EOL);
    // ini_set("error_log",__DIR__.DIRECTORY_SEPARATOR.'error_log.php.txt');
    assert_options(ASSERT_ACTIVE, 1);
    assert_options(ASSERT_WARNING, 0);
    assert_options(ASSERT_QUIET_EVAL, 1);
    assert_options(ASSERT_CALLBACK, 'hhb_assert_handler');
}

function hhb_exception_error_handler($errno, $errstr, $errfile, $errline)
{
    if (! (error_reporting() & $errno)) {
        // This error code is not included in error_reporting
        return;
    }
    throw new ErrorException($errstr, 0, $errno, $errfile, $errline);
}

function hhb_assert_handler($file, $line, $code, $desc = null)
{
    $errstr = 'Assertion failed at ' . $file . ':' . $line . ' ' . $desc . ' code: ' . $code;
    throw new ErrorException($errstr, 0, 1, $file, $line);
}
