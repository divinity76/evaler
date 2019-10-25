<?php
declare(strict_types = 1);

$stdin="\x01"; // protocol version
$stdin.=to_little_uint32_t(strlen("{}"));
$stdin.="{}";
$stdin.="<?php echo 'hello world';fwrite(STDERR,123);";
$stdout="";
$stderr="";
$ret=my_shell_exec("php jailexecutor.php",$stdin,$stdout,$stderr);
echo '$ret: ';
var_dump($ret);
//var_dump($stdin);
echo '$stdout: ';
var_dump($stdout);
echo '$stderr: ';
var_dump($stderr);


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

function to_little_uint32_t(int $i): string {
    return pack ( 'V', $i );
}
function from_little_uint32_t(string $i): int {
    $arr = unpack ( 'Vuint32_t', $i );
    return $arr ['uint32_t'];
}
