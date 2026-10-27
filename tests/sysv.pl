# SysV IPC: shared memory, semaphores and message queues between processes.
use strict;
use warnings;
use IPC::SysV qw(IPC_PRIVATE SHM_RDONLY IPC_CREAT IPC_EXCL IPC_RMID IPC_NOWAIT IPC_STAT S_IRUSR S_IWUSR SETVAL GETVAL GETALL SETALL GETNCNT MSG_NOERROR);
use POSIX qw(EINTR EAGAIN EIDRM E2BIG ENOMSG EEXIST);
use Time::HiRes qw(time sleep);

my $fails = 0;
sub ok { my ($c, $what) = @_; print(($c ? "ok   " : "FAIL ") . "$what\n"); $fails++ unless $c; }

# Shared memory
my $m = shmget(IPC_PRIVATE, 8192, IPC_CREAT | 0600);
ok(defined $m, "shmget private");
ok(shmwrite($m, "hello", 0, 5), "shmwrite");
my $pid0 = fork;
if ($pid0 == 0) { shmwrite($m, "child", 100, 5); exit 0; }
waitpid $pid0, 0;
my $got;
shmread($m, $got, 100, 5);
ok($got eq "child", "a child's write is shared");
shmread($m, $got, 0, 5);
ok($got eq "hello", "shmread");
my $mds;
ok(shmctl($m, IPC_STAT, $mds) && length $mds > 0, "shmctl IPC_STAT");
ok(shmctl($m, IPC_RMID, 0), "shmctl IPC_RMID");

# Semaphores
my $s = semget(IPC_PRIVATE, 3, IPC_CREAT | 0600);
ok(defined $s, "semget private ($s)");
ok(semctl($s, 1, SETVAL, 5), "SETVAL");
ok(semctl($s, 1, GETVAL, 0) == 5, "GETVAL 5");
ok(semop($s, pack("s!3", 1, -2, 0)), "semop -2");
ok(semctl($s, 1, GETVAL, 0) == 3, "value 3");
ok(!semop($s, pack("s!3", 0, -1, IPC_NOWAIT)) && $! == EAGAIN, "NOWAIT on 0: EAGAIN");
# all or nothing: sem 2 can take -1? no (0), so sem 1 must stay 3
ok(!semop($s, pack("s!3s!3", 1, -1, 0, 2, -1, IPC_NOWAIT)) && semctl($s, 1, GETVAL, 0) == 3, "atomic: none applied");
# blocking across processes
my $t0 = time;
my $pid = fork;
if ($pid == 0) { sleep 0.3; semop($s, pack("s!3", 0, 1, 0)); exit 0; }
sleep 0.1;
my $n = semctl($s, 0, GETNCNT, 0);
ok(semop($s, pack("s!3", 0, -1, 0)), "blocking semop woke");
ok(time - $t0 >= 0.25, sprintf("waited %.2f s", time - $t0));
waitpid $pid, 0;
my $all = '';
semctl($s, 0, GETALL, $all);
ok(join(",", unpack("s!*", $all)) eq "0,3,0", "GETALL " . join(",", unpack("s!*", $all)));
semctl($s, 0, SETALL, pack("s!3", 1, 2, 3));
semctl($s, 0, GETALL, $all);
ok(join(",", unpack("s!*", $all)) eq "1,2,3", "SETALL");
# waiter woken by IPC_RMID
$pid = fork;
if ($pid == 0) { my $r = semop($s, pack("s!3", 2, -10, 0)); exit($r ? 1 : $! == EIDRM ? 0 : 2); }
sleep 0.2;
ok(semctl($s, 2, GETNCNT, 0) == 1, "GETNCNT 1");
ok(semctl($s, 0, IPC_RMID, 0), "IPC_RMID");
waitpid $pid, 0;
ok($? >> 8 == 0, "waiter got EIDRM (exit " . ($? >> 8) . ")");
ok(!defined semctl($s, 0, GETVAL, 0), "removed set gone");
# keyed
my $k = 0x5eed;
my $a = semget($k, 1, IPC_CREAT | 0600);
ok(defined $a && $a == $k, "keyed id = key");
ok(!defined semget($k, 1, IPC_CREAT | IPC_EXCL | 0600) && $! == EEXIST, "IPC_EXCL: EEXIST");
ok(semget($k, 0, 0) == $a, "find by key");
ok(!defined semget($k, 5, 0), "more sems than the set: EINVAL");
semctl($a, 0, IPC_RMID, 0);

# Message queues
my $q = msgget(IPC_PRIVATE, IPC_CREAT | 0600);
ok(defined $q, "msgget private");
msgsnd($q, pack("l! a*", 2, "two"), 0) or die "msgsnd: $!";
msgsnd($q, pack("l! a*", 1, "one"), 0) or die;
msgsnd($q, pack("l! a*", 3, "three"), 0) or die;
my $buf;
msgrcv($q, $buf, 100, 3, 0);
ok(substr($buf, 8) eq "three", "type 3 by type");
msgrcv($q, $buf, 100, -5, 0);
ok(substr($buf, 8) eq "one", "lowest type <= 5");
ok(!msgrcv($q, $buf, 1, 0, 0) && $! == E2BIG, "too small: E2BIG");
msgrcv($q, $buf, 1, 0, MSG_NOERROR);
ok(substr($buf, 8) eq "t", "MSG_NOERROR truncates");
ok(!msgrcv($q, $buf, 100, 0, IPC_NOWAIT) && $! == ENOMSG, "empty: ENOMSG");
$pid = fork;
if ($pid == 0) { sleep 0.3; msgsnd($q, pack("l! a*", 7, "late"), 0); exit 0; }
$t0 = time;
msgrcv($q, $buf, 100, 7, 0);
ok(substr($buf, 8) eq "late" && time - $t0 >= 0.25, "blocking msgrcv");
waitpid $pid, 0;
# fill the queue: blocks / EAGAIN
my $big = "x" x 8000;
msgsnd($q, pack("l! a*", 1, $big), 0) for 1 .. 2;
ok(!msgsnd($q, pack("l! a*", 1, $big), IPC_NOWAIT) && $! == EAGAIN, "full: EAGAIN");
my $ds;
msgctl($q, IPC_STAT, $ds);
ok(length $ds > 0, "IPC_STAT");
$pid = fork;
if ($pid == 0) { my $r = msgrcv($q, $buf, 100, 99, 0); exit($r ? 1 : $! == EIDRM ? 0 : 2); }
sleep 0.2;
msgctl($q, IPC_RMID, 0);
waitpid $pid, 0;
ok($? >> 8 == 0, "msgrcv waiter got EIDRM");


# A signal interrupts a blocked semop
my $e = semget(IPC_PRIVATE, 1, IPC_CREAT | 0600);
local $SIG{ALRM} = sub { };
alarm 1;
$t0 = time;
my $r = semop($e, pack("s!3", 0, -1, 0));
ok(!$r && $! == EINTR && time - $t0 < 3, "a signal: EINTR");
semctl($e, 0, IPC_RMID, 0);

print $fails ? "$fails FAILED\n" : "all passed\n";
exit($fails ? 1 : 0);
