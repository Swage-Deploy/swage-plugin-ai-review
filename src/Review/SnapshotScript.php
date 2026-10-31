<?php

namespace Swage\AiReview\Review;

use App\Models\Server;
use Illuminate\Support\Str;

/**
 * The script that reads a server for the review: how it is set up, how its resources are holding up, and what its
 * services' logs keep saying.
 *
 * It only reads. The AI never writes it or adds to it, and it never writes a file, changes a setting or restarts
 * anything, so the review cannot change the server. Keep it that way: tests check the script against the commands it
 * is allowed to run. Redis's password, which it needs to read Redis's figures, is handed to redis-cli in its
 * environment and never printed, so it never reaches the model.
 *
 * Logs are summarised on the server: repeated messages are counted once times and ids are taken out of them, so a
 * busy log doesn't crowd out the rest of the review, and whole log lines aren't sent where a count says enough.
 *
 * Its output holds text others can choose, such as account names and requested paths, so each section starts with a
 * marker made fresh for every run, which nothing on the server can know in advance.
 */
final readonly class SnapshotScript
{
    /**
     * The most of each section's output kept, so one noisy command can't crowd out the rest of the review.
     */
    public const int MAX_SECTION_BYTES = 6000;

    /**
     * The sections the script writes, and what each is called in the review.
     *
     * @var array<string, string>
     */
    public const array SECTIONS = [
        'os' => 'Operating system and kernel',
        'reboot-required' => 'Reboot required by updates',
        'updates' => 'Packages with pending updates',
        'auto-updates' => 'Automatic security updates',
        'resources' => 'CPU, load, memory, swap and kernel limits',
        'disk' => 'Disk space and inodes',
        'memory' => 'Memory by process',
        'oom-kills' => 'Out of memory kills in the last 7 days',
        'php-fpm' => 'PHP-FPM pools, settings and workers',
        'php-fpm-log' => 'PHP-FPM log',
        'nginx-config' => 'nginx settings',
        'nginx-log' => 'nginx error logs',
        'mysql' => 'MySQL settings and status',
        'mysql-log' => 'MySQL error log',
        'postgres' => 'PostgreSQL settings and status',
        'postgres-log' => 'PostgreSQL log',
        'redis' => 'Redis memory and status',
        'redis-log' => 'Redis log',
        'supervisor' => 'Supervisor programs',
        'failed-units' => 'Failed systemd units',
        'system-errors' => 'System journal errors in the last 24 hours',
        'sshd' => 'Effective SSH server settings',
        'listening' => 'Listening ports',
        'firewall' => 'Firewall (ufw) status',
        'accounts' => 'Accounts that can log in, and root equivalents',
        'passwords' => 'Accounts with a usable password',
        'authorized-keys' => 'Authorized SSH keys per account',
        'sudo' => 'Passwordless sudo rules',
        'logins' => 'Recent logins',
    ];

    public function __construct(public string $marker, public ?string $redisUser = null, public ?string $redisPassword = null) {}

    public static function make(Server $server): self
    {
        $marker = '@@SWAGE_REVIEW_'.Str::upper(Str::random(24));

        return $server->usesRedisAuthentication()
            ? new self($marker, (string) config('swage.user'), $server->redis_password)
            : new self($marker);
    }

    public function render(): string
    {
        return 'marker='.escapeshellarg($this->marker)."\n"
            .'redis_user='.escapeshellarg((string) $this->redisUser)."\n"
            .'redis_auth='.escapeshellarg((string) $this->redisPassword)."\n"
            .<<<'BASH'
        set -uo pipefail
        section() { printf '\n%s %s\n' "$marker" "$*"; }

        # Sections say "unavailable" when their command failed, "not installed" when the service isn't on the server,
        # and "none" when it ran and found nothing, so the review can tell a clean server from one it couldn't read.
        or_none() { local out; out=$(cat); if [ -n "$out" ]; then printf '%s\n' "$out"; else echo none; fi; }

        # Count a log's repeated messages: the lines matching the filter, once the sed expression has taken out what
        # differs between them, such as times and ids. Says how many files and lines it read and how the first one
        # starts, so the review knows how long the log covers. Rotated files come first.
        log_summary() {
            local filter=$1 strip=$2 f
            shift 2
            local files=()
            for f in "$@"; do [ -f "$f" ] && [ -r "$f" ] && files+=("$f"); done
            if [ ${#files[@]} -eq 0 ]; then echo 'no log'; return; fi
            printf 'read %s files, %s lines, starting: %.40s\n' "${#files[@]}" "$(cat "${files[@]}" | wc -l)" "$(head -n 1 "${files[0]}")"
            cat "${files[@]}" | grep -aE "$filter" | sed -E "$strip" | cut -c1-300 | sort | uniq -c | sort -rn | head -n 25 | or_none
        }

        section os
        { sed -n 's/^PRETTY_NAME=//p' /etc/os-release 2>/dev/null | tr -d '"'; uname -r; uptime -p 2>/dev/null; } | or_none

        section reboot-required
        if [ -f /var/run/reboot-required ]; then echo yes; cat /var/run/reboot-required.pkgs 2>/dev/null; else echo no; fi

        section updates
        if out=$(apt list --upgradable 2>/dev/null); then printf '%s\n' "$out" | grep -v '^Listing' | head -n 200 | or_none; else echo unavailable; fi

        section auto-updates
        if command -v systemctl > /dev/null; then
            echo "unattended-upgrades $(systemctl is-enabled unattended-upgrades 2>/dev/null || echo not-installed)"
            cat /etc/apt/apt.conf.d/20auto-upgrades 2>/dev/null
        else
            echo unavailable
        fi

        section resources
        if out=$(free -m 2>/dev/null); then
            echo "cpu cores: $(nproc 2>/dev/null)"
            echo "load average: $(cut -d ' ' -f 1-3 /proc/loadavg 2>/dev/null)"
            printf '%s\n' "$out"
            swapon --show 2>/dev/null
            sysctl vm.swappiness vm.overcommit_memory fs.file-max net.core.somaxconn 2>/dev/null
        else
            echo unavailable
        fi

        section disk
        if out=$(df -hP -x tmpfs -x devtmpfs -x squashfs -x overlay -x efivarfs 2>/dev/null); then
            printf '%s\n' "$out"
            df -iP -x tmpfs -x devtmpfs -x squashfs -x overlay -x efivarfs 2>/dev/null
            echo '-- largest in /var/log'
            du -sh /var/log/* 2>/dev/null | sort -rh | head -n 5
        else
            echo unavailable
        fi

        # Memory by command, adding up processes of the same name, such as every PHP-FPM worker.
        section memory
        if out=$(ps -eo rss=,comm= 2>/dev/null); then
            printf '%s\n' "$out" | awk '{ mb[$2] += $1 / 1024; n[$2]++ } END { for (c in mb) printf "%s %d processes %d MB\n", c, n[c], mb[c] }' | sort -k4 -rn | head -n 15 | or_none
        else
            echo unavailable
        fi

        section oom-kills
        if command -v journalctl > /dev/null; then
            journalctl -k --since '-7d' --no-pager -q -o short-iso 2>/dev/null | grep -aiE 'out of memory|oom-kill|killed process' | tail -n 20 | or_none
        else
            echo unavailable
        fi

        section php-fpm
        found=0
        for dir in /etc/php/*/fpm; do
            [ -d "$dir" ] || continue
            found=1
            version=$(basename "$(dirname "$dir")")
            echo "== PHP $version"
            echo '-- pools'
            for pool in "$dir"/pool.d/*.conf; do
                [ -r "$pool" ] || continue
                printf '%s: %s\n' "$(basename "$pool" .conf)" "$(grep -hE '^[[:space:]]*(pm|pm\.[a-z_]+|request_terminate_timeout|request_slowlog_timeout)[[:space:]]*=' "$pool" | tr -s ' ' | paste -sd ';' -)"
            done
            echo '-- php.ini'
            grep -hE '^[[:space:]]*(memory_limit|max_execution_time|upload_max_filesize|post_max_size|opcache\.(enable|memory_consumption|max_accelerated_files|validate_timestamps))[[:space:]]*=' "$dir/php.ini" "$dir"/conf.d/*.ini 2>/dev/null | tr -s ' '
            echo '-- workers'
            ps -C "php-fpm$version" -o rss=,args= 2>/dev/null | awk '{ pool = ($3 == "master") ? "master" : $NF; mb = $1 / 1024; total[pool] += mb; n[pool]++; if (largest[pool] < mb) largest[pool] = mb } END { for (p in n) printf "%s: %d processes, average %d MB, largest %d MB\n", p, n[p], total[p] / n[p], largest[p] }' | sort
        done
        [ "$found" = 1 ] || echo 'not installed'

        section php-fpm-log
        found=0
        for dir in /etc/php/*/fpm; do
            [ -d "$dir" ] || continue
            found=1
            version=$(basename "$(dirname "$dir")")
            echo "== PHP $version"
            log_summary 'WARNING|ERROR|ALERT' "s/^\[[^]]*\] //; s/child [0-9]+/child N/g; s/\([0-9.]+ sec\)/(N sec)/g; s/script '[^']*'/script/g" "/var/log/php$version-fpm.log.1" "/var/log/php$version-fpm.log"
        done
        [ "$found" = 1 ] || echo 'not installed'

        section nginx-config
        if [ -d /etc/nginx ]; then
            grep -hE '^[[:space:]]*(worker_processes|worker_connections|worker_rlimit_nofile|keepalive_timeout|client_max_body_size|fastcgi_read_timeout)[[:space:]]' /etc/nginx/nginx.conf /etc/nginx/conf.d/*.conf 2>/dev/null | tr -s ' ' | sort | uniq -c | or_none
        else
            echo 'not installed'
        fi

        section nginx-log
        if [ -d /etc/nginx ]; then
            log_summary '\[(warn|error|crit|alert|emerg)\]' 's/^[0-9\/]+ [0-9:]+ //; s/[0-9]+#[0-9]+: (\*[0-9]+ )?//; s/, (client|server|request|upstream|host|referrer): .*//; s/"[^"]*"/"…"/g' /var/log/nginx/*error.log.1 /var/log/nginx/*error.log
        else
            echo 'not installed'
        fi

        section mysql
        if command -v mysqld > /dev/null; then
            if out=$(mysql -N -B -e "SHOW GLOBAL VARIABLES WHERE Variable_name IN ('version', 'max_connections', 'innodb_buffer_pool_size', 'innodb_redo_log_capacity', 'tmp_table_size', 'max_heap_table_size', 'table_open_cache', 'performance_schema', 'slow_query_log', 'long_query_time', 'wait_timeout'); SHOW GLOBAL STATUS WHERE Variable_name IN ('Uptime', 'Max_used_connections', 'Max_used_connections_time', 'Threads_connected', 'Threads_running', 'Aborted_connects', 'Aborted_clients', 'Connection_errors_max_connections', 'Innodb_buffer_pool_read_requests', 'Innodb_buffer_pool_reads', 'Innodb_buffer_pool_wait_free', 'Created_tmp_tables', 'Created_tmp_disk_tables', 'Slow_queries', 'Table_open_cache_overflows', 'Innodb_row_lock_waits')" 2>/dev/null); then
                printf '%s\n' "$out" | or_none
            else
                echo unavailable
            fi
        else
            echo 'not installed'
        fi

        section mysql-log
        if command -v mysqld > /dev/null; then
            log_summary '\[(Warning|ERROR)\]' 's/^[0-9T:.Z+-]+ +[0-9]+ //' /var/log/mysql/error.log.1 /var/log/mysql/error.log
        else
            echo 'not installed'
        fi

        section postgres
        if [ -d /etc/postgresql ] && command -v psql > /dev/null; then
            if out=$(sudo -u postgres psql -X -tA -F ' ' -c "SELECT name, setting, coalesce(unit, '') FROM pg_settings WHERE name IN ('max_connections', 'shared_buffers', 'effective_cache_size', 'work_mem', 'maintenance_work_mem', 'max_wal_size')" -c "SELECT 'connections', count(*) FROM pg_stat_activity" -c "SELECT datname, numbackends, deadlocks, temp_files, temp_bytes, blks_hit, blks_read FROM pg_stat_database WHERE datname IS NOT NULL AND datname NOT LIKE 'template%'" 2>/dev/null); then
                printf '%s\n' "$out" | or_none
            else
                echo unavailable
            fi
        else
            echo 'not installed'
        fi

        section postgres-log
        if [ -d /etc/postgresql ]; then
            log_summary 'WARNING|ERROR|FATAL|PANIC' 's/^[0-9-]+ [0-9:.]+ [A-Z]+ \[[0-9]+\] //' /var/log/postgresql/postgresql-*-main.log.1 /var/log/postgresql/postgresql-*-main.log
        else
            echo 'not installed'
        fi

        # Sites authenticate to Redis as Swage's user. Its password goes to Redis's client in its environment, never on its
        # command line or in the output.
        section redis
        if command -v redis-cli > /dev/null; then
            out=$(if [ -n "$redis_auth" ]; then export REDISCLI_AUTH=$redis_auth; fi; redis-cli --no-auth-warning ${redis_user:+--user "$redis_user"} INFO 2>/dev/null | tr -d '\r')
            unset redis_auth
            if printf '%s\n' "$out" | grep -q '^redis_version:'; then
                printf '%s\n' "$out" | grep -E '^(redis_version|uptime_in_days|connected_clients|blocked_clients|used_memory_human|used_memory_peak_human|maxmemory_human|maxmemory_policy|mem_fragmentation_ratio|evicted_keys|expired_keys|rejected_connections|keyspace_hits|keyspace_misses|rdb_last_bgsave_status|aof_last_write_status|db[0-9]+):'
            else
                echo unavailable
            fi
        else
            echo 'not installed'
        fi

        section redis-log
        if command -v redis-cli > /dev/null; then
            log_summary ' # ' 's/^[0-9]+:[A-Z] [0-9]+ [A-Za-z]+ [0-9]+ [0-9:.]+ //' /var/log/redis/redis-server.log.1 /var/log/redis/redis-server.log
        else
            echo 'not installed'
        fi

        # It exits non-zero when any program isn't running, so its output is read either way.
        section supervisor
        if command -v supervisorctl > /dev/null; then
            out=$(supervisorctl status 2>/dev/null)
            if [ -n "$out" ]; then
                printf '%s\n' "$out" | awk '$2 == "RUNNING" { running++; next } { print } END { print running + 0, "programs running" }'
            else
                echo unavailable
            fi
        else
            echo 'not installed'
        fi

        section failed-units
        if command -v systemctl > /dev/null; then systemctl --failed --no-legend --plain 2>/dev/null | head -n 50 | or_none; else echo unavailable; fi

        # sshd's own errors are left out: they are attackers failing to connect, which the security scanner counts.
        section system-errors
        if command -v journalctl > /dev/null; then
            journalctl -p err --since '-24h' --no-pager -q -o short 2>/dev/null | sed -E 's/^[A-Za-z]+ +[0-9]+ [0-9:]+ [^ ]+ //; s/\[[0-9]+\]//' | grep -av '^sshd' | cut -c1-200 | sort | uniq -c | sort -rn | head -n 25 | or_none
        else
            echo unavailable
        fi

        section sshd
        if out=$(sshd -T 2>/dev/null); then
            printf '%s\n' "$out" | grep -Ei '^(port|listenaddress|permitrootlogin|passwordauthentication|kbdinteractiveauthentication|pubkeyauthentication|permitemptypasswords|authenticationmethods|maxauthtries|logingracetime|x11forwarding|allowtcpforwarding|allowagentforwarding|permittunnel|allowusers|allowgroups|denyusers|denygroups|clientaliveinterval|clientalivecountmax) ' | or_none
        else
            echo unavailable
        fi

        section listening
        if out=$(ss -H -tulpn 2>/dev/null); then printf '%s\n' "$out" | awk '{print $1, $5, $7}' | or_none; else echo unavailable; fi

        section firewall
        if ! command -v ufw > /dev/null; then echo 'not installed'; elif out=$(ufw status verbose 2>/dev/null); then printf '%s\n' "$out" | or_none; else echo unavailable; fi

        section accounts
        awk -F: '$3 == 0 || ($3 >= 1000 && $7 !~ /(nologin|false)$/) { print $1, "uid=" $3, $7 }' /etc/passwd | or_none

        # Only account names are printed, never the password hashes.
        section passwords
        if out=$(awk -F: '$2 == "" { print $1, "empty password" } $2 != "" && $2 !~ /^[!*]/ { print $1, "password set" }' /etc/shadow 2>/dev/null); then printf '%s\n' "$out" | or_none; else echo unavailable; fi

        section authorized-keys
        while IFS=: read -r name _ uid _ _ home _; do
            f="$home/.ssh/authorized_keys"
            [ -f "$f" ] && echo "$name $(grep -cvE '^[[:space:]]*(#|$)' "$f" 2>/dev/null) keys"
        done < /etc/passwd | or_none

        section sudo
        grep -rhE '^[^#]*NOPASSWD' /etc/sudoers /etc/sudoers.d 2>/dev/null | head -n 50 | or_none

        section logins
        if command -v last > /dev/null; then last -n 20 -i -w 2>/dev/null | grep -vE '^($|wtmp)' | or_none; else echo unavailable; fi

        section end
        BASH;
    }

    /**
     * The sections a snapshot lacks, or whose command failed, so the review could not see them. A service that isn't
     * installed isn't missing.
     *
     * @param  array<string, string>  $sections
     * @return list<string>
     */
    public static function missing(array $sections): array
    {
        return array_values(array_filter(
            array_keys(self::SECTIONS),
            fn (string $section): bool => in_array(trim($sections[$section] ?? ''), ['', 'unavailable'], true),
        ));
    }

    /**
     * Read the script's output into its sections, keyed by the names in SECTIONS.
     *
     * @return array<string, string>
     */
    public function parse(string $output): array
    {
        $sections = [];

        foreach (array_slice(explode("\n{$this->marker} ", "\n".$output), 1) as $section) {
            [$name, $content] = array_pad(explode("\n", $section, 2), 2, '');

            if (array_key_exists($name = trim($name), self::SECTIONS)) {
                $sections[$name] = mb_strcut(trim($content), 0, self::MAX_SECTION_BYTES);
            }
        }

        return $sections;
    }
}
