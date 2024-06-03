// This code is licensed under the GPLv3. You can find its text here:
// https://www.gnu.org/licenses/gpl-3.0.en.html */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <pwd.h>
#include <sched.h>
#include <seccomp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/capability.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <linux/capability.h>
#include <linux/limits.h>


struct ctn_config {
    int argc;
    uid_t uid;
    int fd;
    char *hostname;
    char **argv;
    char *mount_dir;
};
// 1
int setup_mounts(struct ctn_config *config) {
    // 使用 MS_PRIVATE 重新挂载所有内容
    fprintf(stderr, "=> remounting everything with MS_PRIVATE...");
    /*
    int mount(const char *source, const char *target,
          const char *filesystemtype, unsigned long mountflags,
          const void *data);
    source: 源设备或目录。在这里传 NULL 表示不改变现有的源。
    target: 目标挂载点。在这里是根目录 /。
    filesystemtype: 文件系统类型。在这里传 NULL 表示不改变现有的文件系统类型。
    mountflags: 挂载标志。在这里是 MS_REC | MS_PRIVATE，表示递归地将挂载点及其所有子挂载点设置为私有。
    data: 额外的数据。在这里传 NULL 表示不使用任何额外数据
    这里传 NULL，因为我们不需要指定新的源设备或目录。mount 函数的这种调用方式用于修改现有挂载点的属性，而不是挂载新的文件系统。
    */
    if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL)) {
        fprintf(stderr, "failed! %m\n");
        return -1;
    }
    fprintf(stderr, "remounted.\n");

    // 创建一个临时目录，并在其中创建一个绑定挂载
    fprintf(stderr, "=> making a temp directory and a bind mount there...");
    char mount_dir[] = "/tmp/tmp.XXXXXX";
    if (!mkdtemp(mount_dir)) {
        fprintf(stderr, "failed making a directory!\n");
        return -1;
    }
    fprintf(stderr, "\n=> temp directory %s\n", mount_dir);

    // 在临时目录中创建绑定挂载
    if (mount(config->mount_dir, mount_dir, NULL, MS_BIND | MS_PRIVATE, NULL)) {
        fprintf(stderr, "bind mount failed!\n");
        return -1;
    }

    // 在临时目录中创建一个内部目录
    char inner_mount_dir[] = "/tmp/tmp.XXXXXX/oldroot.XXXXXX";
    memcpy(inner_mount_dir, mount_dir, sizeof(mount_dir) - 1);
    if (!mkdtemp(inner_mount_dir)) {
        fprintf(stderr, "failed making the inner directory!\n");
        return -1;
    }
    fprintf(stderr, "done.\n");

    // 切换根目录
    // SYS_pivot_root 是一个常见的系统调用，用于进程的根目录。mount_dir 是新的根目录，inner_mount_dir 新目录下的子目录，该系统调用会将原来进程的根目录挂载到此子目录中。
    // 同时，本来在该进程中看到的/tmp/tmp.XX/oldroot.xx 则在更改根路径之后变为了 /oldroot.xx
    fprintf(stderr, "=> pivoting root...");
    if (syscall(SYS_pivot_root, mount_dir, inner_mount_dir)) {
        fprintf(stderr, "failed!\n");
        return -1;
    }
    fprintf(stderr, "done.\n");

    // 获取旧的根目录路径
    char *old_root_dir = basename(inner_mount_dir);
    char old_root[sizeof(inner_mount_dir) + 1] = { "/" };
    strcpy(&old_root[1], old_root_dir);

    // 卸载旧的根目录
    fprintf(stderr, "=> unmounting %s...", old_root);
    if (chdir("/")) {
        fprintf(stderr, "chdir failed! %m\n");
        return -1;
    }
    // umount2 函数是 umount 函数的扩展版，它允许指定额外的标志来控制卸载行为。MNT_DETACH 分离挂载点，但不立即卸载。即在挂载点不再被任何进程使用时自动卸载
    if (umount2(old_root, MNT_DETACH)) {
        fprintf(stderr, "umount failed! %m\n");
        return -1;
    }
    if (rmdir(old_root)) {
        fprintf(stderr, "rmdir failed! %m\n");
        return -1;
    }
    fprintf(stderr, "done.\n");
    return 0;
}

int setup_userns(struct ctn_config *config) {
    // 尝试使用用户命名空间
    fprintf(stderr, "=> trying a user namespace...");
    // 判断是否支持用户命名空间
    int has_userns = !unshare(CLONE_NEWUSER);
    if (write(config->fd, &has_userns, sizeof(has_userns)) != sizeof(has_userns)) {
        // 写入结果失败
        fprintf(stderr, "couldn't write: %m\n");
        return -1;
    }
    int result = 0;
    if (read(config->fd, &result, sizeof(result)) != sizeof(result)) {
        // 读取结果失败
        fprintf(stderr, "couldn't read: %m\n");
        return -1;
    }
    if (result) return -1;
    if (has_userns) {
        // 用户命名空间设置成功
        fprintf(stderr, "done.\n");
    } else {
        // 用户命名空间不支持，继续执行
        fprintf(stderr, "unsupported? continuing.\n");
    }

    // 切换到指定用户ID和组ID
    fprintf(stderr, "=> switching to uid %d / gid %d...", config->uid, config->uid);
    if (setgroups(1, & (gid_t) { config->uid })) {
        // 设置组失败
        fprintf(stderr, "setgroups failed: %m\n");
        return -1;
    }
    if (setresgid(config->uid, config->uid, config->uid)) {
        // 设置有效组ID、实际组ID和保存组ID失败
        fprintf(stderr, "setresgid failed: %m\n");
        return -1;
    }
    if (setresuid(config->uid, config->uid, config->uid)) {
        // 设置有效用户ID、实际用户ID和保存用户ID失败
        fprintf(stderr, "setresuid failed: %m\n");
        return -1;
    }
    // 切换成功
    fprintf(stderr, "done.\n");
    return 0;
}

struct cgrp_control {
    char control[256];
    struct cgrp_setting {
        char name[256];
        char value[256];
    } **settings;
};
struct cgrp_setting add_to_tasks = {
    .name = "cgroup.procs",
    .value = "0"
};

struct cgrp_control *cgrps[] = {
    & (struct cgrp_control) {
        .control = "memory",
        .settings = (struct cgrp_setting *[]) {
            & (struct cgrp_setting) {
                .name = "memory.max",
                .value = "536870912"
            },
            /* & (struct cgrp_setting) { */
            /* 	.name = "memory.kmem.limit_in_bytes", */
            /* 	.value = "1073741824" */
            /* }, */
            &add_to_tasks,
            NULL
        }
    },
    & (struct cgrp_control) {
        .control = "cpu",
        .settings = (struct cgrp_setting *[]) {
            & (struct cgrp_setting) {
                .name = "cpu.max",
                .value = "300000 1000000" // CPU shares
            },
            &add_to_tasks,
            NULL
        }
    },
    & (struct cgrp_control) {
        .control = "pids",
        .settings = (struct cgrp_setting *[]) {
            & (struct cgrp_setting) {
                .name = "pids.max",
                .value = "64"
            },
            //&add_to_tasks,
            NULL
        }
    },
    /* & (struct cgrp_control) { */
    /* 	.control = "blkio", */
    /* 	.settings = (struct cgrp_setting *[]) { */
    /* 		& (struct cgrp_setting) { */
    /* 			.name = "blkio.weight", // not found in kernel 5.10+, 6.1+ */
    /* 			.value = "10" */
    /* 		}, */
    /* 		&add_to_tasks, */
    /* 		NULL */
    /* 	} */
    /* }, */
    NULL
};

// 递归创建目录函数，模拟 -p 选项的效果
int mkdir_p(const char *path) {
    // 如果目录已经存在，则返回成功
    struct stat st;
    if (stat(path, &st) == 0 && S_ISDIR(st.st_mode)) {
        return 0;
    }
    
    // 递归创建父目录
    char *sep = strrchr(path, '/');
    if (sep != NULL) {
        *sep = '\0'; // 截断字符串，将路径分隔符替换为字符串结束符
        if (mkdir_p(path) != 0) {
            return -1;
        }
        *sep = '/'; // 恢复路径分隔符
    }
    
    // 创建当前目录
    if (mkdir(path, S_IRUSR | S_IWUSR | S_IXUSR) != 0) {
        return -1;
    }
    
    return 0;
}

int setup_cgroups(struct ctn_config *config) {
    fprintf(stderr, "=> setting cgroups...");
    for (struct cgrp_control **cgrp = cgrps; *cgrp; cgrp++) {
        char dir[PATH_MAX] = {0};
        fprintf(stderr, "%s...", (*cgrp)->control);
        if (snprintf(dir, sizeof(dir), "/sys/fs/cgroup/system.slice/%s",
                    config->hostname) == -1) {
            return -1;
        }
        // 如果目录已经存在，则返回成功
        struct stat st;
        if (!(stat(dir, &st) == 0 && S_ISDIR(st.st_mode))) {
            if (mkdir(dir, S_IRUSR | S_IWUSR | S_IXUSR)) {
                fprintf(stderr, "mkdir %s failed: %m\n", dir);
                return -1;
            }
        }

        for (struct cgrp_setting **setting = (*cgrp)->settings; *setting; setting++) {
            char path[PATH_MAX] = {0};
            int fd = 0;
            struct stat st;
            if (snprintf(path, sizeof(path), "%s/%s", dir,
                        (*setting)->name) == -1) {
                fprintf(stderr, "snprintf failed: %m\n");
                return -1;
            }
            if ((fd = open(path, O_WRONLY | O_CREAT)) == -1) {
                fprintf(stderr, "opening %s failed: %m\n", path);
                return -1;
            }
            if (write(fd, (*setting)->value, strlen((*setting)->value)) == -1) {
                fprintf(stderr, "writing to %s failed: %m\n", path);
                close(fd);
                return -1;
            }
            close(fd);
        }
    }
    fprintf(stderr, "done.\n");
    fprintf(stderr, "=> setting rlimit...");
    if (setrlimit(RLIMIT_NOFILE, & (struct rlimit) {.rlim_max = 64, .rlim_cur = 64,})) {
        fprintf(stderr, "failed: %m\n");
        return 1;
    }
    fprintf(stderr, "done.\n");
    return 0;
}

int cleanup_cgroups(struct ctn_config *config) {
    fprintf(stderr, "=> cleaning cgroups...");
    for (struct cgrp_control **cgrp = cgrps; *cgrp; cgrp++) {
        char dir[PATH_MAX] = {0};
        char task[PATH_MAX] = {0};
        int task_fd = 0;
        if (snprintf(dir, sizeof(dir), "/sys/fs/cgroup/%s/%s",
                    (*cgrp)->control, config->hostname) == -1
                || snprintf(task, sizeof(task), "/sys/fs/cgroup/system.slice/%s/cgroup.procs",
                    config->hostname) == -1) {
            fprintf(stderr, "snprintf failed: %m\n");
            return -1;
        }
        if ((task_fd = open(task, O_WRONLY)) == -1) {
            fprintf(stderr, "opening %s failed: %m\n", task);
            return -1;
        }
        if (write(task_fd, "0", 2) == -1) {
            fprintf(stderr, "writing to %s failed: %m\n", task);
            close(task_fd);
            return -1;
        }
        close(task_fd);
        if (rmdir(dir)) {
            fprintf(stderr, "rmdir %s failed: %m", dir);
            return -1;
        }
    }
    fprintf(stderr, "done.\n");
    return 0;
}

int setup_capabilities() {
    // 输出日志信息，表示正在丢弃能力
    fprintf(stderr, "=> dropping capabilities...");
    // 定义要丢弃的能力数组
    int drop_caps[] = {
        CAP_AUDIT_CONTROL,  // 控制审计子系统，包括启动/停止审计、读取/写入审计配置等
        CAP_AUDIT_READ,     // 允许读取审计记录（用于非 root 用户查看审计日志）
        CAP_AUDIT_WRITE,    // 允许将用户生成的消息写入审计日志
        CAP_BLOCK_SUSPEND,  // 允许使用实时唤醒机制，阻止系统挂起
        CAP_DAC_READ_SEARCH,// 忽略文件和目录的读/搜索权限检查（主要用于备份工具和反病毒软件）
        CAP_FSETID,         // 允许设置文件系统 ID 位（如 set-user-ID 和 set-group-ID 位）
        CAP_IPC_LOCK,       // 允许锁定内存中的进程间通信（IPC）资源，防止交换到磁盘
        CAP_MAC_ADMIN,      // 允许配置和管理强制访问控制（MAC）策略
        CAP_MAC_OVERRIDE,   // 允许覆盖强制访问控制（MAC）策略检查
        CAP_MKNOD,          // 允许创建特殊文件（如设备文件）
        CAP_SETFCAP,        // 允许设置文件能力（file capabilities）
        CAP_SYSLOG,         // 允许执行 syslog 系统调用以配置日志记录行为
        CAP_SYS_ADMIN,      // 广泛的系统管理权限，包括挂载文件系统、改变系统参数等
        CAP_SYS_BOOT,       // 允许执行系统重启操作
        CAP_SYS_MODULE,     // 允许插入和移除内核模块
        CAP_SYS_NICE,       // 允许改变进程的优先级和调度策略
        CAP_SYS_RAWIO,      // 允许直接访问硬件设备
        CAP_SYS_RESOURCE,   // 允许超过通常的资源限制（如内存、CPU 等）
        CAP_SYS_TIME,       // 允许更改系统时钟
        CAP_WAKE_ALARM      // 允许设置系统唤醒闹钟
    };
    // 计算能力数组的大小
    size_t num_caps = sizeof(drop_caps) / sizeof(*drop_caps);
    // 输出日志信息，表示正在设置边界
    fprintf(stderr, "bounding...");
    // 遍历能力数组，丢弃每个能力
    for (size_t i = 0; i < num_caps; i++) {
        if (prctl(PR_CAPBSET_DROP, drop_caps[i], 0, 0, 0)) {
            // 如果丢弃失败，则输出错误信息
            fprintf(stderr, "prctl failed: %m\n");
            return 1;
        }
    }
    // 输出日志信息，表示正在设置可继承能力
    fprintf(stderr, "inheritable...");
    // 获取当前进程的能力集合
    cap_t caps = NULL;
    if (!(caps = cap_get_proc())
            // 清除指定能力的可继承标志
            || cap_set_flag(caps, CAP_INHERITABLE, num_caps, drop_caps, CAP_CLEAR)
            // 设置当前进程的能力集合
            || cap_set_proc(caps)) {
        // 如果设置失败，则输出错误信息
        fprintf(stderr, "failed: %m\n");
        // 释放能力集合
        if (caps) cap_free(caps);
        return 1;
    }
    // 释放能力集合
    cap_free(caps);
    // 输出日志信息，表示设置完成
    fprintf(stderr, "done.\n");
    return 0;
}

#define SCMP_FAIL SCMP_ACT_ERRNO(EPERM)

/*
这段代码定义了一个名为 setup_seccomp 的函数，它用于设置 Linux 系统的 seccomp 安全策略。
seccomp（安全计算模式）是 Linux 内核的一个功能，允许用户空间程序限制其可以调用的系统调用。
使用 seccomp 工具来添加一系列安全规则，以限制和阻止特定的系统调用及其参数。这些规则的目的主要是增强系统的安全性，防止一些潜在的危险操作
这对于提高程序的安全性非常有用，因为它可以防止程序执行可能具有潜在危险的系统调用。
*/
int setup_seccomp() {
    scmp_filter_ctx ctx = NULL;
    fprintf(stderr, "=> filtering syscalls...");
     // 创建 seccomp 过滤器上下文 默认所有系统调用
    if (!(ctx = seccomp_init(SCMP_ACT_ALLOW))
            || seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(chmod), 1, SCMP_A1(SCMP_CMP_MASKED_EQ, S_ISUID, S_ISUID)) 
            // 添加规则，阻止设置 S_ISUID 位的 chmod 调用
            || seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(chmod), 1, SCMP_A1(SCMP_CMP_MASKED_EQ, S_ISGID, S_ISGID)) 
            // 添加规则，阻止设置 S_ISGID 位的 chmod 调用
            || seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(fchmod), 1, SCMP_A1(SCMP_CMP_MASKED_EQ, S_ISUID, S_ISUID)) 
            // 添加规则，阻止设置 S_ISUID 位的 fchmod 调用
            || seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(fchmod), 1, SCMP_A1(SCMP_CMP_MASKED_EQ, S_ISGID, S_ISGID)) 
            // 添加规则，阻止设置 S_ISGID 位的 fchmod 调用
            || seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(fchmodat), 1, SCMP_A2(SCMP_CMP_MASKED_EQ, S_ISUID, S_ISUID)) 
            // 添加规则，阻止设置 S_ISUID 位的 fchmodat 调用
            || seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(fchmodat), 1, SCMP_A2(SCMP_CMP_MASKED_EQ, S_ISGID, S_ISGID)) 
            // 添加规则，阻止设置 S_ISGID 位的 fchmodat 调用
            || seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(unshare), 1, SCMP_A0(SCMP_CMP_MASKED_EQ, CLONE_NEWUSER, CLONE_NEWUSER)) 
            // 添加规则，阻止创建新用户命名空间的 unshare 调用
            || seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(clone), 1, SCMP_A0(SCMP_CMP_MASKED_EQ, CLONE_NEWUSER, CLONE_NEWUSER)) 
            // 添加规则，阻止创建新用户命名空间的 clone 调用
            || seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(ioctl), 1, SCMP_A1(SCMP_CMP_MASKED_EQ, TIOCSTI, TIOCSTI)) 
            // 添加规则，阻止传递 TIOCSTI 命令的 ioctl 调用
            || seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(keyctl), 0) 
            // 添加规则，完全阻止 keyctl 调用
            || seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(add_key), 0) 
            // 添加规则，完全阻止 add_key 调用
            || seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(request_key), 0) 
            // 添加规则，完全阻止 request_key 调用
            || seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(ptrace), 0) 
            // 添加规则，完全阻止 ptrace 调用
            || seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(mbind), 0) 
            // 添加规则，完全阻止 mbind 调用
            || seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(migrate_pages), 0) 
            // 添加规则，完全阻止 migrate_pages 调用
            || seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(move_pages), 0) 
            // 添加规则，完全阻止 move_pages 调用
            || seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(set_mempolicy), 0) 
            // 添加规则，完全阻止 set_mempolicy 调用
            || seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(userfaultfd), 0) 
            // 添加规则，完全阻止 userfaultfd 调用
            || seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(perf_event_open), 0) 
            // 添加规则，完全阻止 perf_event_open 调用
            || seccomp_attr_set(ctx, SCMP_FLTATR_CTL_NNP, 0) 
            // 设置 seccomp 过滤器属性，要求在过滤器加载后禁止新的特权 (No New Privileges)
            || seccomp_load(ctx)) {
                if (ctx) seccomp_release(ctx);
                fprintf(stderr, "failed: %m\n");
                return 1;
            }
    seccomp_release(ctx);
    fprintf(stderr, "done.\n");
    return 0;
}

int child(void *arg) {
    // 将参数转换为结构体指针
    struct ctn_config *config = arg;

    // 设置主机名
    if (sethostname(config->hostname, strlen(config->hostname))
            // 设置挂载点
            || setup_mounts(config)
            // 设置用户命名空间
            || setup_userns(config)
            // 设置能力集
            || setup_capabilities()
            // 设置安全计算模式
            || setup_seccomp()) {
        // 关闭文件描述符
        close(config->fd);
        // 返回错误码
        return -1;
    }

    // 关闭文件描述符
    if (close(config->fd)) {
        // 输出错误信息
        fprintf(stderr, "close failed: %m\n");
        // 返回错误码
        return -1;
    }

    // 执行指定的程序
    if (execve(config->argv[0], config->argv, NULL)) {
        // 输出错误信息
        fprintf(stderr, "execve failed! %m.\n");
        // 返回错误码
        return -1;
    }

    // 执行成功，返回0
    return 0;
}

int gen_hostname(char *buff, size_t len) {
    static const char *suits[] = { "swords", "wands", "pentacles", "cups" };
    static const char *minor[] = {
        "ace", "two", "three", "four", "five", "six", "seven", "eight",
        "nine", "ten", "page", "knight", "queen", "king"
    };
    static const char *major[] = {
        "fool", "magician", "high-priestess", "empress", "emperor",
        "hierophant", "lovers", "chariot", "strength", "hermit",
        "wheel", "justice", "hanged-man", "death", "temperance",
        "devil", "tower", "star", "moon", "sun", "judgment", "world"
    };
    snprintf(buff, len, "%05d-%s", 0, major[0]);
    return 0;
    struct timespec now = {0};
    clock_gettime(CLOCK_MONOTONIC, &now);
    size_t ix = now.tv_nsec % 78;
    if (ix < sizeof(major) / sizeof(*major)) {
        snprintf(buff, len, "%05lx-%s", now.tv_sec, major[ix]);
    } else {
        ix -= sizeof(major) / sizeof(*major);
        snprintf(buff, len,
                "%05lxc-%s-of-%s",
                now.tv_sec,
                minor[ix % (sizeof(minor) / sizeof(*minor))],
                suits[ix / (sizeof(minor) / sizeof(*minor))]);
    }
    return 0;
}

#define USERNS_OFFSET 10000
#define USERNS_COUNT 2000

int handle_child_uid_map (pid_t child_pid, int fd) {
    int uid_map = 0;
    int has_userns = -1;
    if (read(fd, &has_userns, sizeof(has_userns)) != sizeof(has_userns)) {
        fprintf(stderr, "couldn't read from child!\n");
        return -1;
    }
    if (has_userns) {
        char path[PATH_MAX] = {0};
        for (char **file = (char *[]) { "uid_map", "gid_map", 0 }; *file; file++) {
            if (snprintf(path, sizeof(path), "/proc/%d/%s", child_pid, *file)
                    > sizeof(path)) {
                fprintf(stderr, "snprintf too big? %m\n");
                return -1;
            }
            fprintf(stderr, "writing %s...", path);
            if ((uid_map = open(path, O_WRONLY)) == -1) {
                fprintf(stderr, "open failed: %m\n");
                return -1;
            }
            if (dprintf(uid_map, "0 %d %d\n", USERNS_OFFSET, USERNS_COUNT) == -1) {
                fprintf(stderr, "dprintf failed: %m\n");
                close(uid_map);
                return -1;
            }
            close(uid_map);
        }
    }
    if (write(fd, & (int) { 0 }, sizeof(int)) != sizeof(int)) {
        fprintf(stderr, "couldn't write: %m\n");
        return -1;
    }
    return 0;
}

int main (int argc, char **argv) {
    // 创建一个配置结构体，用于保存参数
    struct ctn_config config = {0};
    int err = 0;
    // 解析命令行参数
    int option = 0;
    // 用于主进程和子进程的通讯socket
    int sockets[2] = {0};
    // 用于子进程的pid
    pid_t child_pid = 0;
    // 解析参数用的临时变量
    int last_optind = 0;

    //////////////////////////////////////////////////////////////////////////
    // Step 1: parse CLI parameters, validate Linux kernel/cpu/..., generate hostname for container
    //////////////////////////////////////////////////////////////////////////
    while ((option = getopt(argc, argv, "c:m:u:"))) {
        switch (option) {
            case 'c':
                // 解析子进程的argc 和argv 参数
                config.argc = argc - last_optind - 1;
                config.argv = &argv[argc - config.argc];
                goto finish_options;
            case 'm':
                // 解析到子进程的挂载目录
                config.mount_dir = optarg;
                break;
            case 'u':
                // 解析到子进程的uid
                if (sscanf(optarg, "%d", &config.uid) != 1) {
                    fprintf(stderr, "invalid uid: %s\n", optarg);
                    goto usage;
                }
                break;
            default:
                goto usage;
        }
        last_optind = optind;
    }
// 完成参数解析
finish_options:
    if (!config.argc) goto usage;
    if (!config.mount_dir) goto usage;

    fprintf(stderr, "=> validating Linux version...");
    // 获取host 信息
    struct utsname host = {0};
    if (uname(&host)) {
        fprintf(stderr, "failed: %m\n");
        goto cleanup;
    }
    // 验证linux版本 6.5 or 6.0
    int major = -1;
    int minor = -1;
    if (sscanf(host.release, "%u.%u.", &major, &minor) != 2) {
        fprintf(stderr, "weird release format: %s\n", host.release);
        goto cleanup;
    }
    if (major != 6 || (minor != 5 && minor != 0)) {
        fprintf(stderr, "expected 6.x: %s\n", host.release);
        goto cleanup;
    }
    // 判断是否为x86_64架构
    if (strcmp("x86_64", host.machine)) {
        fprintf(stderr, "expected x86_64: %s\n", host.machine);
        goto cleanup;
    }
    fprintf(stderr, "%s on %s.\n", host.release, host.machine);

    fprintf(stderr, "=> generating hostname for container ... ");
    // 生成一个随机的hostname 在子进程中使用
    char ctn_hostname[256] = {0};
    if (gen_hostname(ctn_hostname, sizeof(ctn_hostname)))
        goto error;
    config.hostname = ctn_hostname;
    fprintf(stderr, "%s done\n", ctn_hostname);

    //////////////////////////////////////////////////////////////////////////
    // Step 2: setup a socket pair for container sending messages to the parent process
    //////////////////////////////////////////////////////////////////////////
    // 创建一对socket 用于父子进程通信
    if (socketpair(AF_LOCAL, SOCK_SEQPACKET, 0, sockets)) {
        fprintf(stderr, "socketpair failed: %m\n");
        goto error;
    }
    // 给socket设置FD_CLOEXEC 属性
    if (fcntl(sockets[0], F_SETFD, FD_CLOEXEC)) {
        fprintf(stderr, "fcntl failed: %m\n");
        goto error;
    }
    config.fd = sockets[1];

    ///////////////////////////////////////////////////////////////////////
    // Step 3: allocate stack space for `execve()`
    ///////////////////////////////////////////////////////////////////////
#define STACK_SIZE (1024 * 1024)
    char *stack = 0;
    if (!(stack = malloc(STACK_SIZE))) {
        fprintf(stderr, "=> malloc failed, out of memory?\n");
        goto error;
    }

    ///////////////////////////////////////////////////////////////////////
    // Step 4: setup cgroup for the container for resource isolation
    ///////////////////////////////////////////////////////////////////////
    if (setup_cgroups(&config)) {
        err = 1;
        goto clear_resources;
    }

    ///////////////////////////////////////////////////////////////////////
    // Step 5: launch container
    ///////////////////////////////////////////////////////////////////////
    int flags = CLONE_NEWNS | CLONE_NEWCGROUP | CLONE_NEWPID | CLONE_NEWIPC | CLONE_NEWNET | CLONE_NEWUTS;
    // 子进程会继承父进程的文件描述符，因为文件描述符在整个进程中都是共享的。所以子进程在执行exec 之后由于sockets[0]设置了
    // FD_CLOEXEC，索引 sockets[0] 会被关闭。
    if ((child_pid = clone(child, stack + STACK_SIZE, flags | SIGCHLD, &config)) == -1) {
        fprintf(stderr, "=> clone failed! %m\n");
        err = 1;
        goto clear_resources;
    }

    ///////////////////////////////////////////////////////////////////////
    // Step 6: error handling and cleanup
    ///////////////////////////////////////////////////////////////////////
    /*
    为了清理掉不需要的写入端，同时防止意外地继续向子进程写入消息。这样做有助于保持代码的清晰性和可维护性，并且避免不必要的通信错误
    */
    close(sockets[1]);
    sockets[1] = 0;
    close(sockets[1]);
    sockets[1] = 0;

    if (handle_child_uid_map(child_pid, sockets[0])) {
        err = 1;
        goto kill_and_finish_child;
    }

    goto finish_child;
kill_and_finish_child:
    if (child_pid) kill(child_pid, SIGKILL);
finish_child:;
             int child_status = 0;
             waitpid(child_pid, &child_status, 0);
             err |= WEXITSTATUS(child_status);
clear_resources:
             cleanup_cgroups(&config);
             free(stack);

             goto cleanup;
usage:
             fprintf(stderr, "Usage: %s -u 0 -m ~/busybox-rootfs-1.36/ -c /bin/whoami\n", argv[0]);
error:
             err = 1;
cleanup:
             if (sockets[0]) close(sockets[0]);
             if (sockets[1]) close(sockets[1]);
             return err;
}
