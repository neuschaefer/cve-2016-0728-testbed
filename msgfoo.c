/*
 * This program can be used to figure out how large the buffer/limit for a
 * message queue is.
 */

#define _XOPEN_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <unistd.h>


struct list_head {
	void *prev, *next;
};

/* copied from linux/include/linux/msg.h */
struct msg_msg {
	struct list_head m_list;
	long m_type;
	size_t m_ts;            /* message text size */
	void *next;
	void *security;
	/* the actual message follows immediately */
};

int main(void) {
	int mq = msgget(IPC_PRIVATE, 0600|IPC_CREAT);
	printf("msgget = %d\n", mq);

	struct {
		long mtype;
		char data[0xb8 - 0x30];
	} buf = {
		.mtype = 0x0102030405060708,
		.data = "HELLO WORLD!  "
		        "HELLO WORLD!  "
		        "HELLO WORLD!  "
		        "HELLO WORLD!  "
		        "HELLO WORLD!  "
		        "HELLO WORLD!  "
		        "HELLO WORLD!  "
		        "HELLO WORLD!  "
		        "HELLO WORLD!  ",
	};
	for (int i = 0; i < 0x100000; i++) {
		printf("[%4d] msgsnd = ", i);
		fflush(stdout);
		int ret = msgsnd(mq, &buf, sizeof(buf) - sizeof(long), 0);
		printf("%d\n", ret);
		if (ret == -1) {
			perror("msgsnd");
			sleep(1);
		}
	}

	return EXIT_SUCCESS;
}
