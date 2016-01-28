/* copied from linux/include/linux/msg.h */
struct msg_msg {
	//struct list_head m_list;
	void *lprev, *lnext;
	long m_type;
	size_t m_ts;            /* message text size */
	void *next;
	void *security;
	/* the actual message follows immediately */
};

/* copied from linux/include/linux/types.h */
struct list_head {
	void *prev, *next;
};

/* copied from linux/lib/rbtree.c */
struct rb_node {
	unsigned long	__rb_parent_color;
	void		*rb_right;
	void		*rb_left;
};

/* copied from linux/include/linux/rwsem.h */
typedef int raw_spinlock_t;
typedef int optimistic_spin_queue_t;
struct rw_semaphore {
	long count;
	struct list_head wait_list;
	raw_spinlock_t wait_lock;
	optimistic_spin_queue_t osq;
	void *owner;
};

/* copied from linux/include/linux/assoc_array.h */
struct assoc_array {
	void			*root;
	unsigned long		nr_leaves_on_tree;
};

/* copied from linux/include/linux/key.h */
struct keyring_index_key {
	void 			*type;
	const char		*description;
	size_t			desc_len;
};

typedef uid_t kuid_t;
typedef gid_t kgid_t;
struct key {
	uint32_t		usage;
	key_serial_t		serial;
	union {
		struct list_head graveyard_link;
		struct rb_node	serial_node;
	};
	struct rw_semaphore	sem;
	struct key_user		*user;
	void			*security;
	union {
		time_t		expiry;
		time_t		revoked_at;
	};
	time_t			last_used_at;
	kuid_t			uid;
	kgid_t			gid;
	key_perm_t		perm;
	unsigned short		quotalen;
	unsigned short		datalen;

//#ifdef KEY_DEBUGGING
//	unsigned		magic;
//#define KEY_DEBUG_MAGIC		0x18273645u
//#define KEY_DEBUG_MAGIC_X	0xf8e9dacbu
//#endif

	unsigned long		flags;

	union {
		struct keyring_index_key index_key;
		struct {
			struct key_type	*type;
			char		*description;
		};
	};

	/* key data
	 * - this is used to hold the data actually used in cryptography or
	 *   whatever
	 */
	union {
		void *payload[4];
		struct {
			/* Keyring bits */
			struct list_head name_link;
			struct assoc_array keys;
		};
		int reject_error;
	};
};

/* copied from linux/include/linux/key-type.h */
struct key_type {
	/* name of the type */
	const char *name;

	/* default payload length for quota precalculation (optional)
	 * - this can be used instead of calling key_payload_reserve(), that
	 *   function only needs to be called if the real datalen is different
	 */
	size_t def_datalen;

	/* vet a description */
	int (*vet_description)(const char *description);

	/* Preparse the data blob from userspace that is to be the payload,
	 * generating a proposed description and payload that will be handed to
	 * the instantiate() and update() ops.
	 */
	int (*preparse)(void *prep);

	/* Free a preparse data structure.
	 */
	void (*free_preparse)(void *prep);

	/* instantiate a key of this type
	 * - this method should call key_payload_reserve() to determine if the
	 *   user's quota will hold the payload
	 */
	int (*instantiate)(struct key *key, void *prep);

	/* update a key of this type (optional)
	 * - this method should call key_payload_reserve() to recalculate the
	 *   quota consumption
	 * - the key must be locked against read when modifying
	 */
	int (*update)(struct key *key, void *prep);

	/* Preparse the data supplied to ->match() (optional).  The
	 * data to be preparsed can be found in match_data->raw_data.
	 * The lookup type can also be set by this function.
	 */
	int (*match_preparse)(void *match_data);

	/* Free preparsed match data (optional).  This should be supplied it
	 * ->match_preparse() is supplied. */
	void (*match_free)(void *match_data);

	/* clear some of the data from a key on revokation (optional)
	 * - the key's semaphore will be write-locked by the caller
	 */
	void (*revoke)(struct key *key);

	/* clear the data from a key (optional) */
	void (*destroy)(struct key *key);

	/* describe a key */
	void (*describe)(const struct key *key, void *p);

	/* read a key's data (optional)
	 * - permission checks will be done by the caller
	 * - the key's semaphore will be readlocked by the caller
	 * - should return the amount of data that could be read, no matter how
	 *   much is copied into the buffer
	 * - shouldn't do the copy if the buffer is NULL
	 */
	long (*read)(const struct key *key, char *buffer, size_t buflen);

	/* handle request_key() for this type instead of invoking
	 * /sbin/request-key (optional)
	 * - key is the key to instantiate
	 * - authkey is the authority to assume when instantiating this key
	 * - op is the operation to be done, usually "create"
	 * - the call must not return until the instantiation process has run
	 *   its course
	 */
	void *request_key;

	/* internal fields */
	struct list_head	link;		/* link in types list */
	//struct lock_class_key	lock_class;	/* key->sem lock class */
};

