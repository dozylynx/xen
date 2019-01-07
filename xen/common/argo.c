/******************************************************************************
 * Argo : Hypervisor-Mediated data eXchange
 *
 * Derived from v4v, the version 2 of v2v.
 *
 * Copyright (c) 2010, Citrix Systems
 * Copyright (c) 2018-2019 BAE Systems
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <xen/argo.h>
#include <xen/domain.h>
#include <xen/domain_page.h>
#include <xen/errno.h>
#include <xen/event.h>
#include <xen/guest_access.h>
#include <xen/nospec.h>
#include <xen/sched.h>
#include <xen/time.h>

#include <public/argo.h>

DEFINE_XEN_GUEST_HANDLE(xen_argo_addr_t);
DEFINE_XEN_GUEST_HANDLE(xen_argo_ring_t);

/* Xen command line option to enable argo */
static bool __read_mostly opt_argo_enabled;
boolean_param("argo", opt_argo_enabled);

typedef struct argo_ring_id
{
    xen_argo_port_t aport;
    domid_t partner_id;
    domid_t domain_id;
} argo_ring_id;

/* Data about a domain's own ring that it has registered */
struct argo_ring_info
{
    /* next node in the hash, protected by rings_L2 */
    struct hlist_node node;
    /* this ring's id, protected by rings_L2 */
    struct argo_ring_id id;
    /* L3, the ring_info lock: protects the members of this struct below */
    spinlock_t L3_lock;
    /* length of the ring, protected by L3 */
    unsigned int len;
    /* number of pages translated into mfns, protected by L3 */
    unsigned int nmfns;
    /* cached tx pointer location, protected by L3 */
    unsigned int tx_ptr;
    /* mapped ring pages protected by L3 */
    void **mfn_mapping;
    /* list of mfns of guest ring, protected by L3 */
    mfn_t *mfns;
    /* list of struct pending_ent for this ring, protected by L3 */
    struct hlist_head pending;
    /* number of pending entries queued for this ring, protected by L3 */
    unsigned int npending;
};

/* Data about a single-sender ring, held by the sender (partner) domain */
struct argo_send_info
{
    /* next node in the hash, protected by send_L2 */
    struct hlist_node node;
    /* this ring's id, protected by send_L2 */
    struct argo_ring_id id;
};

/* A space-available notification that is awaiting sufficient space */
struct pending_ent
{
    /* List node within argo_ring_info's pending list */
    struct hlist_node node;
    /*
     * List node within argo_domain's wildcard_pend_list. Only used if the
     * ring is one with a wildcard partner (ie. that any domain may send to)
     * to enable cancelling signals on wildcard rings on domain destroy.
     */
    struct hlist_node wildcard_node;
    /*
     * Pointer to the ring_info that this ent pertains to. Used to ensure that
     * ring_info->npending is decremented when ents for wildcard rings are
     * cancelled for domain destroy.
     * Caution: Must hold the correct locks before accessing ring_info via this.
     */
    struct argo_ring_info *ring_info;
    /* minimum ring space available that this signal is waiting upon */
    unsigned int len;
    /* domain to be notified when space is available */
    domid_t domain_id;
};

/*
 * The value of the argo element in a struct domain is
 * protected by L1_global_argo_rwlock
 */
#define ARGO_HTABLE_SIZE 32
struct argo_domain
{
    /* rings_L2 */
    rwlock_t rings_L2_rwlock;
    /*
     * Hash table of argo_ring_info about rings this domain has registered.
     * Protected by rings_L2.
     */
    struct hlist_head ring_hash[ARGO_HTABLE_SIZE];
    /* Counter of rings registered by this domain. Protected by rings_L2. */
    unsigned int ring_count;

    /* send_L2 */
    spinlock_t send_L2_lock;
    /*
     * Hash table of argo_send_info about rings other domains have registered
     * for this domain to send to. Single partner, non-wildcard rings.
     * Protected by send_L2.
     */
    struct hlist_head send_hash[ARGO_HTABLE_SIZE];

    /* wildcard_L2 */
    spinlock_t wildcard_L2_lock;
    /*
     * List of pending space-available signals for this domain about wildcard
     * rings registered by other domains. Protected by wildcard_L2.
     */
    struct hlist_head wildcard_pend_list;
};

/*
 * Locking is organized as follows:
 *
 * Terminology: R(<lock>) means taking a read lock on the specified lock;
 *              W(<lock>) means taking a write lock on it.
 *
 * == L1 : The global read/write lock: L1_global_argo_rwlock
 * Protects the argo elements of all struct domain *d in the system.
 * It does not protect any of the elements of d->argo, only their
 * addresses.
 *
 * By extension since the destruction of a domain with a non-NULL
 * d->argo will need to free the d->argo pointer, holding W(L1)
 * guarantees that no domains pointers that argo is interested in
 * become invalid whilst this lock is held.
 */

static DEFINE_RWLOCK(L1_global_argo_rwlock); /* L1 */

/*
 * == rings_L2 : The per-domain ring hash lock: d->argo->rings_L2_rwlock
 *
 * Holding a read lock on rings_L2 protects the ring hash table and
 * the elements in the hash_table d->argo->ring_hash, and
 * the node and id fields in struct argo_ring_info in the
 * hash table.
 * Holding a write lock on rings_L2 protects all of the elements of all the
 * struct argo_ring_info belonging to this domain.
 *
 * To take rings_L2 you must already have R(L1). W(L1) implies W(rings_L2) and
 * L3.
 *
 * == L3 : The individual ring_info lock: ring_info->L3_lock
 *
 * Protects all the fields within the argo_ring_info, aside from the ones that
 * rings_L2 already protects: node, id, lock.
 *
 * To acquire L3 you must already have R(rings_L2). W(rings_L2) implies L3.
 *
 * == send_L2 : The per-domain single-sender partner rings lock:
 *              d->argo->send_L2_lock
 *
 * Protects the per-domain send hash table : d->argo->send_hash
 * and the elements in the hash table, and the node and id fields
 * in struct argo_send_info in the hash table.
 *
 * To take send_L2, you must already have R(L1). W(L1) implies send_L2.
 * Do not attempt to acquire a rings_L2 on any domain after taking and while
 * holding a send_L2 lock -- acquire the rings_L2 (if one is needed) beforehand.
 *
 * == wildcard_L2 : The per-domain wildcard pending list lock:
 *                  d->argo->wildcard_L2_lock
 *
 * Protects the per-domain list of outstanding signals for space availability
 * on wildcard rings.
 *
 * To take wildcard_L2, you must already have R(L1). W(L1) implies wildcard_L2.
 * No other locks are acquired after obtaining wildcard_L2.
 */

/*
 * Lock state validations macros
 *
 * These macros encode the logic to verify that the locking has adhered to the
 * locking discipline above.
 * eg. On entry to logic that requires holding at least R(rings_L2), this:
 *      ASSERT(LOCKING_Read_rings_L2(d));
 *
 * checks that the lock state is sufficient, validating that one of the
 * following must be true when executed:       R(rings_L2) && R(L1)
 *                                        or:  W(rings_L2) && R(L1)
 *                                        or:  W(L1)
 */

/* RAW macros here are only used to assist defining the other macros below */
#define RAW_LOCKING_Read_L1 (rw_is_locked(&L1_global_argo_rwlock))
#define RAW_LOCKING_Read_rings_L2(d) \
    (rw_is_locked(&d->argo->rings_L2_rwlock) && RAW_LOCKING_Read_L1)

/* The LOCKING macros defined below here are for use at verification points */
#define LOCKING_Write_L1 (rw_is_write_locked(&L1_global_argo_rwlock))
#define LOCKING_Read_L1 (RAW_LOCKING_Read_L1 || LOCKING_Write_L1)

#define LOCKING_Write_rings_L2(d) \
    ((RAW_LOCKING_Read_L1 && rw_is_write_locked(&d->argo->rings_L2_rwlock)) || \
     LOCKING_Write_L1)

#define LOCKING_Read_rings_L2(d) \
    ((RAW_LOCKING_Read_L1 && rw_is_locked(&d->argo->rings_L2_rwlock)) || \
     LOCKING_Write_rings_L2(d) || LOCKING_Write_L1)

#define LOCKING_L3(d, r) \
    ((RAW_LOCKING_Read_rings_L2(d) && spin_is_locked(&r->L3_lock)) || \
     LOCKING_Write_rings_L2(d) || LOCKING_Write_L1)

#define LOCKING_send_L2(d) \
    ((RAW_LOCKING_Read_L1 && spin_is_locked(&d->argo->send_L2_lock)) || \
     LOCKING_Write_L1)

/* Change this to #define ARGO_DEBUG here to enable more debug messages */
#undef ARGO_DEBUG

#ifdef ARGO_DEBUG
#define argo_dprintk(format, args...) printk("argo: " format, ## args )
#else
#define argo_dprintk(format, ... ) ((void)0)
#endif

static struct argo_ring_info *
ring_find_info(const struct domain *d, const struct argo_ring_id *id);

/*
 * This hash function is used to distribute rings within the per-domain
 * hash tables (d->argo->ring_hash and d->argo_send_hash). The hash table
 * will provide a struct if a match is found with a 'argo_ring_id' key:
 * ie. the key is a (domain id, argo port, partner domain id) tuple.
 * Since argo port number varies the most in expected use, and the Linux driver
 * allocates at both the high and low ends, incorporate high and low bits to
 * help with distribution.
 * Apply array_index_nospec as a defensive measure since this operates
 * on user-supplied input and the array size that it indexes into is known.
 */
static unsigned int
hash_index(const struct argo_ring_id *id)
{
    unsigned int hash;

    hash = (uint16_t)(id->aport >> 16);
    hash ^= (uint16_t)id->aport;
    hash ^= id->domain_id;
    hash ^= id->partner_id;
    hash &= (ARGO_HTABLE_SIZE - 1);

    return array_index_nospec(hash, ARGO_HTABLE_SIZE);
}

static void
ring_unmap(const struct domain *d, struct argo_ring_info *ring_info)
{
    unsigned int i;

    ASSERT(LOCKING_L3(d, ring_info));

    if ( !ring_info->mfn_mapping )
        return;

    for ( i = 0; i < ring_info->nmfns; i++ )
    {
        if ( !ring_info->mfn_mapping[i] )
            continue;
        if ( ring_info->mfns )
            argo_dprintk(XENLOG_ERR "argo: unmapping page %"PRI_mfn" from %p\n",
                         mfn_x(ring_info->mfns[i]),
                         ring_info->mfn_mapping[i]);
        unmap_domain_page_global(ring_info->mfn_mapping[i]);
        ring_info->mfn_mapping[i] = NULL;
    }
}

static void
wildcard_pending_list_remove(domid_t domain_id, struct pending_ent *ent)
{
    struct domain *d = get_domain_by_id(domain_id);

    if ( !d )
        return;

    ASSERT(LOCKING_Read_L1);

    if ( d->argo )
    {
        spin_lock(&d->argo->wildcard_L2_lock);
        hlist_del(&ent->wildcard_node);
        spin_unlock(&d->argo->wildcard_L2_lock);
    }
    put_domain(d);
}

static void
pending_remove_all(const struct domain *d, struct argo_ring_info *ring_info)
{
    struct hlist_node *node, *next;
    struct pending_ent *ent;

    ASSERT(LOCKING_L3(d, ring_info));

    hlist_for_each_entry_safe(ent, node, next, &ring_info->pending, node)
    {
        if ( ring_info->id.partner_id == XEN_ARGO_DOMID_ANY )
            wildcard_pending_list_remove(ent->domain_id, ent);
        hlist_del(&ent->node);
        xfree(ent);
    }
    ring_info->npending = 0;
}

static void
wildcard_rings_pending_remove(struct domain *d)
{
    struct hlist_node *node, *next;
    struct pending_ent *ent;

    ASSERT(LOCKING_Write_L1);

    hlist_for_each_entry_safe(ent, node, next, &d->argo->wildcard_pend_list,
                              node)
    {
        /*
         * The ent->node deleted here, and the npending value decreased,
         * belong to the ring_info of another domain, which is why this
         * function requires holding W(L1):
         * it implies the L3 lock that protects that ring_info struct.
         */
        ent->ring_info->npending--;
        hlist_del(&ent->node);
        hlist_del(&ent->wildcard_node);
        xfree(ent);
    }
}

static void
ring_remove_mfns(const struct domain *d, struct argo_ring_info *ring_info)
{
    unsigned int i;

    ASSERT(LOCKING_Write_rings_L2(d));

    if ( !ring_info->mfns )
        return;

    if ( !ring_info->mfn_mapping )
    {
        ASSERT_UNREACHABLE();
        return;
    }

    ring_unmap(d, ring_info);

    for ( i = 0; i < ring_info->nmfns; i++ )
        if ( !mfn_eq(ring_info->mfns[i], INVALID_MFN) )
            put_page_and_type(mfn_to_page(ring_info->mfns[i]));

    ring_info->nmfns = 0;
    XFREE(ring_info->mfns);
    XFREE(ring_info->mfn_mapping);
}

static void
ring_remove_info(const struct domain *d, struct argo_ring_info *ring_info)
{
    ASSERT(LOCKING_Write_rings_L2(d));

    pending_remove_all(d, ring_info);
    hlist_del(&ring_info->node);
    ring_remove_mfns(d, ring_info);
    xfree(ring_info);
}

static void
domain_rings_remove_all(struct domain *d)
{
    unsigned int i;

    ASSERT(LOCKING_Write_rings_L2(d));

    for ( i = 0; i < ARGO_HTABLE_SIZE; ++i )
    {
        struct hlist_node *node, *next;
        struct argo_ring_info *ring_info;

        hlist_for_each_entry_safe(ring_info, node, next,
                                  &d->argo->ring_hash[i], node)
            ring_remove_info(d, ring_info);
    }
    d->argo->ring_count = 0;
}

/*
 * Tear down all rings of other domains where src_d domain is the partner.
 * (ie. it is the single domain that can send to those rings.)
 * This will also cancel any pending notifications about those rings.
 */
static void
partner_rings_remove(struct domain *src_d)
{
    unsigned int i;

    ASSERT(LOCKING_Write_L1);

    for ( i = 0; i < ARGO_HTABLE_SIZE; ++i )
    {
        struct hlist_node *node, *next;
        struct argo_send_info *send_info;

        hlist_for_each_entry_safe(send_info, node, next,
                                  &src_d->argo->send_hash[i], node)
        {
            struct argo_ring_info *ring_info;
            struct domain *dst_d;

            dst_d = get_domain_by_id(send_info->id.domain_id);
            if ( dst_d )
            {
                ring_info = ring_find_info(dst_d, &send_info->id);
                if ( ring_info )
                {
                    ring_remove_info(dst_d, ring_info);
                    dst_d->argo->ring_count--;
                }

                put_domain(dst_d);
            }

            hlist_del(&send_info->node);
            xfree(send_info);
        }
    }
}

static struct argo_ring_info *
ring_find_info(const struct domain *d, const struct argo_ring_id *id)
{
    unsigned int ring_hash_index;
    struct hlist_node *node;
    struct argo_ring_info *ring_info;

    ASSERT(LOCKING_Read_rings_L2(d));

    ring_hash_index = hash_index(id);

    argo_dprintk("d->argo=%p, d->argo->ring_hash[%u]=%p id=%p\n",
                 d->argo, ring_hash_index,
                 d->argo->ring_hash[ring_hash_index].first, id);
    argo_dprintk("id.aport=%x id.domain=vm%u id.partner_id=vm%d\n",
                 id->aport, id->domain_id, id->partner_id);

    hlist_for_each_entry(ring_info, node, &d->argo->ring_hash[ring_hash_index],
                         node)
    {
        const struct argo_ring_id *cmpid = &ring_info->id;

        if ( cmpid->aport == id->aport &&
             cmpid->domain_id == id->domain_id &&
             cmpid->partner_id == id->partner_id )
        {
            argo_dprintk("ring_info=%p\n", ring_info);
            return ring_info;
        }
    }
    argo_dprintk("no ring_info found\n");

    return NULL;
}

long
do_argo_op(unsigned int cmd, XEN_GUEST_HANDLE_PARAM(void) arg1,
           XEN_GUEST_HANDLE_PARAM(void) arg2, unsigned long arg3,
           unsigned long arg4)
{
    struct domain *currd = current->domain;
    long rc = -EFAULT;

    argo_dprintk("->do_argo_op(%u,%p,%p,%d,%d)\n", cmd,
                 (void *)arg1.p, (void *)arg2.p, (int) arg3, (int) arg4);

    if ( unlikely(!opt_argo_enabled) )
        return -EOPNOTSUPP;

    switch (cmd)
    {
    default:
        rc = -EOPNOTSUPP;
        break;
    }

    argo_dprintk("<-do_argo_op(%u)=%ld\n", cmd, rc);

    return rc;
}

static void
argo_domain_init(struct argo_domain *argo)
{
    unsigned int i;

    rwlock_init(&argo->rings_L2_rwlock);
    spin_lock_init(&argo->send_L2_lock);
    spin_lock_init(&argo->wildcard_L2_lock);
    argo->ring_count = 0;

    for ( i = 0; i < ARGO_HTABLE_SIZE; ++i )
    {
        INIT_HLIST_HEAD(&argo->ring_hash[i]);
        INIT_HLIST_HEAD(&argo->send_hash[i]);
    }
    INIT_HLIST_HEAD(&argo->wildcard_pend_list);
}

int
argo_init(struct domain *d)
{
    struct argo_domain *argo;

    if ( !opt_argo_enabled )
    {
        argo_dprintk("argo disabled, domid: %d\n", d->domain_id);
        return 0;
    }

    argo_dprintk("init: domid: %d\n", d->domain_id);

    argo = xmalloc(struct argo_domain);
    if ( !argo )
        return -ENOMEM;

    argo_domain_init(argo);

    write_lock(&L1_global_argo_rwlock);

    d->argo = argo;

    write_unlock(&L1_global_argo_rwlock);

    return 0;
}

void
argo_destroy(struct domain *d)
{
    BUG_ON(!d->is_dying);

    write_lock(&L1_global_argo_rwlock);

    argo_dprintk("destroy: domid %d d->argo=%p\n", d->domain_id, d->argo);

    if ( d->argo )
    {
        domain_rings_remove_all(d);
        partner_rings_remove(d);
        wildcard_rings_pending_remove(d);
        XFREE(d->argo);
    }
    write_unlock(&L1_global_argo_rwlock);
}

void
argo_soft_reset(struct domain *d)
{
    write_lock(&L1_global_argo_rwlock);

    argo_dprintk("soft reset d=%d d->argo=%p\n", d->domain_id, d->argo);

    if ( d->argo )
    {
        domain_rings_remove_all(d);
        partner_rings_remove(d);
        wildcard_rings_pending_remove(d);

        /*
         * Since opt_argo_enabled cannot change at runtime, if d->argo is true
         * then opt_argo_enabled must be true, and we can assume that init
         * is allowed to proceed again here.
         */
        argo_domain_init(d->argo);
    }

    write_unlock(&L1_global_argo_rwlock);
}
