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

#include <xen/errno.h>
#include <xen/sched.h>
#include <xen/domain.h>
#include <xen/argo.h>
#include <xen/event.h>
#include <xen/domain_page.h>
#include <xen/guest_access.h>
#include <xen/time.h>
#include <public/argo.h>

DEFINE_XEN_GUEST_HANDLE(xen_argo_addr_t);
DEFINE_XEN_GUEST_HANDLE(xen_argo_ring_t);

/* Xen command line option to enable argo */
static bool __read_mostly opt_argo_enabled;
boolean_param("argo", opt_argo_enabled);

typedef struct argo_ring_id
{
    uint32_t port;
    domid_t partner_id;
    domid_t domain_id;
} argo_ring_id;

/* Data about a domain's own ring that it has registered */
struct argo_ring_info
{
    /* next node in the hash, protected by L2 */
    struct hlist_node node;
    /* this ring's id, protected by L2 */
    struct argo_ring_id id;
    /* L3 */
    spinlock_t lock;
    /* length of the ring, protected by L3 */
    uint32_t len;
    /* number of pages in the ring, protected by L3 */
    uint32_t npage;
    /* number of pages translated into mfns, protected by L3 */
    uint32_t nmfns;
    /* cached tx pointer location, protected by L3 */
    uint32_t tx_ptr;
    /* mapped ring pages protected by L3 */
    uint8_t **mfn_mapping;
    /* list of mfns of guest ring, protected by L3 */
    mfn_t *mfns;
    /* list of struct pending_ent for this ring, protected by L3 */
    struct hlist_head pending;
    /* number of pending entries queued for this ring, protected by L3 */
    uint32_t npending;
};

/* Data about a single-sender ring, held by the sender (partner) domain */
struct argo_send_info
{
    /* next node in the hash, protected by Lsend */
    struct hlist_node node;
    /* this ring's id, protected by Lsend */
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
    /* domain to be notified when space is available */
    domid_t domain_id;
    uint16_t pad;
    /* minimum ring space available that this signal is waiting upon */
    uint32_t len;
};

/*
 * The value of the argo element in a struct domain is
 * protected by the global lock argo_lock: L1
 */
#define ARGO_HTABLE_SIZE 32
struct argo_domain
{
    /* L2 */
    rwlock_t lock;
    /*
     * Hash table of argo_ring_info about rings this domain has registered.
     * Protected by L2.
     */
    struct hlist_head ring_hash[ARGO_HTABLE_SIZE];
    /* Counter of rings registered by this domain. Protected by L2. */
    uint32_t ring_count;

    /* Lsend */
    spinlock_t send_lock;
    /*
     * Hash table of argo_send_info about rings other domains have registered
     * for this domain to send to. Single partner, non-wildcard rings.
     * Protected by Lsend.
     */
    struct hlist_head send_hash[ARGO_HTABLE_SIZE];

    /* Lwildcard */
    spinlock_t wildcard_lock;
    /*
     * List of pending space-available signals for this domain about wildcard
     * rings registered by other domains. Protected by Lwildcard.
     */
    struct hlist_head wildcard_pend_list;
};

/*
 * Locking is organized as follows:
 *
 * Terminology: R(<lock>) means taking a read lock on the specified lock;
 *              W(<lock>) means taking a write lock on it.
 *
 * L1 : The global lock: argo_lock
 * Protects the argo elements of all struct domain *d in the system.
 * It does not protect any of the elements of d->argo, only their
 * addresses.
 *
 * By extension since the destruction of a domain with a non-NULL
 * d->argo will need to free the d->argo pointer, holding W(L1)
 * guarantees that no domains pointers that argo is interested in
 * become invalid whilst this lock is held.
 */

static DEFINE_RWLOCK(argo_lock); /* L1 */

/*
 * L2 : The per-domain ring hash lock: d->argo->lock
 * Holding a read lock on L2 protects the ring hash table and
 * the elements in the hash_table d->argo->ring_hash, and
 * the node and id fields in struct argo_ring_info in the
 * hash table.
 * Holding a write lock on L2 protects all of the elements of
 * struct argo_ring_info.
 *
 * To take L2 you must already have R(L1). W(L1) implies W(L2) and L3.
 *
 * L3 : The ringinfo lock: argo_ring_info *ringinfo; ringinfo->lock
 * Protects all the fields within the argo_ring_info, aside from the ones that
 * L2 already protects: node, id, lock.
 *
 * To aquire L3 you must already have R(L2). W(L2) implies L3.
 *
 * Lsend : The per-domain single-sender partner rings lock: d->argo->send_lock
 * Protects the per-domain send hash table : d->argo->send_hash
 * and the elements in the hash table, and the node and id fields
 * in struct argo_send_info in the hash table.
 *
 * To take Lsend, you must already have R(L1). W(L1) implies Lsend.
 * Do not attempt to acquire a L2 on any domain after taking and while
 * holding a Lsend lock -- acquire the L2 (if one is needed) beforehand.
 *
 * Lwildcard : The per-domain wildcard pending list lock: d->argo->wildcard_lock
 * Protects the per-domain list of outstanding signals for space availability
 * on wildcard rings.
 *
 * To take Lwildcard, you must already have R(L1). W(L1) implies Lwildcard.
 * No other locks are acquired after obtaining Lwildcard.
 */

/* Change this to #define ARGO_DEBUG here to enable more debug messages */
#undef ARGO_DEBUG

#ifdef ARGO_DEBUG
#define argo_dprintk(format, args...) printk("argo: " format, ## args )
#else
#define argo_dprintk(format, ... ) ((void)0)
#endif

static void
ring_unmap(struct argo_ring_info *ring_info)
{
    unsigned int i;

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

    if ( d->argo )
    {
        spin_lock(&d->argo->wildcard_lock);
        hlist_del(&ent->wildcard_node);
        spin_unlock(&d->argo->wildcard_lock);
    }
    put_domain(d);
}

static void
pending_remove_all(struct argo_ring_info *ring_info)
{
    struct hlist_node *node, *next;
    struct pending_ent *ent;

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

    ASSERT(rw_is_write_locked(&argo_lock));

    hlist_for_each_entry_safe(ent, node, next, &d->argo->wildcard_pend_list,
                              node)
    {
        hlist_del(&ent->node);
        ent->ring_info->npending--;
        hlist_del(&ent->wildcard_node);
        xfree(ent);
    }
}

static void
ring_remove_mfns(const struct domain *d, struct argo_ring_info *ring_info)
{
    unsigned int i;

    ASSERT(rw_is_write_locked(&d->argo->lock) ||
           rw_is_write_locked(&argo_lock));

    if ( !ring_info->mfns )
        return;

    if ( !ring_info->mfn_mapping )
    {
        ASSERT_UNREACHABLE();
        return;
    }

    ring_unmap(ring_info);

    for ( i = 0; i < ring_info->nmfns; i++ )
        if ( !mfn_eq(ring_info->mfns[i], INVALID_MFN) )
            put_page_and_type(mfn_to_page(ring_info->mfns[i]));

    xfree(ring_info->mfns);
    ring_info->mfns = NULL;
    ring_info->npage = 0;
    xfree(ring_info->mfn_mapping);
    ring_info->mfn_mapping = NULL;
    ring_info->nmfns = 0;
}

static void
ring_remove_info(struct domain *d, struct argo_ring_info *ring_info)
{
    ASSERT(rw_is_write_locked(&d->argo->lock) ||
           rw_is_write_locked(&argo_lock));

    pending_remove_all(ring_info);
    hlist_del(&ring_info->node);
    ring_remove_mfns(d, ring_info);
    xfree(ring_info);
}

static void
domain_rings_remove_all(struct domain *d)
{
    unsigned int i;

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

    ASSERT(rw_is_write_locked(&argo_lock));

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
    {
        rc = -EOPNOTSUPP;
        return rc;
    }

    domain_lock(currd);

    switch (cmd)
    {
    default:
        rc = -EOPNOTSUPP;
        break;
    }

    domain_unlock(currd);

    argo_dprintk("<-do_argo_op(%u)=%ld\n", cmd, rc);

    return rc;
}

static void
argo_domain_init(struct argo_domain *argo)
{
    unsigned int i;

    rwlock_init(&argo->lock);
    spin_lock_init(&argo->send_lock);
    spin_lock_init(&argo->wildcard_lock);
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

    write_lock(&argo_lock);

    argo_domain_init(argo);

    d->argo = argo;

    write_unlock(&argo_lock);

    return 0;
}

void
argo_destroy(struct domain *d)
{
    BUG_ON(!d->is_dying);

    write_lock(&argo_lock);

    argo_dprintk("destroy: domid %d d->argo=%p\n", d->domain_id, d->argo);

    if ( d->argo )
    {
        domain_rings_remove_all(d);
        partner_rings_remove(d);
        wildcard_rings_pending_remove(d);
        xfree(d->argo);
        d->argo = NULL;
    }
    write_unlock(&argo_lock);
}

void
argo_soft_reset(struct domain *d)
{
    write_lock(&argo_lock);

    argo_dprintk("soft reset d=%d d->argo=%p\n", d->domain_id, d->argo);

    if ( d->argo )
    {
        domain_rings_remove_all(d);
        partner_rings_remove(d);
        wildcard_rings_pending_remove(d);

        if ( !opt_argo_enabled )
        {
            xfree(d->argo);
            d->argo = NULL;
        }
        else
            argo_domain_init(d->argo);
    }

    write_unlock(&argo_lock);
}
