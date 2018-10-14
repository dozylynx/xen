/******************************************************************************
 * Argo : Hypervisor-Mediated data eXchange
 *
 * Derived from v4v, the version 2 of v2v.
 *
 * Copyright (c) 2010, Citrix Systems
 * Copyright (c) 2018, BAE Systems
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

DEFINE_XEN_GUEST_HANDLE(argo_addr_t);
DEFINE_XEN_GUEST_HANDLE(argo_ring_t);

/* Xen command line option to enable argo */
static bool __read_mostly opt_argo_enabled = 0;
boolean_param("argo", opt_argo_enabled);

/* Xen command line option for conservative or relaxed access control */
bool __read_mostly argo_mac_bootparam_enforcing = true;

static int __init parse_argo_mac_param(const char *s)
{
    if ( !strncmp(s, "enforcing", 10) )
        argo_mac_bootparam_enforcing = true;
    else if ( !strncmp(s, "permissive", 11) )
        argo_mac_bootparam_enforcing = false;
    else
        return -EINVAL;
    return 0;
}
custom_param("argo_mac", parse_argo_mac_param);

struct argo_pending_ent
{
    struct hlist_node node;
    domid_t id;
    uint32_t len;
};

struct argo_ring_info
{
    /* next node in the hash, protected by L2 */
    struct hlist_node node;
    /* this ring's id, protected by L2 */
    argo_ring_id_t id;
    /* used to confirm sender id, protected by L2 */
    uint64_t partner_cookie;
    /* L3 */
    spinlock_t lock;
    /* cached length of the ring (from ring->len), protected by L3 */
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
    /* list of struct argo_pending_ent for this ring, protected by L3 */
    struct hlist_head pending;
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
    /* event channel */
    evtchn_port_t evtchn_port;
    /* protected by L2 */
    struct hlist_head ring_hash[ARGO_HTABLE_SIZE];
    /* id cookie, written only at init, so readable with R(L1) */
    uint64_t domain_cookie;
};

/*
 * locks
 */

/*
 * locking is organized as follows:
 *
 * L1 : The global lock: argo_lock
 * Protects the argo elements of all struct domain *d in the system.
 * It does not protect any of the elements of d->argo, only their
 * addresses.
 * By extension since the destruction of a domain with a non-NULL
 * d->argo will need to free the d->argo pointer, holding this lock
 * guarantees that no domains pointers that argo is interested in
 * become invalid whilst this lock is held.
 */

static DEFINE_RWLOCK(argo_lock); /* L1 */

/*
 * L2 : The per-domain lock: d->argo->lock
 * Holding a read lock on L2 protects the hash table and
 * the elements in the hash_table d->argo->ring_hash, and
 * the node and id fields in struct argo_ring_info in the
 * hash table.
 * Holding a write lock on L2 protects all of the elements of
 * struct argo_ring_info.
 * To take L2 you must already have R(L1). W(L1) implies W(L2) and L3.
 *
 * L3 : The ringinfo lock: argo_ring_info *ringinfo; ringinfo->lock
 * Protects len, tx_ptr, the guest ring, the guest ring_data and
 * the pending list.
 * To aquire L3 you must already have R(L2). W(L2) implies L3.
 */

/*
 * Debugs
 */

#ifdef ARGO_DEBUG
#define argo_dprintk(format, args...)            \
    do {                                         \
        printk("argo: " format, ## args );       \
    } while ( 1 == 0 )
#else
#define argo_dprintk(format, ... ) (void)0
#endif

/*
 * ring buffer
 */

/* caller must have L3 or W(L2) */
static void
argo_ring_unmap(struct argo_ring_info *ring_info)
{
    int i;

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

/*
 * pending
 */
static void
argo_pending_remove_ent(struct argo_pending_ent *ent)
{
    hlist_del(&ent->node);
    xfree(ent);
}

static void
argo_pending_remove_all(struct argo_ring_info *ring_info)
{
    struct hlist_node *node, *next;
    struct argo_pending_ent *pending_ent;

    hlist_for_each_entry_safe(pending_ent, node, next,
                              &ring_info->pending, node)
    {
        argo_pending_remove_ent(pending_ent);
    }
}

static void argo_ring_remove_mfns(const struct domain *d,
                                  struct argo_ring_info *ring_info)
{
    int i;

    ASSERT(rw_is_write_locked(&d->argo->lock));

    if ( !ring_info->mfns )
        return;
    ASSERT(ring_info->mfn_mapping);

    argo_ring_unmap(ring_info);

    for ( i = 0; i < ring_info->nmfns; i++ )
        if ( mfn_x(ring_info->mfns[i]) != mfn_x(INVALID_MFN) )
            put_page_and_type(mfn_to_page(ring_info->mfns[i]));

    xfree(ring_info->mfns);
    ring_info->mfns = NULL;
    ring_info->npage = 0;
    xfree(ring_info->mfn_mapping);
    ring_info->mfn_mapping = NULL;
    ring_info->nmfns = 0;
}

static void
argo_ring_remove_info(struct domain *d, struct argo_ring_info *ring_info)
{
    ASSERT(rw_is_write_locked(&d->argo->lock));

    /* Holding W(L2) so do not need to acquire L3 */
    argo_pending_remove_all(ring_info);
    hlist_del(&ring_info->node);
    argo_ring_remove_mfns(d, ring_info);
    xfree(ring_info);
}

long
do_argo_message_op(int cmd, XEN_GUEST_HANDLE_PARAM(void) arg1,
                   XEN_GUEST_HANDLE_PARAM(void) arg2,
                   uint32_t arg3, uint32_t arg4)
{
    struct domain *d = current->domain;
    long rc = -EFAULT;

    argo_dprintk("->do_argo_message_op(%d,%p,%p,%d,%d)\n", cmd,
                 (void *)arg1.p, (void *)arg2.p, (int) arg3, (int) arg4);

    if ( unlikely(!opt_argo_enabled) )
    {
        rc = -ENOSYS;
        argo_dprintk("<-do_argo_message_op()=%ld\n", rc);
        return rc;
    }

    domain_lock(d);

    switch (cmd)
    {
    default:
        rc = -ENOSYS;
        break;
    }

    domain_unlock(d);
    argo_dprintk("<-do_argo_message_op()=%ld\n", rc);
    return rc;
}

int
argo_init(struct domain *d)
{
    struct argo_domain *argo;
    evtchn_port_t port;
    int i;
    int rc;

    if ( !opt_argo_enabled )
    {
        argo_dprintk("argo disabled, domid: %d\n", d->domain_id);
        return 0;
    }

    argo_dprintk("argo init: domid: %d\n", d->domain_id);

    argo = xmalloc(struct argo_domain);
    if ( !argo )
        return -ENOMEM;

    rwlock_init(&argo->lock);

    for ( i = 0; i < ARGO_HTABLE_SIZE; ++i )
        INIT_HLIST_HEAD(&argo->ring_hash[i]);

    rc = evtchn_bind_ipi_vcpu0_domain(d, &port);
    if ( rc )
    {
        xfree(argo);
        return rc;
    }
    argo->evtchn_port = port;
    argo->domain_cookie = (uint64_t)NOW();

    write_lock(&argo_lock);
    d->argo = argo;
    write_unlock(&argo_lock);

    return 0;
}

void
argo_destroy(struct domain *d)
{
    int i;

    BUG_ON(!d->is_dying);
    write_lock(&argo_lock);

    argo_dprintk("d->v=%p\n", d->argo);

    if ( d->argo )
    {
        for ( i = 0; i < ARGO_HTABLE_SIZE; ++i )
        {
            struct hlist_node *node, *next;
            struct argo_ring_info *ring_info;

            hlist_for_each_entry_safe(ring_info, node,
                                      next, &d->argo->ring_hash[i],
                                      node)
            {
                argo_ring_remove_info(d, ring_info);
            }
        }
        /*
         * Since this function is only called during domain destruction,
         * argo->evtchn_port need not be closed here. ref: evtchn_destroy
         */
        d->argo->domain_cookie = 0;
        xfree(d->argo);
        d->argo = NULL;
    }
    write_unlock(&argo_lock);

    /*
     * This (dying) domain's domid may be recorded as the authorized sender
     * to rings registered by other domains, and those rings are not
     * unregistered here.
     * If a later domain is created that has the same domid as this one, the
     * domain_cookie will differ, which ensures that the new domain cannot
     * use the inherited authorizations to transmit that were issued to this
     * domain.
     */
}
