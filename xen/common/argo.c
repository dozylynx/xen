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

DEFINE_XEN_GUEST_HANDLE(argo_pfn_t);
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
 * Helper functions
 */

static inline uint16_t
argo_hash_fn(const struct argo_ring_id *id)
{
    uint16_t ret;

    ret = (uint16_t)(id->addr.port >> 16);
    ret ^= (uint16_t)id->addr.port;
    ret ^= id->addr.domain_id;
    ret ^= id->partner;

    ret &= (ARGO_HTABLE_SIZE - 1);

    return ret;
}

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

/* caller must have L3 or W(L2) */
static int
argo_ring_map_page(struct argo_ring_info *ring_info, uint32_t i,
                   uint8_t **page)
{
    if ( i >= ring_info->nmfns )
    {
        printk(XENLOG_ERR "argo: ring (vm%u:%x vm%d) %p attempted to map page"
               " %u of %u\n", ring_info->id.addr.domain_id,
               ring_info->id.addr.port, ring_info->id.partner, ring_info,
               i, ring_info->nmfns);
        return -EFAULT;
    }
    ASSERT(ring_info->mfns);
    ASSERT(ring_info->mfn_mapping);

    if ( !ring_info->mfn_mapping[i] )
    {
        /*
         * TODO:
         * The first page of the ring contains the ring indices, so both read and
         * write access to the page is required by the hypervisor, but read-access
         * is not needed for this mapping for the remainder of the ring.
         * Since this mapping will remain resident in Xen's address space for
         * the lifetime of the ring, and following the principle of least privilege,
         * it could be preferable to:
         *  # add a XSM check to determine what policy is wanted here
         *  # depending on the XSM query, optionally create this mapping as
         *    _write-only_ on platforms that can support it.
         *    (eg. Intel EPT/AMD NPT).
         */
        ring_info->mfn_mapping[i] = map_domain_page_global(ring_info->mfns[i]);

        if ( !ring_info->mfn_mapping[i] )
        {
            printk(XENLOG_ERR "argo: ring (vm%u:%x vm%d) %p attempted to map page"
                   " %u of %u\n", ring_info->id.addr.domain_id,
                   ring_info->id.addr.port, ring_info->id.partner, ring_info,
                   i, ring_info->nmfns);
            return -EFAULT;
        }
        argo_dprintk("mapping page %"PRI_mfn" to %p\n",
               mfn_x(ring_info->mfns[i]), ring_info->mfn_mapping[i]);
    }

    if ( page )
        *page = ring_info->mfn_mapping[i];
    return 0;
}

/* caller must have L3 or W(L2) */
static int
argo_update_tx_ptr(struct argo_ring_info *ring_info, uint32_t tx_ptr)
{
    uint8_t *dst;
    uint32_t *p;
    int ret;

    ret = argo_ring_map_page(ring_info, 0, &dst);
    if ( ret )
        return ret;

    p = (uint32_t *)(dst + offsetof(argo_ring_t, tx_ptr));
    write_atomic(p, tx_ptr);
    mb();
    return 0;
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

/*
 * ring
 */

static int
argo_find_ring_mfn(struct domain *d, argo_pfn_t pfn, mfn_t *mfn)
{
    p2m_type_t p2mt;
    int ret = 0;

#ifdef CONFIG_X86
    *mfn = get_gfn_unshare(d, pfn, &p2mt);
#else
    *mfn = p2m_lookup(d, _gfn(pfn), &p2mt);
#endif

    if ( !mfn_valid(*mfn) )
        ret = -EINVAL;
#ifdef CONFIG_X86
    else if ( p2m_is_paging(p2mt) || (p2mt == p2m_ram_logdirty) )
        ret = -EAGAIN;
#endif
    else if ( (p2mt != p2m_ram_rw) ||
              !get_page_and_type(mfn_to_page(*mfn), d, PGT_writable_page) )
        ret = -EINVAL;

#ifdef CONFIG_X86
    put_gfn(d, pfn);
#endif

    return ret;
}

static int
argo_find_ring_mfns(struct domain *d, struct argo_ring_info *ring_info,
                    uint32_t npage, XEN_GUEST_HANDLE_PARAM(argo_pfn_t) pfn_hnd,
                    uint32_t len)
{
    int i;
    int ret = 0;

    if ( (npage << PAGE_SHIFT) < len )
        return -EINVAL;

    if ( ring_info->mfns )
    {
        /*
         * Ring already existed. Check if it's the same ring,
         * i.e. same number of pages and all translated gpfns still
         * translating to the same mfns
         */
        if ( ring_info->npage != npage )
            i = ring_info->nmfns + 1; /* forces re-register below */
        else
        {
            for ( i = 0; i < ring_info->nmfns; i++ )
            {
                argo_pfn_t pfn;
                mfn_t mfn;

                ret = copy_from_guest_offset_errno(&pfn, pfn_hnd, i, 1);
                if ( ret )
                    break;

                ret = argo_find_ring_mfn(d, pfn, &mfn);
                if ( ret )
                    break;

                if ( mfn_x(mfn) != mfn_x(ring_info->mfns[i]) )
                    break;
            }
        }
        if ( i != ring_info->nmfns )
        {
            printk(XENLOG_INFO "argo: vm%u re-registering existing argo ring"
                   " (vm%u:%x vm%d), clearing MFN list\n",
                   current->domain->domain_id, ring_info->id.addr.domain_id,
                   ring_info->id.addr.port, ring_info->id.partner);

            argo_ring_remove_mfns(d, ring_info);
            ASSERT(!ring_info->mfns);
        }
    }

    if ( !ring_info->mfns )
    {
        mfn_t *mfns;
        uint8_t **mfn_mapping;

        mfns = xmalloc_array(mfn_t, npage);
        if ( !mfns )
            return -ENOMEM;

        for ( i = 0; i < npage; i++ )
            mfns[i] = INVALID_MFN;

        mfn_mapping = xmalloc_array(uint8_t *, npage);
        if ( !mfn_mapping )
        {
            xfree(mfns);
            return -ENOMEM;
        }

        ring_info->npage = npage;
        ring_info->mfns = mfns;
        ring_info->mfn_mapping = mfn_mapping;
    }
    ASSERT(ring_info->npage == npage);

    if ( ring_info->nmfns == ring_info->npage )
        return 0;

    for ( i = ring_info->nmfns; i < ring_info->npage; i++ )
    {
        argo_pfn_t pfn;
        mfn_t mfn;

        ret = copy_from_guest_offset_errno(&pfn, pfn_hnd, i, 1);
        if ( ret )
            break;

        ret = argo_find_ring_mfn(d, pfn, &mfn);
        if ( ret )
        {
            printk(XENLOG_ERR "argo: vm%u passed invalid gpfn %"PRI_xen_pfn
                   " ring (vm%u:%x vm%d) %p seq %d of %d\n",
                   d->domain_id, pfn, ring_info->id.addr.domain_id,
                   ring_info->id.addr.port, ring_info->id.partner,
                   ring_info, i, ring_info->npage);
            break;
        }

        ring_info->mfns[i] = mfn;
        ring_info->nmfns = i + 1;

        argo_dprintk("%d: %"PRI_xen_pfn" -> %"PRI_mfn"\n",
               i, pfn, mfn_x(ring_info->mfns[i]));

        ring_info->mfn_mapping[i] = NULL;
    }

    if ( ret )
        argo_ring_remove_mfns(d, ring_info);
    else
    {
        ASSERT(ring_info->nmfns == ring_info->npage);

        printk(XENLOG_ERR "argo: vm%u ring (vm%u:%x vm%d) %p mfn_mapping %p"
               " npage %d nmfns %d\n", current->domain->domain_id,
               ring_info->id.addr.domain_id, ring_info->id.addr.port,
               ring_info->id.partner, ring_info, ring_info->mfn_mapping,
               ring_info->npage, ring_info->nmfns);
    }
    return ret;
}

static struct argo_ring_info *
argo_ring_find_info(const struct domain *d, const struct argo_ring_id *id)
{
    uint16_t hash;
    struct hlist_node *node;
    struct argo_ring_info *ring_info;

    ASSERT(rw_is_locked(&d->argo->lock));

    hash = argo_hash_fn(id);

    argo_dprintk("d->argo=%p, d->argo->ring_hash[%d]=%p id=%p\n",
                 d->argo, hash, d->argo->ring_hash[hash].first, id);
    argo_dprintk("id.addr.port=%d id.addr.domain=vm%u"
                 " id.addr.partner=vm%d\n",
                 id->addr.port, id->addr.domain_id, id->partner);

    hlist_for_each_entry(ring_info, node, &d->argo->ring_hash[hash], node)
    {
        argo_ring_id_t *cmpid = &ring_info->id;

        if ( cmpid->addr.port == id->addr.port &&
             cmpid->addr.domain_id == id->addr.domain_id &&
             cmpid->partner == id->partner )
        {
            argo_dprintk("ring_info=%p\n", ring_info);
            return ring_info;
        }
    }
    argo_dprintk("no ring_info found\n");

    return NULL;
}

static long
argo_unregister_ring(struct domain *d,
                     XEN_GUEST_HANDLE_PARAM(argo_ring_t) ring_hnd)
{
    struct argo_ring ring;
    struct argo_ring_info *ring_info;
    int ret = 0;

    read_lock(&argo_lock);

    do {
        if ( !d->argo )
        {
            ret = -ENODEV;
            break;
        }

        ret = copy_from_guest_errno(&ring, ring_hnd, 1);
        if ( ret )
            break;

        if ( ring.magic != ARGO_RING_MAGIC )
        {
            argo_dprintk(
                "ring.magic(%"PRIx64") != ARGO_RING_MAGIC(%llx), EINVAL\n",
                ring.magic, ARGO_RING_MAGIC);
            ret = -EINVAL;
            break;
        }

        ring.id.addr.domain_id = d->domain_id;

        write_lock(&d->argo->lock);

        ring_info = argo_ring_find_info(d, &ring.id);
        if ( ring_info )
            argo_ring_remove_info(d, ring_info);

        write_unlock(&d->argo->lock);

        if ( !ring_info )
        {
            argo_dprintk("ENOENT\n");
            ret = -ENOENT;
            break;
        }

    } while ( 0 );

    read_unlock(&argo_lock);
    return ret;
}

static long
argo_register_ring(struct domain *d,
                   XEN_GUEST_HANDLE_PARAM(argo_ring_t) ring_hnd,
                   XEN_GUEST_HANDLE_PARAM(argo_pfn_t) pfn_hnd, uint32_t npage,
                   bool fail_exist)
{
    struct argo_ring ring;
    struct argo_ring_info *ring_info;
    int ret = 0;
    bool update_tx_ptr = 0;
    uint64_t dst_domain_cookie = 0;

    if ( !(guest_handle_is_aligned(ring_hnd, ~PAGE_MASK)) )
        return -EINVAL;

    read_lock (&argo_lock);

    do {
        if ( !d->argo )
        {
            ret = -ENODEV;
            break;
        }

        if ( copy_from_guest(&ring, ring_hnd, 1) )
        {
            ret = -EFAULT;
            break;
        }

        if ( ring.magic != ARGO_RING_MAGIC )
        {
            ret = -EINVAL;
            break;
        }

        if ( (ring.len < (sizeof(struct argo_ring_message_header)
                          + ARGO_ROUNDUP(1) + ARGO_ROUNDUP(1)))   ||
             (ARGO_ROUNDUP(ring.len) != ring.len) )
        {
            ret = -EINVAL;
            break;
        }

        if ( ring.len > ARGO_MAX_RING_SIZE )
        {
            ret = -EINVAL;
            break;
        }

        if ( ring.id.partner == ARGO_DOMID_ANY )
        {
            ret = xsm_argo_register_any_source(d, argo_mac_bootparam_enforcing);
            if ( ret )
                break;
        }
        else
        {
            struct domain *dst_d = get_domain_by_id(ring.id.partner);
            if ( !dst_d )
            {
                argo_dprintk("!dst_d, ECONNREFUSED\n");
                ret = -ECONNREFUSED;
                break;
            }

            ret = xsm_argo_register_single_source(d, dst_d);
            if ( ret )
            {
                put_domain(dst_d);
                break;
            }

            if ( !dst_d->argo )
            {
                argo_dprintk("!dst_d->argo, ECONNREFUSED\n");
                ret = -ECONNREFUSED;
                put_domain(dst_d);
                break;
            }

            dst_domain_cookie = dst_d->argo->domain_cookie;

            put_domain(dst_d);
        }

        ring.id.addr.domain_id = d->domain_id;
        if ( copy_field_to_guest(ring_hnd, &ring, id) )
        {
            ret = -EFAULT;
            break;
        }

        /*
         * no need for a lock yet, because only we know about this
         * set the tx pointer if it looks bogus (we don't reset it
         * because this might be a re-register after S4)
         */

        if ( ring.tx_ptr >= ring.len ||
             ARGO_ROUNDUP(ring.tx_ptr) != ring.tx_ptr )
        {
            /*
             * Since the ring is a mess, attempt to flush the contents of it
             * here by setting the tx_ptr to the next aligned message slot past
             * the latest rx_ptr we have observed. Handle ring wrap correctly.
             */
            ring.tx_ptr = ARGO_ROUNDUP(ring.rx_ptr);

            if ( ring.tx_ptr >= ring.len )
                ring.tx_ptr = 0;

            /* ring.tx_ptr will be written back to the guest ring below. */
            update_tx_ptr = 1;
        }

        /* W(L2) protects all the elements of the domain's ring_info */
        write_lock(&d->argo->lock);

        do {
            ring_info = argo_ring_find_info(d, &ring.id);

            if ( !ring_info )
            {
                uint16_t hash;

                ring_info = xmalloc(struct argo_ring_info);
                if ( !ring_info )
                {
                    ret = -ENOMEM;
                    break;
                }

                spin_lock_init(&ring_info->lock);

                ring_info->mfns = NULL;
                ring_info->npage = 0;
                ring_info->mfn_mapping = NULL;
                ring_info->len = 0;
                ring_info->nmfns = 0;
                ring_info->tx_ptr = 0;
                ring_info->partner_cookie = dst_domain_cookie;

                ring_info->id = ring.id;
                INIT_HLIST_HEAD(&ring_info->pending);

                hash = argo_hash_fn(&ring_info->id);
                hlist_add_head(&ring_info->node, &d->argo->ring_hash[hash]);

                printk(XENLOG_INFO "argo: vm%u registering ring (vm%u:%x vm%d)\n",
                       current->domain->domain_id, ring.id.addr.domain_id,
                       ring.id.addr.port, ring.id.partner);
            }
            else
            {
                /*
                 * If the caller specified that the ring must not already exist,
                 * fail at attempt to add a completed ring which already exists.
                 */
                if ( fail_exist && ring_info->len )
                {
                    ret = -EEXIST;
                    break;
                }

                printk(XENLOG_INFO
                    "argo: vm%u re-registering existing ring (vm%u:%x vm%d)\n",
                     current->domain->domain_id, ring.id.addr.domain_id,
                     ring.id.addr.port, ring.id.partner);
            }

            /* Since we hold W(L2), there is no need to take L3 here */
            ring_info->tx_ptr = ring.tx_ptr;

            ret = argo_find_ring_mfns(d, ring_info, npage, pfn_hnd, ring.len);
            if ( !ret )
                ret = update_tx_ptr ? argo_update_tx_ptr(ring_info, ring.tx_ptr)
                                    : argo_ring_map_page(ring_info, 0, NULL);
            if ( !ret )
                ring_info->len = ring.len;

        } while ( 0 );

        write_unlock(&d->argo->lock);

    } while ( 0 );

    read_unlock(&argo_lock);

    return ret;
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
    case ARGO_MESSAGE_OP_register_ring:
    {
        XEN_GUEST_HANDLE_PARAM(argo_ring_t) ring_hnd =
            guest_handle_cast(arg1, argo_ring_t);
        XEN_GUEST_HANDLE_PARAM(argo_pfn_t) pfn_hnd =
            guest_handle_cast(arg2, argo_pfn_t);
        uint32_t npage = arg3;
        bool fail_exist = arg4 & ARGO_REGISTER_FLAG_FAIL_EXIST;

        if ( unlikely(!guest_handle_okay(ring_hnd, 1)) )
            break;
        if ( unlikely(npage > (ARGO_MAX_RING_SIZE >> PAGE_SHIFT)) )
        {
            rc = -EINVAL;
            break;
        }
        if ( unlikely(!guest_handle_okay(pfn_hnd, npage)) )
            break;
        /* arg4: reserve currently-undefined bits, require zero.  */
        if ( unlikely(arg4 & ~ARGO_REGISTER_FLAG_MASK) )
        {
            rc = -EINVAL;
            break;
        }

        rc = argo_register_ring(d, ring_hnd, pfn_hnd, npage, fail_exist);
        break;
    }
    case ARGO_MESSAGE_OP_unregister_ring:
    {
        XEN_GUEST_HANDLE_PARAM(argo_ring_t) ring_hnd =
            guest_handle_cast(arg1, argo_ring_t);
        if ( unlikely(!guest_handle_okay(ring_hnd, 1)) )
            break;
        rc = argo_unregister_ring(d, ring_hnd);
        break;
    }
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
