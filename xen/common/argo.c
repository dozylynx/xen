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
#include <xsm/xsm.h>

#define ARGO_MAX_RINGS_PER_DOMAIN       128U
#define ARGO_MAX_NOTIFY_COUNT           256U

DEFINE_XEN_GUEST_HANDLE(argo_pfn_t);
DEFINE_XEN_GUEST_HANDLE(argo_addr_t);
DEFINE_XEN_GUEST_HANDLE(argo_send_addr_t);
DEFINE_XEN_GUEST_HANDLE(argo_ring_t);
DEFINE_XEN_GUEST_HANDLE(argo_ring_data_t);
DEFINE_XEN_GUEST_HANDLE(argo_ring_data_ent_t);
DEFINE_XEN_GUEST_HANDLE(uint8_t);

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
    /* counter of rings registered by this domain, protected by L2 */
    uint32_t ring_count;
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

static struct argo_ring_info *
argo_ring_find_info_by_match(const struct domain *d, uint32_t port,
                             domid_t partner_id, uint64_t partner_cookie);

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
 * Event channel
 */

static void
argo_signal_domain(struct domain *d)
{
    argo_dprintk("signalling domid:%d\n", d->domain_id);

    if ( !d->argo ) /* This can happen if the domain is being destroyed */
        return;

    evtchn_send(d, d->argo->evtchn_port);
}

static void
argo_signal_domid(domid_t id)
{
    struct domain *d = get_domain_by_id(id);

    if ( !d )
        return;

    argo_signal_domain(d);

    put_domain(d);
}

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

static int
argo_memcpy_to_guest_ring(struct argo_ring_info *ring_info,
                          uint32_t offset,
                          const void *src,
                          XEN_GUEST_HANDLE(uint8_t) src_hnd,
                          uint32_t len)
{
    int page = offset >> PAGE_SHIFT;
    uint8_t *dst;
    int ret;
    unsigned int src_offset = 0;

    ASSERT(spin_is_locked(&ring_info->lock));

    offset &= ~PAGE_MASK;

    if ( (len > ARGO_MAX_RING_SIZE) || (offset > ARGO_MAX_RING_SIZE) )
        return -EFAULT;

    while ( (offset + len) > PAGE_SIZE )
    {
        ret = argo_ring_map_page(ring_info, page, &dst);
        if ( ret )
            return ret;

        if ( src )
        {
            memcpy(dst + offset, src + src_offset, PAGE_SIZE - offset);
            src_offset += (PAGE_SIZE - offset);
        }
        else
        {
            ret = copy_from_guest_errno(dst + offset, src_hnd,
                                        PAGE_SIZE - offset);
            if ( ret )
                return ret;

            guest_handle_add_offset(src_hnd, PAGE_SIZE - offset);
        }

        page++;
        len -= PAGE_SIZE - offset;
        offset = 0;
    }

    ret = argo_ring_map_page(ring_info, page, &dst);
    if ( ret )
    {
        argo_dprintk("argo: ring (vm%u:%x vm%d) %p attempted to map page"
               " %d of %d\n", ring_info->id.addr.domain_id,
               ring_info->id.addr.port, ring_info->id.partner, ring_info,
               page, ring_info->nmfns);
        return ret;
    }

    if ( src )
        memcpy(dst + offset, src + src_offset, len);
    else
        ret = copy_from_guest_errno(dst + offset, src_hnd, len);

    return ret;
}

static int
argo_ringbuf_get_rx_ptr(struct argo_ring_info *ring_info, uint32_t *rx_ptr)
{
    uint8_t *src;
    argo_ring_t *ringp;
    int ret;

    ASSERT(spin_is_locked(&ring_info->lock));

    if ( !ring_info->nmfns || ring_info->nmfns < ring_info->npage )
        return -EINVAL;

    ret = argo_ring_map_page(ring_info, 0, &src);
    if ( ret )
        return ret;

    ringp = (argo_ring_t *)src;

    *rx_ptr = read_atomic(&ringp->rx_ptr);

    return 0;
}

static uint32_t
argo_ringbuf_payload_space(struct domain *d, struct argo_ring_info *ring_info)
{
    argo_ring_t ring;
    int32_t ret;

    ASSERT(spin_is_locked(&ring_info->lock));

    ring.len = ring_info->len;
    if ( !ring.len )
        return 0;

    ring.tx_ptr = ring_info->tx_ptr;

    if ( argo_ringbuf_get_rx_ptr(ring_info, &ring.rx_ptr) )
        return 0;

    argo_dprintk("argo_ringbuf_payload_space: tx_ptr=%d rx_ptr=%d\n",
                 ring.tx_ptr, ring.rx_ptr);

    if ( ring.rx_ptr == ring.tx_ptr )
        return ring.len - sizeof(struct argo_ring_message_header);

    ret = ring.rx_ptr - ring.tx_ptr;
    if ( ret < 0 )
        ret += ring.len;

    ret -= sizeof(struct argo_ring_message_header);
    ret -= ARGO_ROUNDUP(1);

    return (ret < 0) ? 0 : ret;
}

/*
 * argo_sanitize_ring creates a modified copy of the ring pointers
 * where the rx_ptr is rounded up to ensure it is aligned, and then
 * ring wrap is handled. Simplifies safe use of the rx_ptr for
 * available space calculation.
 */
static void
argo_sanitize_ring(argo_ring_t *ring, const struct argo_ring_info *ring_info)
{
    uint32_t rx_ptr = ring->rx_ptr;

    ring->tx_ptr = ring_info->tx_ptr;
    ring->len = ring_info->len;

    rx_ptr = ARGO_ROUNDUP(rx_ptr);
    if ( rx_ptr >= ring_info->len )
        rx_ptr = 0;

    ring->rx_ptr = rx_ptr;
}

/*
 * argo_iov_count returns its count on success via an out variable
 * to avoid potential for a negative return value to be used incorrectly
 * (eg. coerced into an unsigned variable resulting in a large incorrect value)
 */
static int
argo_iov_count(XEN_GUEST_HANDLE_PARAM(argo_iov_t) iovs, uint8_t niov,
               uint32_t *count)
{
    argo_iov_t iov;
    uint32_t sum_iov_lens = 0;
    int ret;

    if ( niov > ARGO_MAXIOV )
        return -EINVAL;

    while ( niov-- )
    {
        ret = copy_from_guest_errno(&iov, iovs, 1);
        if ( ret )
            return ret;

        /* check each to protect sum against integer overflow */
        if ( iov.iov_len > ARGO_MAX_RING_SIZE )
            return -EINVAL;

        sum_iov_lens += iov.iov_len;

        /*
         * Again protect sum from integer overflow
         * and ensure total msg size will be within bounds.
         */
        if ( sum_iov_lens > ARGO_MAX_MSG_SIZE )
            return -EINVAL;

        guest_handle_add_offset(iovs, 1);
    }

    *count = sum_iov_lens;
    return 0;
}

static int
argo_ringbuf_insert(struct domain *d,
                    struct argo_ring_info *ring_info,
                    const struct argo_ring_id *src_id,
                    XEN_GUEST_HANDLE_PARAM(argo_iov_t) iovs, uint8_t niov,
                    uint32_t message_type, unsigned long *out_len)
{
    argo_ring_t ring;
    struct argo_ring_message_header mh = { 0 };
    int32_t sp;
    int32_t ret = 0;
    uint32_t len;
    uint32_t iov_len;
    uint32_t sum_iov_len = 0;

    ASSERT(spin_is_locked(&ring_info->lock));

    if ( (ret = argo_iov_count(iovs, niov, &len)) )
        return ret;

    if ( ((ARGO_ROUNDUP(len) + sizeof (struct argo_ring_message_header) ) >=
          ring_info->len)
         || (len > ARGO_MAX_MSG_SIZE) )
        return -EMSGSIZE;

    do {
        ret =  argo_ringbuf_get_rx_ptr(ring_info, &ring.rx_ptr);
        if ( ret )
            break;

        argo_sanitize_ring(&ring, ring_info);

        argo_dprintk("ring.tx_ptr=%d ring.rx_ptr=%d ring.len=%d"
                     " ring_info->tx_ptr=%d\n",
                     ring.tx_ptr, ring.rx_ptr, ring.len, ring_info->tx_ptr);

        if ( ring.rx_ptr == ring.tx_ptr )
            sp = ring_info->len;
        else
        {
            sp = ring.rx_ptr - ring.tx_ptr;
            if ( sp < 0 )
                sp += ring.len;
        }

        if ( (ARGO_ROUNDUP(len) + sizeof(struct argo_ring_message_header)) >= sp )
        {
            argo_dprintk("EAGAIN\n");
            ret = -EAGAIN;
            break;
        }

        mh.len = len + sizeof(struct argo_ring_message_header);
        mh.source.port = src_id->addr.port;
        mh.source.domain_id = src_id->addr.domain_id;
        mh.message_type = message_type;

        /*
         * For this copy to the guest ring, tx_ptr is always 16-byte aligned
         * and the message header is 16 bytes long.
         */
        BUILD_BUG_ON(sizeof(struct argo_ring_message_header) != ARGO_ROUNDUP(1));

        if ( (ret = argo_memcpy_to_guest_ring(ring_info,
                                              ring.tx_ptr + sizeof(argo_ring_t),
                                              &mh,
                                              XEN_GUEST_HANDLE_NULL(uint8_t),
                                              sizeof(mh))) )
            break;

        ring.tx_ptr += sizeof(mh);
        if ( ring.tx_ptr == ring_info->len )
            ring.tx_ptr = 0;

        while ( niov-- )
        {
            XEN_GUEST_HANDLE_PARAM(uint8_t) bufp_hnd;
            XEN_GUEST_HANDLE(uint8_t) buf_hnd;
            argo_iov_t iov;

            ret = copy_from_guest_errno(&iov, iovs, 1);
            if ( ret )
                break;

            bufp_hnd = guest_handle_from_ptr((uintptr_t)iov.iov_base, uint8_t);
            buf_hnd = guest_handle_from_param(bufp_hnd, uint8_t);
            iov_len = iov.iov_len;

            if ( !iov_len )
            {
                printk(XENLOG_ERR "argo: iov.iov_len=0 iov.iov_base=%"
                       PRIx64" ring (vm%u:%x vm%d)\n",
                       iov.iov_base, ring_info->id.addr.domain_id,
                       ring_info->id.addr.port, ring_info->id.partner);

                guest_handle_add_offset(iovs, 1);
                continue;
            }

            if ( iov_len > ARGO_MAX_MSG_SIZE )
            {
                ret = -EINVAL;
                break;
            }

            sum_iov_len += iov_len;
            if ( sum_iov_len > len )
            {
                ret = -EINVAL;
                break;
            }

            if ( unlikely(!guest_handle_okay(buf_hnd, iov_len)) )
            {
                ret = -EFAULT;
                break;
            }

            sp = ring.len - ring.tx_ptr;

            if ( iov_len > sp )
            {
                ret = argo_memcpy_to_guest_ring(ring_info,
                        ring.tx_ptr + sizeof(argo_ring_t),
                        NULL, buf_hnd, sp);
                if ( ret )
                    break;

                ring.tx_ptr = 0;
                iov_len -= sp;
                guest_handle_add_offset(buf_hnd, sp);
            }

            ret = argo_memcpy_to_guest_ring(ring_info,
                        ring.tx_ptr + sizeof(argo_ring_t),
                        NULL, buf_hnd, iov_len);
            if ( ret )
                break;

            ring.tx_ptr += iov_len;

            if ( ring.tx_ptr == ring_info->len )
                ring.tx_ptr = 0;

            guest_handle_add_offset(iovs, 1);
        }

        if ( ret )
            break;

        ring.tx_ptr = ARGO_ROUNDUP(ring.tx_ptr);

        if ( ring.tx_ptr >= ring_info->len )
            ring.tx_ptr -= ring_info->len;

        mb();
        ring_info->tx_ptr = ring.tx_ptr;
        if ( (ret = argo_update_tx_ptr(ring_info, ring.tx_ptr)) )
            break;

    } while ( 0 );

    /*
     * At this point it is possible to unmap the ring_info, ie:
     *   argo_ring_unmap(ring_info);
     * but performance should be improved by not doing so, and retaining
     * the mapping.
     * An XSM policy control over level of confidentiality required
     * versus performance cost could be added to decide that here.
     * See the similar comment in argo_ring_map_page re: write-only mappings.
     */

    if ( !ret )
        *out_len = len;

    return ret;
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

static void
argo_pending_notify(struct hlist_head *to_notify)
{
    struct hlist_node *node, *next;
    struct argo_pending_ent *pending_ent;

    ASSERT(rw_is_locked(&argo_lock));

    hlist_for_each_entry_safe(pending_ent, node, next, to_notify, node)
    {
        hlist_del(&pending_ent->node);
        argo_signal_domid(pending_ent->id);
        xfree(pending_ent);
    }
}

static void
argo_pending_find(const struct domain *d, struct argo_ring_info *ring_info,
                  uint32_t payload_space, struct hlist_head *to_notify)
{
    struct hlist_node *node, *next;
    struct argo_pending_ent *ent;

    ASSERT(rw_is_locked(&d->argo->lock));

    spin_lock(&ring_info->lock);
    hlist_for_each_entry_safe(ent, node, next, &ring_info->pending, node)
    {
        if ( payload_space >= ent->len )
        {
            hlist_del(&ent->node);
            hlist_add_head(&ent->node, to_notify);
        }
    }
    spin_unlock(&ring_info->lock);
}

static int
argo_pending_queue(struct argo_ring_info *ring_info, domid_t src_id, int len)
{
    struct argo_pending_ent *ent;

    ASSERT(spin_is_locked(&ring_info->lock));

    ent = xmalloc(struct argo_pending_ent);

    if ( !ent )
        return -ENOMEM;

    ent->len = len;
    ent->id = src_id;

    hlist_add_head(&ent->node, &ring_info->pending);

    return 0;
}

static int
argo_pending_requeue(struct argo_ring_info *ring_info, domid_t src_id, int len)
{
    struct hlist_node *node;
    struct argo_pending_ent *ent;

    ASSERT(spin_is_locked(&ring_info->lock));

    hlist_for_each_entry(ent, node, &ring_info->pending, node)
    {
        if ( ent->id == src_id )
        {
            if ( ent->len < len )
                ent->len = len;
            return 0;
        }
    }

    return argo_pending_queue(ring_info, src_id, len);
}

static void
argo_pending_cancel(struct argo_ring_info *ring_info, domid_t src_id)
{
    struct hlist_node *node, *next;
    struct argo_pending_ent *ent;

    ASSERT(spin_is_locked(&ring_info->lock));

    hlist_for_each_entry_safe(ent, node, next, &ring_info->pending, node)
    {
        if ( ent->id == src_id)
        {
            hlist_del(&ent->node);
            xfree(ent);
        }
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

/*ring data*/

static int
argo_fill_ring_data(struct domain *src_d,
                    XEN_GUEST_HANDLE(argo_ring_data_ent_t) data_ent_hnd)
{
    argo_ring_data_ent_t ent;
    domid_t src_id;
    struct domain *dst_d;
    struct argo_ring_info *ring_info;
    int ret;

    ASSERT(rw_is_locked(&argo_lock));

    ret = copy_from_guest_errno(&ent, data_ent_hnd, 1);
    if ( ret )
        return ret;

    argo_dprintk("argo_fill_ring_data: ent.ring.domain=%u,ent.ring.port=%u\n",
                 ent.ring.domain_id, ent.ring.port);

    src_id = src_d->domain_id;
    ent.flags = 0;

    dst_d = get_domain_by_id(ent.ring.domain_id);

    if ( dst_d && dst_d->argo )
    {
        /*
         * Don't supply information about rings that a guest is not
         * allowed to send to.
         */
        ret = xsm_argo_send(src_d, dst_d);
        if ( ret )
        {
            put_domain(dst_d);
            return ret;
        }

        read_lock(&dst_d->argo->lock);

        ring_info = argo_ring_find_info_by_match(dst_d, ent.ring.port, src_id,
                                                 src_d->argo->domain_cookie);

        if ( ring_info )
        {
            uint32_t space_avail;

            ent.flags |= ARGO_RING_DATA_F_EXISTS;
            ent.max_message_size =
                ring_info->len - sizeof(struct argo_ring_message_header) -
                ARGO_ROUNDUP(1);

            spin_lock(&ring_info->lock);

            space_avail = argo_ringbuf_payload_space(dst_d, ring_info);

            argo_dprintk("argo_fill_ring_data: port=%d space_avail=%d"
                         " space_wanted=%d\n",
                         ring_info->id.addr.port, space_avail,
                         ent.space_required);

            if ( space_avail >= ent.space_required )
            {
                argo_pending_cancel(ring_info, src_id);
                ent.flags |= ARGO_RING_DATA_F_SUFFICIENT;
            }
            else
            {
                argo_pending_requeue(ring_info, src_id, ent.space_required);
                ent.flags |= ARGO_RING_DATA_F_PENDING;
            }

            spin_unlock(&ring_info->lock);

            if ( space_avail == ent.max_message_size )
                ent.flags |= ARGO_RING_DATA_F_EMPTY;

        }
        read_unlock(&dst_d->argo->lock);
    }

    if ( dst_d )
        put_domain(dst_d);

    ret = copy_field_to_guest_errno(data_ent_hnd, &ent, flags);
    if ( ret )
        return ret;
    ret = copy_field_to_guest_errno(data_ent_hnd, &ent, max_message_size);
    if ( ret )
        return ret;

    return 0;
}

static int
argo_fill_ring_data_array(struct domain *d, int nent,
                          XEN_GUEST_HANDLE(argo_ring_data_ent_t) data_ent_hnd)
{
    int ret = 0;

    ASSERT(rw_is_locked(&argo_lock));

    while ( !ret && nent-- )
    {
        ret = argo_fill_ring_data(d, data_ent_hnd);
        guest_handle_add_offset(data_ent_hnd, 1);
    }

    return ret;
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

static struct argo_ring_info *
argo_ring_find_info_by_match(const struct domain *d, uint32_t port,
                             domid_t partner_id, uint64_t partner_cookie)
{
    argo_ring_id_t id;
    struct argo_ring_info *ring_info;

    ASSERT(rw_is_locked(&d->argo->lock));

    id.addr.port = port;
    id.addr.domain_id = d->domain_id;
    id.partner = partner_id;

    ring_info = argo_ring_find_info(d, &id);
    if ( ring_info && (partner_cookie == ring_info->partner_cookie) )
        return ring_info;

    id.partner = ARGO_DOMID_ANY;

    return argo_ring_find_info(d, &id);
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
        {
            argo_ring_remove_info(d, ring_info);
            d->argo->ring_count--;
        }

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
            if ( d->argo->ring_count >= ARGO_MAX_RINGS_PER_DOMAIN )
            {
                ret = -ENOSPC;
                break;
            }

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
            {
                ring_info->len = ring.len;
                d->argo->ring_count++;
            }

        } while ( 0 );

        write_unlock(&d->argo->lock);

    } while ( 0 );

    read_unlock(&argo_lock);

    return ret;
}

/*
 * io
 */

static void
argo_notify_ring(struct domain *d, struct argo_ring_info *ring_info,
                struct hlist_head *to_notify)
{
    uint32_t space;

    ASSERT(rw_is_locked(&argo_lock));
    ASSERT(rw_is_locked(&d->argo->lock));

    spin_lock(&ring_info->lock);

    if ( ring_info->len )
        space = argo_ringbuf_payload_space(d, ring_info);
    else
        space = 0;

    spin_unlock(&ring_info->lock);

    if ( space )
        argo_pending_find(d, ring_info, space, to_notify);
}

static void
argo_notify_check_pending(struct domain *d)
{
    int i;
    HLIST_HEAD(to_notify);

    ASSERT(rw_is_locked(&argo_lock));

    read_lock(&d->argo->lock);

    mb();

    for ( i = 0; i < ARGO_HTABLE_SIZE; i++ )
    {
        struct hlist_node *node, *next;
        struct argo_ring_info *ring_info;

        hlist_for_each_entry_safe(ring_info, node, next,
                                  &d->argo->ring_hash[i], node)
        {
            argo_notify_ring(d, ring_info, &to_notify);
        }
    }
    read_unlock(&d->argo->lock);

    if ( !hlist_empty(&to_notify) )
        argo_pending_notify(&to_notify);
}

static long
argo_notify(struct domain *d,
            XEN_GUEST_HANDLE_PARAM(argo_ring_data_t) ring_data_hnd)
{
    argo_ring_data_t ring_data;
    int ret = 0;

    read_lock(&argo_lock);

    if ( !d->argo )
    {
        read_unlock(&argo_lock);
        argo_dprintk("!d->argo, ENODEV\n");
        return -ENODEV;
    }

    argo_notify_check_pending(d);

    do {
        if ( !guest_handle_is_null(ring_data_hnd) )
        {
            /* Quick sanity check on ring_data_hnd */
            ret = copy_field_from_guest_errno(&ring_data, ring_data_hnd, magic);
            if ( ret )
                break;

            if ( ring_data.magic != ARGO_RING_DATA_MAGIC )
            {
                argo_dprintk(
                    "ring.magic(%"PRIx64") != ARGO_RING_MAGIC(%llx), EINVAL\n",
                    ring_data.magic, ARGO_RING_MAGIC);
                ret = -EINVAL;
                break;
            }

            ret = copy_from_guest_errno(&ring_data, ring_data_hnd, 1);
            if ( ret )
                break;

            if ( ring_data.nent > ARGO_MAX_NOTIFY_COUNT )
            {
                ret = -EACCES;
                break;
            }

            {
                /*
                 * This is a guest pointer passed as a field in a struct
                 * so XEN_GUEST_HANDLE is used.
                 */
                XEN_GUEST_HANDLE(argo_ring_data_ent_t) ring_data_ent_hnd;
                ring_data_ent_hnd = guest_handle_for_field(ring_data_hnd,
                                                           argo_ring_data_ent_t,
                                                           data[0]);
                ret = argo_fill_ring_data_array(d, ring_data.nent,
                                                ring_data_ent_hnd);
            }
        }
    } while ( 0 );

    read_unlock(&argo_lock);

    return ret;
}

static long
argo_sendv(struct domain *src_d, const argo_addr_t *src_addr,
           const argo_addr_t *dst_addr,
           XEN_GUEST_HANDLE_PARAM(argo_iov_t) iovs, uint32_t niov,
           uint32_t message_type)
{
    struct domain *dst_d = NULL;
    struct argo_ring_id src_id;
    struct argo_ring_info *ring_info;
    int ret = 0;
    unsigned long len = 0;

    ASSERT(src_d->domain_id == src_addr->domain_id);

    read_lock(&argo_lock);

    do {
        if ( !src_d->argo )
        {
            ret = -ENODEV;
            break;
        }

        src_id.addr.pad = 0;
        src_id.addr.port = src_addr->port;
        src_id.addr.domain_id = src_d->domain_id;
        src_id.partner = dst_addr->domain_id;

        dst_d = get_domain_by_id(dst_addr->domain_id);
        if ( !dst_d || !dst_d->argo )
        {
            argo_dprintk("!dst_d, ECONNREFUSED\n");
            ret = -ECONNREFUSED;
            break;
        }

        ret = xsm_argo_send(src_d, dst_d);
        if ( ret )
        {
            printk(XENLOG_ERR "argo: XSM REJECTED %i -> %i\n",
                   src_addr->domain_id, dst_addr->domain_id);
            break;
        }

        read_lock(&dst_d->argo->lock);

        do {
            ring_info = argo_ring_find_info_by_match(dst_d, dst_addr->port,
                                                 src_addr->domain_id,
                                                 src_d->argo->domain_cookie);
            if ( !ring_info )
            {
                printk(XENLOG_ERR "argo: vm%u connection refused, "
                       "src (vm%u:%x) dst (vm%u:%x)\n",
                       current->domain->domain_id,
                       src_id.addr.domain_id, src_id.addr.port,
                       dst_addr->domain_id, dst_addr->port);

                ret = -ECONNREFUSED;
                break;
            }

            spin_lock(&ring_info->lock);

            ret = argo_ringbuf_insert(dst_d, ring_info, &src_id,
                                      iovs, niov, message_type, &len);
            if ( ret == -EAGAIN )
            {
                argo_dprintk("argo_ringbuf_sendv failed, EAGAIN\n");
                /* requeue to issue a notification when space is there */
                if ( argo_pending_requeue(ring_info, src_addr->domain_id, len) )
                     ret = -ENOMEM;
            }

            spin_unlock(&ring_info->lock);

            if ( ret >= 0 )
                argo_signal_domain(dst_d);

        } while ( 0 );

        read_unlock(&dst_d->argo->lock);

    } while ( 0 );

    if ( dst_d )
        put_domain(dst_d);

    read_unlock(&argo_lock);

    return ( ret < 0 ) ? ret : len;
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

    if ( unlikely(!opt_argo_enabled || xsm_argo_enable(d)) )
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
    case ARGO_MESSAGE_OP_sendv:
    {
        argo_send_addr_t send_addr;
        uint32_t niov = arg3;
        uint32_t message_type = arg4;

        XEN_GUEST_HANDLE_PARAM(argo_send_addr_t) send_addr_hnd =
            guest_handle_cast(arg1, argo_send_addr_t);
        XEN_GUEST_HANDLE_PARAM(argo_iov_t) iovs =
            guest_handle_cast(arg2, argo_iov_t);

        if ( unlikely(!guest_handle_okay(send_addr_hnd, 1)) )
            break;
        rc = copy_from_guest_errno(&send_addr, send_addr_hnd, 1);
        if ( rc )
            break;

        send_addr.src.domain_id = d->domain_id;

        rc = argo_sendv(d, &send_addr.src, &send_addr.dst,
                        iovs, niov, message_type);
        break;
    }
    case ARGO_MESSAGE_OP_notify:
    {
        XEN_GUEST_HANDLE_PARAM(argo_ring_data_t) ring_data_hnd =
                   guest_handle_cast(arg1, argo_ring_data_t);

        rc = argo_notify(d, ring_data_hnd);
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

    if ( !opt_argo_enabled || xsm_argo_enable(d) )
    {
        argo_dprintk("argo disabled, domid: %d\n", d->domain_id);
        return 0;
    }

    argo_dprintk("argo init: domid: %d\n", d->domain_id);

    argo = xmalloc(struct argo_domain);
    if ( !argo )
        return -ENOMEM;

    rwlock_init(&argo->lock);
    argo->ring_count = 0;

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
