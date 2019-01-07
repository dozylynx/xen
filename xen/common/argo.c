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
#include <xen/lib.h>
#include <xen/nospec.h>
#include <xen/time.h>
#include <public/argo.h>

#define MAX_RINGS_PER_DOMAIN            128U
#define MAX_NOTIFY_COUNT                256U
#define MAX_PENDING_PER_RING             32U

/* All messages on the ring are padded to a multiple of the slot size. */
#define ROUNDUP_MESSAGE(a) (ROUNDUP((a), XEN_ARGO_MSG_SLOT_SIZE))

/* The maximum size of a message that may be sent on the largest Argo ring. */
#define MAX_ARGO_MESSAGE_SIZE ((XEN_ARGO_MAX_RING_SIZE) - \
        (sizeof(struct xen_argo_ring_message_header)) - ROUNDUP_MESSAGE(1))

DEFINE_XEN_GUEST_HANDLE(xen_argo_addr_t);
DEFINE_XEN_GUEST_HANDLE(xen_argo_iov_t);
DEFINE_XEN_GUEST_HANDLE(xen_argo_page_descr_t);
DEFINE_XEN_GUEST_HANDLE(xen_argo_register_ring_t);
DEFINE_XEN_GUEST_HANDLE(xen_argo_ring_t);
DEFINE_XEN_GUEST_HANDLE(xen_argo_ring_data_t);
DEFINE_XEN_GUEST_HANDLE(xen_argo_ring_data_ent_t);
DEFINE_XEN_GUEST_HANDLE(xen_argo_send_addr_t);
DEFINE_XEN_GUEST_HANDLE(xen_argo_unregister_ring_t);

/* Xen command line option to enable argo */
static bool __read_mostly opt_argo_enabled;
boolean_param("argo", opt_argo_enabled);

/* Xen command line option for conservative or relaxed access control */
bool __read_mostly opt_argo_mac_enforcing = true;

static int __init parse_opt_argo_mac(const char *s)
{
    if ( !strcmp(s, "enforcing") )
        opt_argo_mac_enforcing = true;
    else if ( !strcmp(s, "permissive") )
        opt_argo_mac_enforcing = false;
    else
        return -EINVAL;

    return 0;
}
custom_param("argo-mac", parse_opt_argo_mac);

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

static struct argo_ring_info *
ring_find_info(const struct domain *d, const struct argo_ring_id *id);

static struct argo_ring_info *
ring_find_info_by_match(const struct domain *d, uint32_t port,
                        domid_t partner_id);

/*
 * This hash function is used to distribute rings within the per-domain
 * hash tables (d->argo->ring_hash and d->argo_send_hash). The hash table
 * will provide a struct if a match is found with a 'argo_ring_id' key:
 * ie. the key is a (domain id, port, partner domain id) tuple.
 * Since port number varies the most in expected use, and the Linux driver
 * allocates at both the high and low ends, incorporate high and low bits to
 * help with distribution.
 * Apply array_index_nospec as a defensive measure since this operates
 * on user-supplied input and the array size that it indexes into is known.
 */
static unsigned int
hash_index(const struct argo_ring_id *id)
{
    unsigned int hash;

    hash = (uint16_t)(id->port >> 16);
    hash ^= (uint16_t)id->port;
    hash ^= id->domain_id;
    hash ^= id->partner_id;
    hash &= (ARGO_HTABLE_SIZE - 1);

    return array_index_nospec(hash, ARGO_HTABLE_SIZE);
}

static void
signal_domain(struct domain *d)
{
    argo_dprintk("signalling domid:%d\n", d->domain_id);

    send_guest_global_virq(d, VIRQ_ARGO_MESSAGE);
}

static void
signal_domid(domid_t domain_id)
{
    struct domain *d = get_domain_by_id(domain_id);
    if ( !d )
        return;

    signal_domain(d);
    put_domain(d);
}

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

static int
ring_map_page(struct argo_ring_info *ring_info, unsigned int i, void **out_ptr)
{
    if ( i >= ring_info->nmfns )
    {
        gprintk(XENLOG_ERR,
               "argo: ring (vm%u:%x vm%d) %p attempted to map page  %u of %u\n",
                ring_info->id.domain_id, ring_info->id.port,
                ring_info->id.partner_id, ring_info, i, ring_info->nmfns);
        return -ENOMEM;
    }

    if ( !ring_info->mfns || !ring_info->mfn_mapping)
    {
        ASSERT_UNREACHABLE();
        ring_info->len = 0;
        return -ENOMEM;
    }

    if ( !ring_info->mfn_mapping[i] )
    {
        /*
         * TODO:
         * The first page of the ring contains the ring indices, so both read
         * and write access to the page is required by the hypervisor, but
         * read-access is not needed for this mapping for the remainder of the
         * ring.
         * Since this mapping will remain resident in Xen's address space for
         * the lifetime of the ring, and following the principle of least
         * privilege, it could be preferable to:
         *  # add a XSM check to determine what policy is wanted here
         *  # depending on the XSM query, optionally create this mapping as
         *    _write-only_ on platforms that can support it.
         *    (eg. Intel EPT/AMD NPT).
         */
        ring_info->mfn_mapping[i] = map_domain_page_global(ring_info->mfns[i]);

        if ( !ring_info->mfn_mapping[i] )
        {
            gprintk(XENLOG_ERR,
                "argo: ring (vm%u:%x vm%d) %p attempted to map page %u of %u\n",
                    ring_info->id.domain_id, ring_info->id.port,
                    ring_info->id.partner_id, ring_info, i, ring_info->nmfns);
            return -ENOMEM;
        }
        argo_dprintk("mapping page %"PRI_mfn" to %p\n",
                     mfn_x(ring_info->mfns[i]), ring_info->mfn_mapping[i]);
    }

    if ( out_ptr )
        *out_ptr = ring_info->mfn_mapping[i];

    return 0;
}

static void
update_tx_ptr(struct argo_ring_info *ring_info, uint32_t tx_ptr)
{
    void *dst;
    uint32_t *p;

    ASSERT(ring_info->mfn_mapping[0]);

    ring_info->tx_ptr = tx_ptr;

    dst = ring_info->mfn_mapping[0];
    p = dst + offsetof(xen_argo_ring_t, tx_ptr);

    write_atomic(p, tx_ptr);
    smp_wmb();
}

static int
memcpy_to_guest_ring(struct argo_ring_info *ring_info, uint32_t offset,
                     const void *src, XEN_GUEST_HANDLE(uint8_t) src_hnd,
                     uint32_t len)
{
    unsigned int mfns_index = offset >> PAGE_SHIFT;
    void *dst;
    int ret;
    unsigned int src_offset = 0;

    ASSERT(spin_is_locked(&ring_info->lock));

    offset &= ~PAGE_MASK;

    if ( (len > XEN_ARGO_MAX_RING_SIZE) || (offset > XEN_ARGO_MAX_RING_SIZE) )
        return -EFAULT;

    while ( (offset + len) > PAGE_SIZE )
    {
        unsigned int head_len = PAGE_SIZE - offset;

        ret = ring_map_page(ring_info, mfns_index, &dst);
        if ( ret )
            return ret;

        if ( src )
        {
            memcpy(dst + offset, src + src_offset, head_len);
            src_offset += head_len;
        }
        else
        {
            ret = copy_from_guest(dst + offset, src_hnd, head_len) ?
                    -EFAULT : 0;
            if ( ret )
                return ret;

            guest_handle_add_offset(src_hnd, head_len);
        }

        mfns_index++;
        len -= head_len;
        offset = 0;
    }

    ret = ring_map_page(ring_info, mfns_index, &dst);
    if ( ret )
    {
        argo_dprintk("argo: ring (vm%u:%x vm%d) %p attempted to map page"
                     " %d of %d\n", ring_info->id.domain_id, ring_info->id.port,
                     ring_info->id.partner_id, ring_info, mfns_index,
                     ring_info->nmfns);
        return ret;
    }

    if ( src )
        memcpy(dst + offset, src + src_offset, len);
    else
        ret = copy_from_guest(dst + offset, src_hnd, len) ? -EFAULT : 0;

    return ret;
}

/*
 * Use this with caution: rx_ptr is under guest control and may be bogus.
 * See get_sanitized_ring for a safer alternative.
 */
static int
get_rx_ptr(struct argo_ring_info *ring_info, uint32_t *rx_ptr)
{
    void *src;
    xen_argo_ring_t *ringp;
    int ret;

    ASSERT(spin_is_locked(&ring_info->lock));

    if ( !ring_info->nmfns || ring_info->nmfns < ring_info->npage )
        return -EINVAL;

    ret = ring_map_page(ring_info, 0, &src);
    if ( ret )
        return ret;

    ringp = (xen_argo_ring_t *)src;

    *rx_ptr = read_atomic(&ringp->rx_ptr);

    return 0;
}

/*
 * get_sanitized_ring creates a modified copy of the ring pointers where
 * the rx_ptr is rounded up to ensure it is aligned, and then ring
 * wrap is handled. Simplifies safe use of the rx_ptr for available
 * space calculation.
 */
static int
get_sanitized_ring(xen_argo_ring_t *ring, struct argo_ring_info *ring_info)
{
    uint32_t rx_ptr;
    int ret;

    ret = get_rx_ptr(ring_info, &rx_ptr);
    if ( ret )
        return ret;

    ring->tx_ptr = ring_info->tx_ptr;

    rx_ptr = ROUNDUP_MESSAGE(rx_ptr);
    if ( rx_ptr >= ring_info->len )
        rx_ptr = 0;

    ring->rx_ptr = rx_ptr;
    return 0;
}

static uint32_t
ringbuf_payload_space(struct domain *d, struct argo_ring_info *ring_info)
{
    xen_argo_ring_t ring;
    uint32_t len;
    int32_t ret;

    ASSERT(spin_is_locked(&ring_info->lock));

    len = ring_info->len;
    if ( !len )
        return 0;

    ret = get_sanitized_ring(&ring, ring_info);
    if ( ret )
        return 0;

    argo_dprintk("sanitized ringbuf_payload_space: tx_ptr=%d rx_ptr=%d\n",
                 ring.tx_ptr, ring.rx_ptr);

    /*
     * rx_ptr == tx_ptr means that the ring has been emptied, so return
     * the maximum payload size that can be accepted -- see message size
     * checking logic in the entry to ringbuf_insert which ensures that
     * there is always one message slot (of size ROUNDUP_MESSAGE(1)) left
     * available, preventing a ring from being entirely filled. This ensures
     * that matching ring indexes always indicate an empty ring and not a
     * full one.
     * The subtraction here will not underflow due to minimum size constraints
     * enforced on ring size elsewhere.
     */
    if ( ring.rx_ptr == ring.tx_ptr )
        return len - sizeof(struct xen_argo_ring_message_header)
                   - ROUNDUP_MESSAGE(1);

    ret = ring.rx_ptr - ring.tx_ptr;
    if ( ret < 0 )
        ret += len;

    /*
     * The maximum size payload for a message that will be accepted is:
     * (the available space between the ring indexes)
     *    minus (space for a message header)
     *    minus (space for one message slot)
     * since ringbuf_insert requires that one message slot be left
     * unfilled, to avoid filling the ring to capacity and confusing a full
     * ring with an empty one.
     * Since the ring indexes are sanitized, the value in ret is aligned, so
     * the simple subtraction here works to return the aligned value needed:
     */
    ret -= sizeof(struct xen_argo_ring_message_header);
    ret -= ROUNDUP_MESSAGE(1);

    return (ret < 0) ? 0 : ret;
}

/*
 * iov_count returns its count on success via an out variable to avoid
 * potential for a negative return value to be used incorrectly
 * (eg. coerced into an unsigned variable resulting in a large incorrect value)
 */
static int
iov_count(const xen_argo_iov_t *piov, unsigned long niov, uint32_t *count)
{
    uint32_t sum_iov_lens = 0;

    if ( niov > XEN_ARGO_MAXIOV )
        return -EINVAL;

    while ( niov-- )
    {
        /* valid iovs must have the padding field set to zero */
        if ( piov->pad )
        {
            argo_dprintk("invalid iov: padding is not zero\n");
            return -EINVAL;
        }

        /* check each to protect sum against integer overflow */
        if ( piov->iov_len > XEN_ARGO_MAX_RING_SIZE )
        {
            argo_dprintk("invalid iov_len: too big (%u)>%llu\n",
                         piov->iov_len, XEN_ARGO_MAX_RING_SIZE);
            return -EINVAL;
        }

        sum_iov_lens += piov->iov_len;

        /*
         * Again protect sum from integer overflow
         * and ensure total msg size will be within bounds.
         */
        if ( sum_iov_lens > MAX_ARGO_MESSAGE_SIZE )
        {
            argo_dprintk("invalid iov series: total message too big\n");
            return -EMSGSIZE;
        }

        piov++;
    }

    *count = sum_iov_lens;

    return 0;
}

static int
ringbuf_insert(struct domain *d, struct argo_ring_info *ring_info,
               const struct argo_ring_id *src_id,
               XEN_GUEST_HANDLE_PARAM(xen_argo_iov_t) iovs_hnd,
               unsigned long niov, uint32_t message_type,
               unsigned long *out_len)
{
    xen_argo_ring_t ring;
    struct xen_argo_ring_message_header mh = { 0 };
    int32_t sp;
    int32_t ret;
    uint32_t len = 0;
    xen_argo_iov_t iovs[XEN_ARGO_MAXIOV];
    xen_argo_iov_t *piov;
    XEN_GUEST_HANDLE(uint8_t) NULL_hnd =
       guest_handle_from_param(guest_handle_from_ptr(NULL, uint8_t), uint8_t);

    ASSERT(spin_is_locked(&ring_info->lock));

    ret = __copy_from_guest(iovs, iovs_hnd, niov) ? -EFAULT : 0;
    if ( ret )
        goto out;

    /*
     * Obtain the total size of data to transmit -- sets the 'len' variable
     * -- and sanity check that the iovs conform to size and number limits.
     * Enforced below: no more than 'len' bytes of guest data
     * (plus the message header) will be sent in this operation.
     */
    ret = iov_count(iovs, niov, &len);
    if ( ret )
        goto out;

    /*
     * Size bounds check against ring size and static maximum message limit.
     * The message must not fill the ring; there must be at least one slot
     * remaining so we can distinguish a full ring from an empty one.
     */
    if ( ((ROUNDUP_MESSAGE(len) +
            sizeof(struct xen_argo_ring_message_header)) >= ring_info->len) ||
         (len > MAX_ARGO_MESSAGE_SIZE) )
    {
        ret = -EMSGSIZE;
        goto out;
    }

    ret = get_sanitized_ring(&ring, ring_info);
    if ( ret )
        goto out;

    argo_dprintk("ring.tx_ptr=%d ring.rx_ptr=%d ring len=%d"
                 " ring_info->tx_ptr=%d\n",
                 ring.tx_ptr, ring.rx_ptr, ring_info->len, ring_info->tx_ptr);

    if ( ring.rx_ptr == ring.tx_ptr )
        sp = ring_info->len;
    else
    {
        sp = ring.rx_ptr - ring.tx_ptr;
        if ( sp < 0 )
            sp += ring_info->len;
    }

    /*
     * Size bounds check against currently available space in the ring.
     * Again: the message must not fill the ring leaving no space remaining.
     */
    if ( (ROUNDUP_MESSAGE(len) +
            sizeof(struct xen_argo_ring_message_header)) >= sp )
    {
        argo_dprintk("EAGAIN\n");
        ret = -EAGAIN;
        goto out;
    }

    mh.len = len + sizeof(struct xen_argo_ring_message_header);
    mh.source.port = src_id->port;
    mh.source.domain_id = src_id->domain_id;
    mh.message_type = message_type;

    /*
     * For this copy to the guest ring, tx_ptr is always 16-byte aligned
     * and the message header is 16 bytes long.
     */
    BUILD_BUG_ON(
        sizeof(struct xen_argo_ring_message_header) != ROUNDUP_MESSAGE(1));

    /*
     * First data write into the destination ring: fixed size, message header.
     * This cannot overrun because the available free space (value in 'sp')
     * is checked above and must be at least this size.
     */
    ret = memcpy_to_guest_ring(ring_info, ring.tx_ptr + sizeof(xen_argo_ring_t),
                               &mh, NULL_hnd, sizeof(mh));
    if ( ret )
    {
        gprintk(XENLOG_ERR,
                "argo: failed to write message header to ring (vm%u:%x vm%d)\n",
                ring_info->id.domain_id, ring_info->id.port,
                ring_info->id.partner_id);

        goto out;
    }

    ring.tx_ptr += sizeof(mh);
    if ( ring.tx_ptr == ring_info->len )
        ring.tx_ptr = 0;

    piov = iovs;

    while ( niov-- )
    {
        XEN_GUEST_HANDLE_64(uint8_t) buf_hnd = piov->iov_hnd;
        uint32_t iov_len = piov->iov_len;

        /* If no data is provided in this iov, moan and skip on to the next */
        if ( !iov_len )
        {
            gprintk(XENLOG_ERR,
                    "argo: no data iov_len=0 iov_hnd=%p ring (vm%u:%x vm%d)\n",
                    buf_hnd.p, ring_info->id.domain_id, ring_info->id.port,
                    ring_info->id.partner_id);

            piov++;
            continue;
        }

        if ( unlikely(!guest_handle_okay(buf_hnd, iov_len)) )
        {
            gprintk(XENLOG_ERR,
                    "argo: bad iov handle [%p, %"PRIx32"] (vm%u:%x vm%d)\n",
                    buf_hnd.p, iov_len,
                    ring_info->id.domain_id, ring_info->id.port,
                    ring_info->id.partner_id);

            ret = -EFAULT;
            goto out;
        }

        sp = ring_info->len - ring.tx_ptr;

        /* Check: iov data size versus free space at the tail of the ring */
        if ( iov_len > sp )
        {
            /*
             * Second possible data write: ring-tail-wrap-write.
             * Populate the ring tail and update the internal tx_ptr to handle
             * wrapping at the end of ring.
             * Size of data written here: sp
             * which is the exact full amount of free space available at the
             * tail of the ring, so this cannot overrun.
             */
            ret = memcpy_to_guest_ring(ring_info,
                                       ring.tx_ptr + sizeof(xen_argo_ring_t),
                                       NULL, buf_hnd, sp);
            if ( ret )
            {
                gprintk(XENLOG_ERR,
                        "argo: failed to copy {%p, %"PRIx32"} (vm%u:%x vm%d)\n",
                        buf_hnd.p, sp,
                        ring_info->id.domain_id, ring_info->id.port,
                        ring_info->id.partner_id);

                goto out;
            }

            ring.tx_ptr = 0;
            iov_len -= sp;
            guest_handle_add_offset(buf_hnd, sp);

            ASSERT(iov_len <= ring_info->len);
        }

        /*
         * Third possible data write: all data remaining for this iov.
         * Size of data written here: iov_len
         *
         * Case 1: if the ring-tail-wrap-write above was performed, then
         *         iov_len has been decreased by 'sp' and ring.tx_ptr is zero.
         *
         *    We know from checking the result of iov_count:
         *      len + sizeof(message_header) <= ring_info->len
         *    We also know that len is the total of summing all iov_lens, so:
         *       iov_len <= len
         *    so by transitivity:
         *       iov_len <= len <= (ring_info->len - sizeof(msgheader))
         *    and therefore:
         *       (iov_len + sizeof(msgheader) <= ring_info->len) &&
         *       (ring.tx_ptr == 0)
         *    so this write cannot overrun here.
         *
         * Case 2: ring-tail-wrap-write above was not performed
         *    -> so iov_len is the guest-supplied value and: (iov_len <= sp)
         *    ie. less than available space at the tail of the ring:
         *        so this write cannot overrun.
         */
        ret = memcpy_to_guest_ring(ring_info,
                                   ring.tx_ptr + sizeof(xen_argo_ring_t),
                                   NULL, buf_hnd, iov_len);
        if ( ret )
        {
            gprintk(XENLOG_ERR,
                    "argo: failed to copy [%p, %"PRIx32"] (vm%u:%x vm%d)\n",
                    buf_hnd.p, iov_len, ring_info->id.domain_id,
                    ring_info->id.port, ring_info->id.partner_id);

            goto out;
        }

        ring.tx_ptr += iov_len;

        if ( ring.tx_ptr == ring_info->len )
            ring.tx_ptr = 0;

        piov++;
    }

    ring.tx_ptr = ROUNDUP_MESSAGE(ring.tx_ptr);

    if ( ring.tx_ptr >= ring_info->len )
        ring.tx_ptr -= ring_info->len;

    update_tx_ptr(ring_info, ring.tx_ptr);

 out:
    /*
     * At this point it is possible to unmap the ring_info, ie:
     *   ring_unmap(ring_info);
     * but performance should be improved by not doing so, and retaining
     * the mapping.
     * An XSM policy control over level of confidentiality required
     * versus performance cost could be added to decide that here.
     * See the similar comment in ring_map_page re: write-only mappings.
     */

    if ( !ret )
        *out_len = len;

    return ret;
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
wildcard_pending_list_insert(domid_t domain_id, struct pending_ent *ent)
{
    struct domain *d = get_domain_by_id(domain_id);
    if ( !d )
        return;

    if ( d->argo )
    {
        spin_lock(&d->argo->wildcard_lock);
        hlist_add_head(&ent->wildcard_node, &d->argo->wildcard_pend_list);
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
pending_notify(struct hlist_head *to_notify)
{
    struct hlist_node *node, *next;
    struct pending_ent *ent;

    ASSERT(rw_is_locked(&argo_lock));

    hlist_for_each_entry_safe(ent, node, next, to_notify, node)
    {
        hlist_del(&ent->node);
        signal_domid(ent->domain_id);
        xfree(ent);
    }
}

static void
pending_find(const struct domain *d, struct argo_ring_info *ring_info,
             uint32_t payload_space, struct hlist_head *to_notify)
{
    struct hlist_node *node, *next;
    struct pending_ent *ent;

    ASSERT(rw_is_locked(&d->argo->lock));

    /*
     * TODO: Current policy here is to signal _all_ of the waiting domains
     *       interested in sending a message of size less than payload_space.
     *
     * This is likely to be suboptimal, since once one of them has added
     * their message to the ring, there may well be insufficient room
     * available for any of the others to transmit, meaning that they were
     * woken in vain, which created extra work just to requeue their wait.
     *
     * Retain this simple policy for now since it at least avoids starving a
     * domain of available space notifications because of a policy that only
     * notified other domains instead. Improvement may be possible;
     * investigation required.
     */

    spin_lock(&ring_info->lock);
    hlist_for_each_entry_safe(ent, node, next, &ring_info->pending, node)
    {
        if ( payload_space >= ent->len )
        {
            if ( ring_info->id.partner_id == XEN_ARGO_DOMID_ANY )
                wildcard_pending_list_remove(ent->domain_id, ent);
            hlist_del(&ent->node);
            ring_info->npending--;
            hlist_add_head(&ent->node, to_notify);
        }
    }
    spin_unlock(&ring_info->lock);
}

static int
pending_queue(struct argo_ring_info *ring_info, domid_t src_id,
              unsigned int len)
{
    struct pending_ent *ent;

    ASSERT(spin_is_locked(&ring_info->lock));

    if ( ring_info->npending >= MAX_PENDING_PER_RING )
        return -ENOSPC;

    ent = xmalloc(struct pending_ent);

    if ( !ent )
        return -ENOMEM;

    ent->len = len;
    ent->domain_id = src_id;
    ent->ring_info = ring_info;

    if ( ring_info->id.partner_id == XEN_ARGO_DOMID_ANY )
        wildcard_pending_list_insert(src_id, ent);
    hlist_add_head(&ent->node, &ring_info->pending);
    ring_info->npending++;

    return 0;
}

static int
pending_requeue(struct argo_ring_info *ring_info, domid_t src_id,
                unsigned int len)
{
    struct hlist_node *node;
    struct pending_ent *ent;

    ASSERT(spin_is_locked(&ring_info->lock));

    hlist_for_each_entry(ent, node, &ring_info->pending, node)
    {
        if ( ent->domain_id == src_id )
        {
            /*
             * Reuse an existing queue entry for a notification rather than add
             * another. If the existing entry is waiting for a smaller size than
             * the current message then adjust the record to wait for the
             * current (larger) size to be available before triggering a
             * notification.
             * This assists the waiting sender by ensuring that whenever a
             * notification is triggered, there is sufficient space available
             * for (at least) any one of the messages awaiting transmission.
             */
            if ( ent->len < len )
                ent->len = len;

            return 0;
        }
    }

    return pending_queue(ring_info, src_id, len);
}

static void
pending_cancel(struct argo_ring_info *ring_info, domid_t src_id)
{
    struct hlist_node *node, *next;
    struct pending_ent *ent;

    ASSERT(spin_is_locked(&ring_info->lock));

    hlist_for_each_entry_safe(ent, node, next, &ring_info->pending, node)
    {
        if ( ent->domain_id == src_id )
        {
            if ( ring_info->id.partner_id == XEN_ARGO_DOMID_ANY )
                wildcard_pending_list_remove(ent->domain_id, ent);
            hlist_del(&ent->node);
            xfree(ent);
            ring_info->npending--;
        }
    }
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

static int
fill_ring_data(const struct domain *currd,
               XEN_GUEST_HANDLE(xen_argo_ring_data_ent_t) data_ent_hnd)
{
    xen_argo_ring_data_ent_t ent;
    struct domain *dst_d;
    struct argo_ring_info *ring_info;
    int ret;

    ASSERT(rw_is_locked(&argo_lock));

    ret = __copy_from_guest(&ent, data_ent_hnd, 1) ? -EFAULT : 0;
    if ( ret )
        goto out;

    argo_dprintk("fill_ring_data: ent.ring.domain=%u,ent.ring.port=%x\n",
                 ent.ring.domain_id, ent.ring.port);

    ent.flags = 0;

    dst_d = get_domain_by_id(ent.ring.domain_id);
    if ( dst_d )
    {
        if ( dst_d->argo )
        {
            read_lock(&dst_d->argo->lock);

            ring_info = ring_find_info_by_match(dst_d, ent.ring.port,
                                                currd->domain_id);
            if ( ring_info )
            {
                uint32_t space_avail;

                ent.flags |= XEN_ARGO_RING_DATA_F_EXISTS;
                ent.max_message_size = ring_info->len -
                                   sizeof(struct xen_argo_ring_message_header) -
                                   ROUNDUP_MESSAGE(1);

                if ( ring_info->id.partner_id == XEN_ARGO_DOMID_ANY )
                    ent.flags |= XEN_ARGO_RING_DATA_F_SHARED;

                spin_lock(&ring_info->lock);

                space_avail = ringbuf_payload_space(dst_d, ring_info);

                argo_dprintk("fill_ring_data: port=%x space_avail=%u"
                             " space_wanted=%u\n",
                             ring_info->id.port, space_avail,
                             ent.space_required);

                /* Do not queue a notification for an unachievable size */
                if ( ent.space_required > ent.max_message_size )
                    ent.flags |= XEN_ARGO_RING_DATA_F_EMSGSIZE;
                else if ( space_avail >= ent.space_required )
                {
                    pending_cancel(ring_info, currd->domain_id);
                    ent.flags |= XEN_ARGO_RING_DATA_F_SUFFICIENT;
                }
                else
                {
                    pending_requeue(ring_info, currd->domain_id,
                                    ent.space_required);
                    ent.flags |= XEN_ARGO_RING_DATA_F_PENDING;
                }

                spin_unlock(&ring_info->lock);

                if ( space_avail == ent.max_message_size )
                    ent.flags |= XEN_ARGO_RING_DATA_F_EMPTY;

            }
            read_unlock(&dst_d->argo->lock);
        }
        put_domain(dst_d);
    }

    ret = __copy_field_to_guest(data_ent_hnd, &ent, flags) ? -EFAULT : 0;
    if ( ret )
        goto out;

    ret = __copy_field_to_guest(data_ent_hnd, &ent, max_message_size) ?
                -EFAULT : 0;
 out:
    return ret;
}

static int
find_ring_mfn(struct domain *d, gfn_t gfn, mfn_t *mfn)
{
    p2m_type_t p2mt;
    int ret = 0;

#ifdef CONFIG_X86
    *mfn = get_gfn_unshare(d, gfn_x(gfn), &p2mt);
#else
    *mfn = p2m_lookup(d, gfn, &p2mt);
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
    put_gfn(d, gfn_x(gfn));
#endif

    return ret;
}

static int
find_ring_mfns(struct domain *d, struct argo_ring_info *ring_info,
               uint32_t npage,
               XEN_GUEST_HANDLE_PARAM(xen_argo_page_descr_t) pg_descr_hnd,
               uint32_t len)
{
    unsigned int i;
    int ret = 0;
    mfn_t *mfns;
    uint8_t **mfn_mapping;

    /*
     * first bounds check on npage here also serves as an overflow check
     * before left shifting it
     */
    if ( (unlikely(npage > (XEN_ARGO_MAX_RING_SIZE >> PAGE_SHIFT))) ||
         ((npage << PAGE_SHIFT) < len) )
        return -EINVAL;

    if ( ring_info->mfns )
    {
        /* Ring already existed: drop the previous mapping. */
        gprintk(XENLOG_INFO,
         "argo: vm%u re-register existing ring (vm%u:%x vm%d) clears mapping\n",
                d->domain_id, ring_info->id.domain_id,
                ring_info->id.port, ring_info->id.partner_id);

        ring_remove_mfns(d, ring_info);
        ASSERT(!ring_info->mfns);
    }

    mfns = xmalloc_array(mfn_t, npage);
    if ( !mfns )
        return -ENOMEM;

    for ( i = 0; i < npage; i++ )
        mfns[i] = INVALID_MFN;

    mfn_mapping = xzalloc_array(uint8_t *, npage);
    if ( !mfn_mapping )
    {
        xfree(mfns);
        return -ENOMEM;
    }

    ring_info->npage = npage;
    ring_info->mfns = mfns;
    ring_info->mfn_mapping = mfn_mapping;

    ASSERT(ring_info->npage == npage);

    if ( ring_info->nmfns == ring_info->npage )
        return 0;

    for ( i = ring_info->nmfns; i < ring_info->npage; i++ )
    {
        xen_argo_page_descr_t pg_descr;
        gfn_t gfn;
        mfn_t mfn;

        ret = __copy_from_guest_offset(&pg_descr, pg_descr_hnd, i, 1) ?
                -EFAULT : 0;
        if ( ret )
            break;

        /* Implementation currently only supports handling 4K pages */
        if ( (pg_descr & XEN_ARGO_PAGE_DESCR_SIZE_MASK) !=
                XEN_ARGO_PAGE_DESCR_SIZE_4K )
        {
            ret = -EINVAL;
            break;
        }
        gfn = _gfn(pg_descr >> PAGE_SHIFT);

        ret = find_ring_mfn(d, gfn, &mfn);
        if ( ret )
        {
            gprintk(XENLOG_ERR,
               "argo: vm%u: invalid gfn %"PRI_gfn" r:(vm%u:%x vm%d) %p %d/%d\n",
                    d->domain_id, gfn_x(gfn), ring_info->id.domain_id,
                    ring_info->id.port, ring_info->id.partner_id,
                    ring_info, i, ring_info->npage);
            break;
        }

        ring_info->mfns[i] = mfn;

        argo_dprintk("%d: %"PRI_gfn" -> %"PRI_mfn"\n",
                     i, gfn_x(gfn), mfn_x(ring_info->mfns[i]));
    }

    ring_info->nmfns = i;

    if ( ret )
        ring_remove_mfns(d, ring_info);
    else
    {
        ASSERT(ring_info->nmfns == ring_info->npage);

        gprintk(XENLOG_DEBUG,
        "argo: vm%u ring (vm%u:%x vm%d) %p mfn_mapping %p npage %d nmfns %d\n",
                d->domain_id, ring_info->id.domain_id,
                ring_info->id.port, ring_info->id.partner_id, ring_info,
                ring_info->mfn_mapping, ring_info->npage, ring_info->nmfns);
    }

    return ret;
}

static struct argo_ring_info *
ring_find_info(const struct domain *d, const struct argo_ring_id *id)
{
    unsigned int ring_hash_index;
    struct hlist_node *node;
    struct argo_ring_info *ring_info;

    ASSERT(rw_is_locked(&d->argo->lock));

    ring_hash_index = hash_index(id);

    argo_dprintk("d->argo=%p, d->argo->ring_hash[%u]=%p id=%p\n",
                 d->argo, ring_hash_index,
                 d->argo->ring_hash[ring_hash_index].first, id);
    argo_dprintk("id.port=%x id.domain=vm%u id.partner_id=vm%d\n",
                 id->port, id->domain_id, id->partner_id);

    hlist_for_each_entry(ring_info, node, &d->argo->ring_hash[ring_hash_index],
                         node)
    {
        struct argo_ring_id *cmpid = &ring_info->id;

        if ( cmpid->port == id->port &&
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

static struct argo_ring_info *
ring_find_info_by_match(const struct domain *d, uint32_t port,
                        domid_t partner_id)
{
    struct argo_ring_id id;
    struct argo_ring_info *ring_info;

    ASSERT(rw_is_locked(&d->argo->lock));

    id.port = port;
    id.domain_id = d->domain_id;
    id.partner_id = partner_id;

    ring_info = ring_find_info(d, &id);
    if ( ring_info )
        return ring_info;

    id.partner_id = XEN_ARGO_DOMID_ANY;

    return ring_find_info(d, &id);
}

static struct argo_send_info *
send_find_info(const struct domain *d, const struct argo_ring_id *id)
{
    struct hlist_node *node;
    struct argo_send_info *send_info;

    hlist_for_each_entry(send_info, node, &d->argo->send_hash[hash_index(id)],
                         node)
    {
        struct argo_ring_id *cmpid = &send_info->id;

        if ( cmpid->port == id->port &&
             cmpid->domain_id == id->domain_id &&
             cmpid->partner_id == id->partner_id )
        {
            argo_dprintk("send_info=%p\n", send_info);
            return send_info;
        }
    }
    argo_dprintk("no send_info found\n");

    return NULL;
}

static long
unregister_ring(struct domain *currd,
                XEN_GUEST_HANDLE_PARAM(xen_argo_unregister_ring_t) unreg_hnd)
{
    xen_argo_unregister_ring_t unreg;
    struct argo_ring_id ring_id;
    struct argo_ring_info *ring_info;
    struct argo_send_info *send_info;
    struct domain *dst_d = NULL;
    int ret;

    ret = copy_from_guest(&unreg, unreg_hnd, 1) ? -EFAULT : 0;
    if ( ret )
        goto out;

    ret = unreg.pad ? -EINVAL : 0;
    if ( ret )
        goto out;

    ring_id.partner_id = unreg.partner_id;
    ring_id.port = unreg.port;
    ring_id.domain_id = currd->domain_id;

    read_lock(&argo_lock);

    if ( !currd->argo )
    {
        ret = -ENODEV;
        goto out_unlock;
    }

    write_lock(&currd->argo->lock);

    ring_info = ring_find_info(currd, &ring_id);
    if ( ring_info )
    {
        ring_remove_info(currd, ring_info);
        currd->argo->ring_count--;
    }

    dst_d = get_domain_by_id(ring_id.partner_id);
    if ( dst_d )
    {
        if ( dst_d->argo )
        {
            spin_lock(&dst_d->argo->send_lock);

            send_info = send_find_info(dst_d, &ring_id);
            if ( send_info )
            {
                hlist_del(&send_info->node);
                xfree(send_info);
            }

            spin_unlock(&dst_d->argo->send_lock);
        }
        put_domain(dst_d);
    }

    write_unlock(&currd->argo->lock);

    if ( !ring_info )
    {
        argo_dprintk("ENOENT\n");
        ret = -ENOENT;
        goto out_unlock;
    }

 out_unlock:
    read_unlock(&argo_lock);

 out:
    return ret;
}

static long
register_ring(struct domain *currd,
              XEN_GUEST_HANDLE_PARAM(xen_argo_register_ring_t) reg_hnd,
              XEN_GUEST_HANDLE_PARAM(xen_argo_page_descr_t) pg_descr_hnd,
              uint32_t npage, bool fail_exist)
{
    xen_argo_register_ring_t reg;
    struct argo_ring_id ring_id;
    void *map_ringp;
    xen_argo_ring_t *ringp;
    struct argo_ring_info *ring_info;
    struct argo_send_info *send_info = NULL;
    struct domain *dst_d = NULL;
    int ret = 0;
    uint32_t private_tx_ptr;

    if ( copy_from_guest(&reg, reg_hnd, 1) )
    {
        ret = -EFAULT;
        goto out;
    }

    /*
     * A ring must be large enough to transmit messages, so requires space for:
     * * 1 message header, plus
     * * 1 payload slot (payload is always rounded to a multiple of 16 bytes)
     *   for the message payload to be written into, plus
     * * 1 more slot, so that the ring cannot be filled to capacity with a
     *   single message -- see the logic in ringbuf_insert -- allowing for this
     *   ensures that there can be space remaining when a message is present.
     * The above determines the minimum acceptable ring size.
     */
    if ( (reg.len < (sizeof(struct xen_argo_ring_message_header)
                      + ROUNDUP_MESSAGE(1) + ROUNDUP_MESSAGE(1))) ||
         (reg.len > XEN_ARGO_MAX_RING_SIZE) ||
         (reg.len != ROUNDUP_MESSAGE(reg.len)) ||
         (reg.pad != 0) )
    {
        ret = -EINVAL;
        goto out;
    }

    ring_id.partner_id = reg.partner_id;
    ring_id.port = reg.port;
    ring_id.domain_id = currd->domain_id;

    read_lock(&argo_lock);

    if ( !currd->argo )
    {
        ret = -ENODEV;
        goto out_unlock;
    }

    if ( reg.partner_id == XEN_ARGO_DOMID_ANY )
    {
        if ( opt_argo_mac_enforcing )
        {
            ret = -EPERM;
            goto out_unlock;
        }
    }
    else
    {
        dst_d = get_domain_by_id(reg.partner_id);
        if ( !dst_d )
        {
            argo_dprintk("!dst_d, ESRCH\n");
            ret = -ESRCH;
            goto out_unlock;
        }

        if ( !dst_d->argo )
        {
            argo_dprintk("!dst_d->argo, ECONNREFUSED\n");
            ret = -ECONNREFUSED;
            put_domain(dst_d);
            goto out_unlock;
        }

        send_info = xzalloc(struct argo_send_info);
        if ( !send_info )
        {
            ret = -ENOMEM;
            put_domain(dst_d);
            goto out_unlock;
        }
        send_info->id = ring_id;
    }

    write_lock(&currd->argo->lock);

    if ( currd->argo->ring_count >= MAX_RINGS_PER_DOMAIN )
    {
        ret = -ENOSPC;
        goto out_unlock2;
    }

    ring_info = ring_find_info(currd, &ring_id);
    if ( !ring_info )
    {
        ring_info = xzalloc(struct argo_ring_info);
        if ( !ring_info )
        {
            ret = -ENOMEM;
            goto out_unlock2;
        }

        spin_lock_init(&ring_info->lock);

        ring_info->id = ring_id;
        INIT_HLIST_HEAD(&ring_info->pending);

        hlist_add_head(&ring_info->node,
                       &currd->argo->ring_hash[hash_index(&ring_info->id)]);

        gprintk(XENLOG_DEBUG, "argo: vm%u registering ring (vm%u:%x vm%d)\n",
                currd->domain_id, ring_id.domain_id, ring_id.port,
                ring_id.partner_id);
    }
    else
    {
        if ( ring_info->len )
        {
            /*
             * If the caller specified that the ring must not already exist,
             * fail at attempt to add a completed ring which already exists.
             */
            if ( fail_exist )
            {
                argo_dprintk("disallowed reregistration of existing ring\n");
                ret = -EEXIST;
                goto out_unlock2;
            }

            if ( ring_info->len != reg.len )
            {
                /*
                 * Change of ring size could result in entries on the pending
                 * notifications list that will never trigger.
                 * Simple blunt solution: disallow ring resize for now.
                 * TODO: investigate enabling ring resize.
                 */
                gprintk(XENLOG_ERR,
                    "argo: vm%u attempted to change ring size(vm%u:%x vm%d)\n",
                        currd->domain_id, ring_id.domain_id, ring_id.port,
                        ring_id.partner_id);
                /*
                 * Could return EINVAL here, but if the ring didn't already
                 * exist then the arguments would have been valid, so: EEXIST.
                 */
                ret = -EEXIST;
                goto out_unlock2;
            }

            gprintk(XENLOG_DEBUG,
                    "argo: vm%u re-registering existing ring (vm%u:%x vm%d)\n",
                    currd->domain_id, ring_id.domain_id, ring_id.port,
                    ring_id.partner_id);
        }
    }

    ret = find_ring_mfns(currd, ring_info, npage, pg_descr_hnd, reg.len);
    if ( ret )
    {
        gprintk(XENLOG_ERR,
                "argo: vm%u failed to find ring mfns (vm%u:%x vm%d)\n",
                currd->domain_id, ring_id.domain_id, ring_id.port,
                ring_id.partner_id);

        ring_remove_info(currd, ring_info);
        goto out_unlock2;
    }

    /*
     * The first page of the memory supplied for the ring has the xen_argo_ring
     * structure at its head, which is where the ring indexes reside.
     */
    ret = ring_map_page(ring_info, 0, &map_ringp);
    if ( ret )
    {
        gprintk(XENLOG_ERR,
                "argo: vm%u failed to map ring mfn 0 (vm%u:%x vm%d)\n",
                currd->domain_id, ring_id.domain_id, ring_id.port,
                ring_id.partner_id);

        ring_remove_info(currd, ring_info);
        goto out_unlock2;
    }
    ringp = map_ringp;

    private_tx_ptr = read_atomic(&ringp->tx_ptr);

    if ( (private_tx_ptr >= reg.len) ||
         (ROUNDUP_MESSAGE(private_tx_ptr) != private_tx_ptr) )
    {
        /*
         * Since the ring is a mess, attempt to flush the contents of it
         * here by setting the tx_ptr to the next aligned message slot past
         * the latest rx_ptr we have observed. Handle ring wrap correctly.
         */
        private_tx_ptr = ROUNDUP_MESSAGE(read_atomic(&ringp->rx_ptr));

        if ( private_tx_ptr >= reg.len )
            private_tx_ptr = 0;

        update_tx_ptr(ring_info, private_tx_ptr);
    }

    ring_info->tx_ptr = private_tx_ptr;
    ring_info->len = reg.len;
    currd->argo->ring_count++;

    if ( send_info )
    {
        spin_lock(&dst_d->argo->send_lock);

        hlist_add_head(&send_info->node,
                       &dst_d->argo->send_hash[hash_index(&send_info->id)]);

        spin_unlock(&dst_d->argo->send_lock);
    }

 out_unlock2:
    if ( !ret && send_info )
        xfree(send_info);

    if ( dst_d )
        put_domain(dst_d);

    write_unlock(&currd->argo->lock);

 out_unlock:
    read_unlock(&argo_lock);

 out:
    return ret;
}

static void
notify_ring(struct domain *d, struct argo_ring_info *ring_info,
            struct hlist_head *to_notify)
{
    uint32_t space;

    ASSERT(rw_is_locked(&argo_lock));
    ASSERT(rw_is_locked(&d->argo->lock));

    spin_lock(&ring_info->lock);

    if ( ring_info->len )
        space = ringbuf_payload_space(d, ring_info);
    else
        space = 0;

    spin_unlock(&ring_info->lock);

    if ( space )
        pending_find(d, ring_info, space, to_notify);
}

static void
notify_check_pending(struct domain *currd)
{
    unsigned int i;
    HLIST_HEAD(to_notify);

    ASSERT(rw_is_locked(&argo_lock));

    read_lock(&currd->argo->lock);

    for ( i = 0; i < ARGO_HTABLE_SIZE; i++ )
    {
        struct hlist_node *node, *next;
        struct argo_ring_info *ring_info;

        hlist_for_each_entry_safe(ring_info, node, next,
                                  &currd->argo->ring_hash[i], node)
        {
            notify_ring(currd, ring_info, &to_notify);
        }
    }

    read_unlock(&currd->argo->lock);

    if ( !hlist_empty(&to_notify) )
        pending_notify(&to_notify);
}

static long
notify(struct domain *currd,
       XEN_GUEST_HANDLE_PARAM(xen_argo_ring_data_t) ring_data_hnd)
{
    XEN_GUEST_HANDLE(xen_argo_ring_data_ent_t) ent_hnd;
    xen_argo_ring_data_t ring_data;
    int ret = 0;

    read_lock(&argo_lock);

    if ( !currd->argo )
    {
        argo_dprintk("!d->argo, ENODEV\n");
        ret = -ENODEV;
        goto out;
    }

    notify_check_pending(currd);

    if ( guest_handle_is_null(ring_data_hnd) )
        goto out;

    ret = copy_from_guest(&ring_data, ring_data_hnd, 1) ? -EFAULT : 0;
    if ( ret )
        goto out;

    if ( ring_data.nent > MAX_NOTIFY_COUNT )
    {
        gprintk(XENLOG_ERR,
                "argo: notify entry count(%u) exceeds max(%u)\n",
                ring_data.nent, MAX_NOTIFY_COUNT);
        ret = -EACCES;
        goto out;
    }

    ent_hnd = guest_handle_for_field(ring_data_hnd,
                                     xen_argo_ring_data_ent_t, data[0]);
    if ( unlikely(!guest_handle_okay(ent_hnd, ring_data.nent)) )
    {
        ret = -EFAULT;
        goto out;
    }

    while ( !ret && ring_data.nent-- )
    {
        ret = fill_ring_data(currd, ent_hnd);
        guest_handle_add_offset(ent_hnd, 1);
    }

 out:
    read_unlock(&argo_lock);

    return ret;
}

static long
sendv(struct domain *src_d, const xen_argo_addr_t *src_addr,
      const xen_argo_addr_t *dst_addr,
      XEN_GUEST_HANDLE_PARAM(xen_argo_iov_t) iovs_hnd, unsigned long niov,
      uint32_t message_type)
{
    struct domain *dst_d = NULL;
    struct argo_ring_id src_id;
    struct argo_ring_info *ring_info;
    int ret = 0;
    unsigned long len = 0;

    ASSERT(src_d->domain_id == src_addr->domain_id);

    argo_dprintk("sendv: (%d:%x)->(%d:%x) niov:%lu iov:%p type:%u\n",
                 src_addr->domain_id, src_addr->port,
                 dst_addr->domain_id, dst_addr->port,
                 niov, iovs_hnd.p, message_type);

    read_lock(&argo_lock);

    if ( !src_d->argo )
    {
        ret = -ENODEV;
        goto out_unlock;
    }

    src_id.port = src_addr->port;
    src_id.domain_id = src_d->domain_id;
    src_id.partner_id = dst_addr->domain_id;

    dst_d = get_domain_by_id(dst_addr->domain_id);
    if ( !dst_d )
    {
        argo_dprintk("!dst_d, ESRCH\n");
        ret = -ESRCH;
        goto out_unlock;
    }

    if ( !dst_d->argo )
    {
        argo_dprintk("!dst_d->argo, ECONNREFUSED\n");
        ret = -ECONNREFUSED;
        goto out_unlock;
    }

    read_lock(&dst_d->argo->lock);

    ring_info = ring_find_info_by_match(dst_d, dst_addr->port,
                                        src_addr->domain_id);
    if ( !ring_info )
    {
        gprintk(XENLOG_ERR,
                "argo: vm%u connection refused, src (vm%u:%x) dst (vm%u:%x)\n",
                current->domain->domain_id, src_id.domain_id, src_id.port,
                dst_addr->domain_id, dst_addr->port);

        ret = -ECONNREFUSED;
        goto out_unlock2;
    }

    spin_lock(&ring_info->lock);

    ret = ringbuf_insert(dst_d, ring_info, &src_id, iovs_hnd, niov,
                         message_type, &len);
    if ( ret == -EAGAIN )
    {
        argo_dprintk("argo_ringbuf_sendv failed, EAGAIN\n");
        /* requeue to issue a notification when space is there */
        ret = pending_requeue(ring_info, src_addr->domain_id, len);
    }

    spin_unlock(&ring_info->lock);

    if ( ret >= 0 )
        signal_domain(dst_d);

 out_unlock2:
    read_unlock(&dst_d->argo->lock);

 out_unlock:
    if ( dst_d )
        put_domain(dst_d);

    read_unlock(&argo_lock);

    return ( ret < 0 ) ? ret : len;
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
    case XEN_ARGO_OP_register_ring:
    {
        XEN_GUEST_HANDLE_PARAM(xen_argo_register_ring_t) reg_hnd =
            guest_handle_cast(arg1, xen_argo_register_ring_t);
        XEN_GUEST_HANDLE_PARAM(xen_argo_page_descr_t) pg_descr_hnd =
            guest_handle_cast(arg2, xen_argo_page_descr_t);
        /* arg3 is npage */
        /* arg4 is flags */
        bool fail_exist = arg4 & XEN_ARGO_REGISTER_FLAG_FAIL_EXIST;

        if ( unlikely(arg3 > (XEN_ARGO_MAX_RING_SIZE >> PAGE_SHIFT)) )
        {
            rc = -EINVAL;
            break;
        }
        /*
         * Check access to the whole array here so we can use the faster __copy
         * operations to read each element later.
         */
        if ( unlikely(!guest_handle_okay(pg_descr_hnd, arg3)) )
            break;
        /* arg4: reserve currently-undefined bits, require zero.  */
        if ( unlikely(arg4 & ~XEN_ARGO_REGISTER_FLAG_MASK) )
        {
            rc = -EINVAL;
            break;
        }

        rc = register_ring(currd, reg_hnd, pg_descr_hnd, arg3, fail_exist);
        break;
    }

    case XEN_ARGO_OP_unregister_ring:
    {
        XEN_GUEST_HANDLE_PARAM(xen_argo_unregister_ring_t) unreg_hnd =
            guest_handle_cast(arg1, xen_argo_unregister_ring_t);

        if ( unlikely((!guest_handle_is_null(arg2)) || arg3 || arg4) )
        {
            rc = -EINVAL;
            break;
        }

        rc = unregister_ring(currd, unreg_hnd);
        break;
    }

    case XEN_ARGO_OP_sendv:
    {
        xen_argo_send_addr_t send_addr;

        XEN_GUEST_HANDLE_PARAM(xen_argo_send_addr_t) send_addr_hnd =
            guest_handle_cast(arg1, xen_argo_send_addr_t);
        XEN_GUEST_HANDLE_PARAM(xen_argo_iov_t) iovs_hnd =
            guest_handle_cast(arg2, xen_argo_iov_t);
        /* arg3 is niov */
        /* arg4 is message_type. Must be a 32-bit value. */

        rc = copy_from_guest(&send_addr, send_addr_hnd, 1) ? -EFAULT : 0;
        if ( rc )
            break;

        if ( send_addr.src.domain_id == XEN_ARGO_DOMID_ANY )
            send_addr.src.domain_id = currd->domain_id;

        /* No domain is currently authorized to send on behalf of another */
        if ( unlikely(send_addr.src.domain_id != currd->domain_id) )
        {
            rc = -EPERM;
            break;
        }

        /* Reject niov or message_type values that are outside 32 bit range. */
        if ( unlikely((arg3 > XEN_ARGO_MAXIOV) || (arg4 & ~0xffffffffUL)) )
        {
            rc = -EINVAL;
            break;
        }

        /*
         * Check access to the whole array here so we can use the faster __copy
         * operations to read each element later.
         */
        if ( unlikely(!guest_handle_okay(iovs_hnd, arg3)) )
            break;

        rc = sendv(currd, &send_addr.src, &send_addr.dst, iovs_hnd, arg3, arg4);
        break;
    }

    case XEN_ARGO_OP_notify:
    {
        XEN_GUEST_HANDLE_PARAM(xen_argo_ring_data_t) ring_data_hnd =
                   guest_handle_cast(arg1, xen_argo_ring_data_t);

        if ( unlikely((!guest_handle_is_null(arg2)) || arg3 || arg4) )
        {
            rc = -EINVAL;
            break;
        }

        rc = notify(currd, ring_data_hnd);
        break;
    }

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
