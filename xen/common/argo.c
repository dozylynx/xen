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
#include <xen/lib.h>
#include <xen/nospec.h>
#include <xen/sched.h>
#include <xen/time.h>
#include <xsm/xsm.h>

#include <public/argo.h>

#ifdef CONFIG_COMPAT
#include <compat/argo.h>
CHECK_argo_addr;
#undef CHECK_argo_addr
#define CHECK_argo_addr struct xen_argo_addr
CHECK_argo_register_ring;
CHECK_argo_ring;
CHECK_argo_ring_data_ent;
#undef CHECK_argo_ring_data_ent
#define CHECK_argo_ring_data_ent struct xen_argo_ring_data_ent
CHECK_argo_ring_data;
CHECK_argo_ring_message_header;
CHECK_argo_unregister_ring;
CHECK_argo_send_addr;
#endif

#define MAX_RINGS_PER_DOMAIN            128U
#define MAX_NOTIFY_COUNT                256U
#define MAX_PENDING_PER_RING             32U

/* All messages on the ring are padded to a multiple of the slot size. */
#define ROUNDUP_MESSAGE(a) ROUNDUP((a), XEN_ARGO_MSG_SLOT_SIZE)

/* The maximum size of a message that may be sent on the largest Argo ring. */
#define MAX_ARGO_MESSAGE_SIZE ((XEN_ARGO_MAX_RING_SIZE) - \
        (sizeof(struct xen_argo_ring_message_header)) - ROUNDUP_MESSAGE(1))

/* Number of PAGEs needed to hold a ring of a given size in bytes */
#define NPAGES_RING(ring_len) \
    (ROUNDUP((ROUNDUP_MESSAGE(ring_len) + sizeof(xen_argo_ring_t)), PAGE_SIZE) \
     >> PAGE_SHIFT)

DEFINE_XEN_GUEST_HANDLE(xen_argo_addr_t);
DEFINE_XEN_GUEST_HANDLE(xen_argo_gfn_t);
DEFINE_XEN_GUEST_HANDLE(xen_argo_iov_t);
DEFINE_XEN_GUEST_HANDLE(xen_argo_register_ring_t);
DEFINE_XEN_GUEST_HANDLE(xen_argo_ring_t);
DEFINE_XEN_GUEST_HANDLE(xen_argo_ring_data_t);
DEFINE_XEN_GUEST_HANDLE(xen_argo_ring_data_ent_t);
DEFINE_XEN_GUEST_HANDLE(xen_argo_send_addr_t);
DEFINE_XEN_GUEST_HANDLE(xen_argo_unregister_ring_t);
#ifdef CONFIG_COMPAT
DEFINE_COMPAT_HANDLE(compat_argo_iov_t);
#endif

static bool __read_mostly opt_argo;
static bool __read_mostly opt_argo_mac_permissive;

static int __init parse_argo(const char *s)
{
    const char *ss;
    int val, rc = 0;

    do {
        ss = strchr(s, ',');
        if ( !ss )
            ss = strchr(s, '\0');

        if ( (val = parse_bool(s, ss)) >= 0 )
            opt_argo = val;
        else if ( (val = parse_boolean("mac-permissive", s, ss)) >= 0 )
            opt_argo_mac_permissive = val;
        else
            rc = -EINVAL;

        s = ss + 1;
    } while ( *ss );

    return rc;
}
custom_param("argo", parse_argo);

typedef struct argo_ring_id
{
    xen_argo_port_t aport;
    domid_t partner_id;
    domid_t domain_id;
} argo_ring_id;

/* Data about a domain's own ring that it has registered */
struct argo_ring_info
{
    /* next node in the hash, protected by rings_L3 */
    struct list_head node;
    /* this ring's id, protected by rings_L3 */
    struct argo_ring_id id;
    /* L4, the ring_info lock: protects the members of this struct below */
    spinlock_t L4_lock;
    /* length of the ring, protected by L4 */
    unsigned int len;
    /* number of pages translated into mfns, protected by L4 */
    unsigned int nmfns;
    /* cached tx pointer location, protected by L4 */
    unsigned int tx_ptr;
    /* mapped ring pages protected by L4 */
    void **mfn_mapping;
    /* list of mfns of guest ring, protected by L4 */
    mfn_t *mfns;
    /* list of struct pending_ent for this ring, protected by L4 */
    struct list_head pending;
    /* number of pending entries queued for this ring, protected by L4 */
    unsigned int npending;
};

/* A space-available notification that is awaiting sufficient space */
struct pending_ent
{
    /* List node within argo_ring_info's pending list */
    struct list_head node;
    /*
     * List node within argo_domain's wildcard_pend_list. Only used if the
     * ring is one with a wildcard partner (ie. that any domain may send to)
     * to enable cancelling signals on wildcard rings on domain destroy.
     */
    struct list_head wildcard_node;
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
#define ARGO_HASHTABLE_SIZE 32
struct argo_domain
{
    /* links_L2 */
    rwlock_t links_L2_rwlock;
    /*
     * Two hash tables of argo_link structs for domains that this domain has
     * registered rings to receive messages from. Both protected by links_L2.
     * The reason that there are two hashtables is to support the strategy
     * for avoiding deadlock when accessing the argo_links structs that are
     * shared between two domains.
     *
     * The upper_links_hash hashtable contains struct argo_links that are each
     * shared with another domain where that other domain has a domid that is
     * numerically higher than this domain's domid.
     * The lower_links_hash hashtable contains struct argo_links that are each
     * shared with another domain where that other domain has a domid that is
     * numerically lower than this domain's domid.
     *
     * In addition to those described just above, the lower_links_hash may also
     * contain a single struct argo_link for managing rings that a domain has
     * registered for communication with itself (ie. partner_id == domain_id).
     * This self-link is not shared with any other domain.
     *
     * The upper_links_hash may also contain a single struct argo_link for
     * managing all the wildcard rings that a domain has registered.
     * This wildcard-link is not shared with any other domain.
     */
    struct list_head upper_links_hash[ARGO_HASHTABLE_SIZE];
    struct list_head lower_links_hash[ARGO_HASHTABLE_SIZE];

    /* count_L2 */
    spinlock_t count_L2_lock;
    /* Counter of rings registered by this domain. Protected by count_L2. */
    unsigned int ring_count;

    /* wildcard_L2 */
    spinlock_t wildcard_L2_lock;
    /*
     * List of pending space-available signals for this domain about wildcard
     * rings registered by other domains. Protected by wildcard_L2.
     */
    struct list_head wildcard_pend_list;
};

/*
 * The argo_link struct is shared between two communicating domains, and tracks
 * all the non-wildcard rings that are registered to communcate between them.
 * An additional argo_link struct is allocated for each domain to track the
 * wildcard rings that it has registered.
 *
 * The domids of the two domains are stored within the struct, with the
 * numerically higher valued domid in 'upper_domain_id' and the other in
 * 'lower_domain_id'.
 * The list_heads allow the struct to be stored within each domain's hashtable:
 *      upper_d->argo->lower_links_hash[link_index(lower_d->domid)]
 *      lower_d->argo->upper_links_hash[link_index(upper_d->domid)]
 */
struct argo_link
{
    /*
     * Next nodes in domain's partner hashes.
     * upper_node is protected by upper_d->links_L2.
     * lower_node is protected by lower_d->links_L2.
     */
    struct list_head upper_node, lower_node;
    /* Domain ids: values are not modified after struct initialization. */
    domid_t upper_domain_id, lower_domain_id;

    /* rings_L3 */
    rwlock_t rings_L3_rwlock;
    /*
     * Hash table of argo_ring_info about rings this pair of domains
     * have registered for communication between them.
     * Protected by rings_L3.
     */
    struct list_head ring_hash[ARGO_HASHTABLE_SIZE];
};

/*
 * Locking is organized as follows:
 *
 * Terminology: R(<lock>) means taking a read lock on the specified lock;
 *              W(<lock>) means taking a write lock on it.
 *
 * == L1 : The global read/write lock: L1_global_argo_rwlock
 * Protects the argo elements of all struct domain *d in the system.
 *
 * R(L1) does not protect any of the elements of d->argo; it protects their
 * addresses. W(L1) protects those and more since it implies W on all the lower
 * level locks - see the notes on those locks below.
 *
 * The destruction of an argo-enabled domain, which must have a non-NULL d->argo
 * pointer, will need to free that d->argo pointer, which requires W(L1).
 * Since holding R(L1) will block acquiring W(L1), it will ensure that
 * no domains pointers that argo is interested in become invalid while either
 * W(L1) or R(L1) are held.
 */

static DEFINE_RWLOCK(L1_global_argo_rwlock); /* L1 */

/*
 * == links_L2 : The per-domain link hash lock: d->argo->links_L2_rwlock
 *
 * Holding a read lock on links_L2 protects the links hashtables:
 *  d->argo->upper_links_hash and d->argo->lower_links_hash
 * and the upper_node and lower_node fields in struct argo_link within the
 * hash tables.
 * To write to the argo_link, write locks must be acquired on _both_ the
 * links_L2 locks of the domains that share the link. To avoid deadlock,
 * the links_L2_lock on the domain with the numerically higher domid must be
 * acquired first.
 * nb: Not all links are shared between multiple domains -- specifically
 *     links for either rings-to-self or wildcard rings are owned by a single
 *     domain, so those are only protected by a single links_L2 lock.
 *
 * == rings_L3 : The per-link ring hash lock: link->rings_L3_rwlock
 *
 * Holding a read lock on rings_L3 protects the ring hash table and
 * the elements in the hash_table link->ring_hash, and the node and id fields
 * in struct argo_ring_info in the hash table.
 * Holding a write lock on rings_L3 protects all of the elements of all the
 * struct argo_ring_info belonging to this domain and the partner domain
 * (if any) that shares the link.
 *
 * To take rings_L3 you must already have R(L1) and R(links_L2).
 * W(L1) implies W(links_L2), W(rings_L3) and L4.
 *
 * == L4 : The individual ring_info lock: ring_info->L4_lock
 *
 * Protects all the fields within the argo_ring_info, aside from the ones that
 * rings_L3 already protects: node, id, lock.
 *
 * To acquire L4 you must already have R(rings_L3). W(rings_L3) implies L4.
 *
 * == count_L2 : The per-domain ring counter lock: d->argo->count_L2_lock;
 *
 * Protects d->argo->ring_count.
 *
 * To take count_L2, must hold R(L1) first. W(L1) implies count_L2.
 * count_L2 is only ever acquired by a domain acting on itself (ie. currd).
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
 * eg. On entry to logic that requires holding at least R(links_L2), this:
 *      ASSERT(LOCKING_Read_links_L2(d));
 *
 * checks that the lock state is sufficient, validating that one of the
 * following must be true when executed:       R(links_L2) && R(L1)
 *                                        or:  W(links_L2) && R(L1)
 *                                        or:  W(L1)
 *
 * The LOCKING macros defined below here are for use at verification points.
 */
#define LOCKING_Write_L1 (rw_is_write_locked(&L1_global_argo_rwlock))
/*
 * While LOCKING_Read_L1 will return true even if the lock is write-locked,
 * that's OK because everywhere that a Read lock is needed with these macros,
 * holding a Write lock there instead is OK too: we're checking that _at least_
 * the specified level of locks are held.
 */
#define LOCKING_Read_L1 (rw_is_locked(&L1_global_argo_rwlock))

#define LOCKING_Write_links_L2(d) \
    ((LOCKING_Read_L1 && rw_is_write_locked(&(d)->argo->links_L2_rwlock)) || \
     LOCKING_Write_L1)
/*
 * Skip checking LOCKING_Write_links_L2(d) within this LOCKING_Read_links_L2
 * definition because the first clause that is testing R(L1) && R(L2) will also
 * return true if R(L1) && W(L2) is true, because of the way that rw_is_locked
 * behaves. This results in a slightly shorter and faster implementation.
 */
#define LOCKING_Read_links_L2(d) \
    ((LOCKING_Read_L1 && rw_is_locked(&(d)->argo->links_L2_rwlock)) || \
     LOCKING_Write_L1)

#define LOCKING_Write_rings_L3(d,lnk) \
    ((LOCKING_Read_L1 && rw_is_locked(&(d)->argo->links_L2_rwlock) && \
      rw_is_write_locked(&(lnk)->rings_L3_rwlock)) || LOCKING_Write_links_L2(d))

#define LOCKING_Read_rings_L3(d,lnk) \
    ((LOCKING_Read_L1 && rw_is_locked(&(d)->argo->links_L2_rwlock) && \
      rw_is_locked(&(lnk)->rings_L3_rwlock)) || LOCKING_Write_links_L2(d))
/*
 * Skip checking LOCKING_Write_L1 within this LOCKING_L4 definition because
 * LOCKING_Write_rings_L3(d) will return true for that condition.
 */
#define LOCKING_L4(d, lnk, r) \
    ((LOCKING_Read_L1 && rw_is_locked(&(d)->argo->links_L2_rwlock) \
      && rw_is_locked(&(lnk)->rings_L3_rwlock) \
      && spin_is_locked(&(r)->L4_lock)) || LOCKING_Write_rings_L3(d, lnk))

/* Change this to #define ARGO_DEBUG here to enable more debug messages */
#undef ARGO_DEBUG

#ifdef ARGO_DEBUG
#define argo_dprintk(format, args...) printk("argo: " format, ## args )
#else
#define argo_dprintk(format, ... ) ((void)0)
#endif

/*
 * This hash function is used to distribute rings within the ring
 * hash tables (link->ring_hash). The hash table will provide a struct
 * if a match is found with a 'argo_ring_id' key:
 * ie. the key is a (domain id, argo port, partner domain id) tuple.
 * The algorithm approximates the string hashing function 'djb2'.
 */
static unsigned int
hash_index(const struct argo_ring_id *id)
{
    unsigned int hash = 5381; /* prime constant from djb2 */

    /* For each input: hash = hash * 33 + <new input character value> */
    hash = ((hash << 5) + hash) +  (id->aport            & 0xff);
    hash = ((hash << 5) + hash) + ((id->aport      >> 8) & 0xff);
    hash = ((hash << 5) + hash) + ((id->aport     >> 16) & 0xff);
    hash = ((hash << 5) + hash) + ((id->aport     >> 24) & 0xff);
    hash = ((hash << 5) + hash) +  (id->domain_id        & 0xff);
    hash = ((hash << 5) + hash) + ((id->domain_id  >> 8) & 0xff);
    hash = ((hash << 5) + hash) +  (id->partner_id       & 0xff);
    hash = ((hash << 5) + hash) + ((id->partner_id >> 8) & 0xff);

    /*
     * Since ARGO_HASHTABLE_SIZE is small, use higher-order bits of the
     * hash to contribute to the lower-order bits before masking off.
     */
    return (hash ^ (hash >> 15)) & (ARGO_HASHTABLE_SIZE - 1);
}

/* This is not especially efficient... */
static unsigned int
link_index(domid_t partner_id)
{
    struct argo_ring_id tmp;

    tmp.aport = 0;
    tmp.domain_id = 0;
    tmp.partner_id = partner_id;

    return hash_index(&tmp);
}

static struct argo_link *
find_link(const struct domain *d, domid_t partner_id)
{
    struct argo_link *link;
    const struct list_head *bucket;

    ASSERT(LOCKING_Read_links_L2(d));

    /* List is not modified here. Search and return the match if found. */
    if ( partner_id > d->domain_id )
    {
        bucket = &d->argo->upper_links_hash[link_index(partner_id)];

        list_for_each_entry(link, bucket, upper_node)
        {
            if ( link->upper_domain_id == partner_id )
                return link;
        }
    }
    else
    {
        bucket = &d->argo->lower_links_hash[link_index(partner_id)];

        list_for_each_entry(link, bucket, lower_node)
        {
            if ( link->lower_domain_id == partner_id )
                return link;
        }
    }

    return NULL;
}

static struct argo_ring_info *
find_ring_info(const struct domain *d, const struct argo_link *link,
               const struct argo_ring_id *id)
{
    struct argo_ring_info *ring_info;
    const struct list_head *bucket;

    ASSERT(LOCKING_Read_rings_L3(d, link));

    /* List is not modified here. Search and return the match if found. */
    bucket = &link->ring_hash[hash_index(id)];

    list_for_each_entry(ring_info, bucket, node)
    {
        const struct argo_ring_id *cmpid = &ring_info->id;

        if ( cmpid->aport == id->aport &&
             cmpid->domain_id == id->domain_id &&
             cmpid->partner_id == id->partner_id )
        {
            argo_dprintk("found ring_info for ring(%u:%x %u)\n",
                         id->domain_id, id->aport, id->partner_id);
            return ring_info;
        }
    }
    argo_dprintk("no ring_info for ring(%u:%x %u)\n",
                 id->domain_id, id->aport, id->partner_id);

    return NULL;
}

/*
 * FIXME: this is broken now because the wildcard rings are not tracked in the
 *        same link as the point-to-point links.
 */
static struct argo_ring_info *
find_ring_info_by_match(const struct domain *d, const struct argo_link *link,
                        const struct argo_ring_id *id)
{
    struct argo_ring_id tmpid;
    struct argo_ring_info *ring_info;

    ASSERT(LOCKING_Read_rings_L3(d, link));

    ring_info = find_ring_info(d, link, id);
    if ( ring_info )
        return ring_info;

    tmpid.aport = id->aport;
    tmpid.domain_id = id->domain_id;
    tmpid.partner_id = XEN_ARGO_DOMID_ANY;

    return find_ring_info(d, link, &tmpid);
}

static void
signal_domain(struct domain *d)
{
    argo_dprintk("signalling domid:%u\n", d->domain_id);

    send_guest_global_virq(d, VIRQ_ARGO);
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
ring_unmap(const struct domain *d, const struct argo_link *link,
           struct argo_ring_info *ring_info)
{
    unsigned int i;

    ASSERT(LOCKING_L4(d, link, ring_info));

    if ( !ring_info->mfn_mapping )
        return;

    ASSERT(!ring_info->nmfns || ring_info->mfns);

    for ( i = 0; i < ring_info->nmfns; i++ )
    {
        if ( !ring_info->mfn_mapping[i] )
            continue;

        ASSERT(!mfn_eq(ring_info->mfns[i], INVALID_MFN));
        argo_dprintk(XENLOG_ERR "argo: unmapping page %"PRI_mfn" from %p\n",
                     mfn_x(ring_info->mfns[i]), ring_info->mfn_mapping[i]);

        unmap_domain_page_global(ring_info->mfn_mapping[i]);
        ring_info->mfn_mapping[i] = NULL;
    }
}

static int
ring_map_page(const struct domain *d, const struct argo_link *link,
              struct argo_ring_info *ring_info, unsigned int i, void **out_ptr)
{
    ASSERT(LOCKING_L4(d, link, ring_info));

    /*
     * FIXME: Investigate using vmap to create a single contiguous virtual
     * address space mapping of the ring instead of using the array of single
     * page mappings.
     * Affects logic in memcpy_to_guest_ring, the mfn_mapping array data
     * structure, and places where ring mappings are added or removed.
     */

    if ( i >= ring_info->nmfns )
    {
        gprintk(XENLOG_ERR,
               "argo: ring (vm%u:%x vm%u) %p attempted to map page %u of %u\n",
                ring_info->id.domain_id, ring_info->id.aport,
                ring_info->id.partner_id, ring_info, i, ring_info->nmfns);
        return -ENOMEM;
    }
    i = array_index_nospec(i, ring_info->nmfns);

    if ( !ring_info->mfns || !ring_info->mfn_mapping )
    {
        ASSERT_UNREACHABLE();
        ring_info->len = 0;
        return -ENOMEM;
    }

    if ( !ring_info->mfn_mapping[i] )
    {
        ring_info->mfn_mapping[i] = map_domain_page_global(ring_info->mfns[i]);
        if ( !ring_info->mfn_mapping[i] )
        {
            gprintk(XENLOG_ERR, "argo: ring (vm%u:%x vm%u) %p attempted to map "
                    "page %u of %u\n",
                    ring_info->id.domain_id, ring_info->id.aport,
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
update_tx_ptr(const struct domain *d, const struct argo_link *link,
              struct argo_ring_info *ring_info, uint32_t tx_ptr)
{
    xen_argo_ring_t *ringp;

    ASSERT(LOCKING_L4(d, link, ring_info));
    ASSERT(ring_info->mfn_mapping[0]);

    ring_info->tx_ptr = tx_ptr;
    ringp = ring_info->mfn_mapping[0];

    write_atomic(&ringp->tx_ptr, tx_ptr);
    smp_wmb();
}

static int
memcpy_to_guest_ring(const struct domain *d, const struct argo_link *link,
                     struct argo_ring_info *ring_info, unsigned int offset,
                     const void *src, XEN_GUEST_HANDLE(uint8) src_hnd,
                     unsigned int len)
{
    unsigned int mfns_index = offset >> PAGE_SHIFT;
    void *dst;
    int ret;
    unsigned int src_offset = 0;

    ASSERT(LOCKING_L4(d, link, ring_info));

    offset &= ~PAGE_MASK;

    if ( len + offset > XEN_ARGO_MAX_RING_SIZE )
        return -EFAULT;

    while ( len )
    {
        unsigned int head_len = (offset + len) > PAGE_SIZE ? PAGE_SIZE - offset
                                                           : len;

        ret = ring_map_page(d, link, ring_info, mfns_index, &dst);
        if ( ret )
            return ret;

        if ( src )
        {
            memcpy(dst + offset, src + src_offset, head_len);
            src_offset += head_len;
        }
        else
        {
            if ( copy_from_guest(dst + offset, src_hnd, head_len) )
                return -EFAULT;

            guest_handle_add_offset(src_hnd, head_len);
        }

        mfns_index++;
        len -= head_len;
        offset = 0;
    }

    return 0;
}

/*
 * Use this with caution: rx_ptr is under guest control and may be bogus.
 * See get_sanitized_ring for a safer alternative.
 */
static int
get_rx_ptr(const struct domain *d, const struct argo_link *link,
           struct argo_ring_info *ring_info, uint32_t *rx_ptr)
{
    void *src;
    xen_argo_ring_t *ringp;
    int ret;

    ASSERT(LOCKING_L4(d, link, ring_info));

    if ( !ring_info->nmfns || ring_info->nmfns < NPAGES_RING(ring_info->len) )
        return -EINVAL;

    ret = ring_map_page(d, link, ring_info, 0, &src);
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
get_sanitized_ring(const struct domain *d, const struct argo_link *link,
                   xen_argo_ring_t *ring, struct argo_ring_info *ring_info)
{
    uint32_t rx_ptr;
    int ret;

    ASSERT(LOCKING_L4(d, link, ring_info));

    ret = get_rx_ptr(d, link, ring_info, &rx_ptr);
    if ( ret )
        return ret;

    ring->tx_ptr = ring_info->tx_ptr;

    rx_ptr = ROUNDUP_MESSAGE(rx_ptr);
    if ( rx_ptr >= ring_info->len )
        rx_ptr = 0;

    ring->rx_ptr = rx_ptr;

    return 0;
}

static unsigned int
ringbuf_payload_space(const struct domain *d, const struct argo_link *link,
                      struct argo_ring_info *ring_info)
{
    xen_argo_ring_t ring;
    unsigned int len;
    int ret;

    ASSERT(LOCKING_L4(d, link, ring_info));

    len = ring_info->len;
    if ( !len )
        return 0;

    if ( get_sanitized_ring(d, link, &ring, ring_info) )
        return 0;

    argo_dprintk("sanitized ringbuf_payload_space: tx_ptr=%u rx_ptr=%u\n",
                 ring.tx_ptr, ring.rx_ptr);

    /*
     * rx_ptr == tx_ptr means that the ring has been emptied.
     * See message size checking logic in the entry to ringbuf_insert which
     * ensures that there is always one message slot of size ROUNDUP_MESSAGE(1)
     * left available, preventing a ring from being entirely filled.
     * This ensures that matching ring indexes always indicate an empty ring
     * and never a full one.
     */
    ret = ring.rx_ptr - ring.tx_ptr;
    if ( ret <= 0 )
        ret += len;

    /*
     * In a sanitized ring, we can rely on:
     *              (rx_ptr < ring_info->len)           &&
     *              (tx_ptr < ring_info->len)           &&
     *      (ring_info->len <= XEN_ARGO_MAX_RING_SIZE)
     *
     * and since: XEN_ARGO_MAX_RING_SIZE < INT32_MAX
     * therefore right here: ret < INT32_MAX
     * and we are safe to return it as a unsigned value from this function.
     * The subtractions below cannot increase its value.
     */

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
iov_count(const xen_argo_iov_t *piov, unsigned int niov,
          unsigned int *count)
{
    unsigned int sum_iov_lens = 0;

    if ( niov > XEN_ARGO_MAXIOV )
        return -EINVAL;

    for ( ; niov--; piov++ )
    {
        /* valid iovs must have the padding field set to zero */
        if ( piov->pad )
        {
            argo_dprintk("invalid iov: padding is not zero\n");
            return -EINVAL;
        }

        /* check each to protect sum against integer overflow */
        if ( piov->iov_len > MAX_ARGO_MESSAGE_SIZE )
        {
            argo_dprintk("invalid iov_len: too big (%u)>%llu\n",
                         piov->iov_len, MAX_ARGO_MESSAGE_SIZE);
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
    }

    *count = sum_iov_lens;

    return 0;
}

static int
ringbuf_insert(const struct domain *d, const struct argo_link *link,
               struct argo_ring_info *ring_info,
               const struct argo_ring_id *src_id, xen_argo_iov_t *iovs,
               unsigned int niov, uint32_t message_type, unsigned int len)
{
    xen_argo_ring_t ring;
    struct xen_argo_ring_message_header mh = { };
    int sp, ret;
    xen_argo_iov_t *piov;
    XEN_GUEST_HANDLE(uint8) NULL_hnd = { };

    ASSERT(LOCKING_L4(d, link, ring_info));

    /*
     * Enforced below: no more than 'len' bytes of guest data
     * (plus the message header) will be sent in this operation.
     */

    /*
     * Upper bound check the message len against the ring size.
     * The message must not fill the ring; there must be at least one slot
     * remaining so we can distinguish a full ring from an empty one.
     * iov_count has already verified: len <= MAX_ARGO_MESSAGE_SIZE.
     */
    if ( ring_info->len <= (sizeof(struct xen_argo_ring_message_header) +
                            ROUNDUP_MESSAGE(len)) )
        return -EMSGSIZE;

    ret = get_sanitized_ring(d, link, &ring, ring_info);
    if ( ret )
        return ret;

    argo_dprintk("ring.tx_ptr=%u ring.rx_ptr=%u ring len=%u"
                 " ring_info->tx_ptr=%u\n",
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
        return -EAGAIN;
    }

    mh.len = len + sizeof(struct xen_argo_ring_message_header);
    mh.source.aport = src_id->aport;
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
    ret = memcpy_to_guest_ring(d, link, ring_info,
                               ring.tx_ptr + sizeof(xen_argo_ring_t),
                               &mh, NULL_hnd, sizeof(mh));
    if ( ret )
    {
        gprintk(XENLOG_ERR,
                "argo: failed to write message header to ring (vm%u:%x vm%u)\n",
                ring_info->id.domain_id, ring_info->id.aport,
                ring_info->id.partner_id);

        return ret;
    }

    ring.tx_ptr += sizeof(mh);
    if ( ring.tx_ptr == ring_info->len )
        ring.tx_ptr = 0;

    for ( piov = iovs; niov--; piov++ )
    {
        XEN_GUEST_HANDLE(uint8) buf_hnd = piov->iov_hnd;
        unsigned int iov_len = piov->iov_len;

        /* If no data is provided in this iov, moan and skip on to the next */
        if ( !iov_len )
        {
            gprintk(XENLOG_WARNING,
                    "argo: no data iov_len=0 iov_hnd=%p ring (vm%u:%x vm%u)\n",
                    buf_hnd.p, ring_info->id.domain_id, ring_info->id.aport,
                    ring_info->id.partner_id);

            continue;
        }

        if ( unlikely(!guest_handle_okay(buf_hnd, iov_len)) )
        {
            gprintk(XENLOG_ERR,
                    "argo: bad iov handle [%p, %u] (vm%u:%x vm%u)\n",
                    buf_hnd.p, iov_len,
                    ring_info->id.domain_id, ring_info->id.aport,
                    ring_info->id.partner_id);

            return -EFAULT;
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
            ret = memcpy_to_guest_ring(d, link, ring_info,
                                       ring.tx_ptr + sizeof(xen_argo_ring_t),
                                       NULL, buf_hnd, sp);
            if ( ret )
            {
                gprintk(XENLOG_ERR,
                        "argo: failed to copy {%p, %d} (vm%u:%x vm%u)\n",
                        buf_hnd.p, sp,
                        ring_info->id.domain_id, ring_info->id.aport,
                        ring_info->id.partner_id);

                return ret;
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
        ret = memcpy_to_guest_ring(d, link, ring_info,
                                   ring.tx_ptr + sizeof(xen_argo_ring_t),
                                   NULL, buf_hnd, iov_len);
        if ( ret )
        {
            gprintk(XENLOG_ERR,
                    "argo: failed to copy [%p, %u] (vm%u:%x vm%u)\n",
                    buf_hnd.p, iov_len, ring_info->id.domain_id,
                    ring_info->id.aport, ring_info->id.partner_id);

            return ret;
        }

        ring.tx_ptr += iov_len;

        if ( ring.tx_ptr == ring_info->len )
            ring.tx_ptr = 0;
    }

    /*
     * Finished writing data from all iovs into the ring: now need to round up
     * tx_ptr to align to the next message boundary, and then wrap if necessary.
     */
    ring.tx_ptr = ROUNDUP_MESSAGE(ring.tx_ptr);

    if ( ring.tx_ptr >= ring_info->len )
        ring.tx_ptr -= ring_info->len;

    update_tx_ptr(d, link, ring_info, ring.tx_ptr);

    /*
     * At this point (and also on an error exit paths from this function) it is
     * possible to unmap the ring_info, ie:
     *   ring_unmap(d, link, ring_info);
     * but performance should be improved by not doing so, and retaining
     * the mapping.
     * An XSM policy control over level of confidentiality required
     * versus performance cost could be added to decide that here.
     */

    return ret;
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
        list_del(&ent->wildcard_node);
        spin_unlock(&d->argo->wildcard_L2_lock);
    }
    put_domain(d);
}

static void
wildcard_pending_list_insert(domid_t domain_id, struct pending_ent *ent)
{
    struct domain *d = get_domain_by_id(domain_id);

    if ( !d )
        return;

    ASSERT(LOCKING_Read_L1);

    if ( d->argo )
    {
        spin_lock(&d->argo->wildcard_L2_lock);
        list_add(&ent->wildcard_node, &d->argo->wildcard_pend_list);
        spin_unlock(&d->argo->wildcard_L2_lock);
    }
    put_domain(d);
}

static void
pending_remove_all(const struct domain *d, const struct argo_link *link,
                   struct argo_ring_info *ring_info)
{
    struct pending_ent *ent;

    ASSERT(LOCKING_L4(d, link, ring_info));

    /* Delete all pending notifications from this ring's list. */
    while ( (ent = list_first_entry_or_null(&ring_info->pending,
                                            struct pending_ent, node)) )
    {
        /* For wildcard rings, remove each from their wildcard list too. */
        if ( ring_info->id.partner_id == XEN_ARGO_DOMID_ANY )
            wildcard_pending_list_remove(ent->domain_id, ent);
        list_del(&ent->node);
        xfree(ent);
    }
    ring_info->npending = 0;
}

static void
pending_notify(struct list_head *to_notify)
{
    struct pending_ent *ent;

    ASSERT(LOCKING_Read_L1);

    /* Sending signals for all ents in this list, draining until it is empty. */
    while ( (ent = list_first_entry_or_null(to_notify, struct pending_ent,
                                            node)) )
    {
        list_del(&ent->node);
        signal_domid(ent->domain_id);
        xfree(ent);
    }
}

static void
pending_find(const struct domain *d, const struct argo_link *link,
             struct argo_ring_info *ring_info, unsigned int payload_space,
             struct list_head *to_notify)
{
    struct pending_ent *ent, *next;

    ASSERT(LOCKING_Read_rings_L3(d, link));

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
    spin_lock(&ring_info->L4_lock);

    /* Remove matching ents from the ring list, and add them to "to_notify" */
    list_for_each_entry_safe(ent, next, &ring_info->pending, node)
    {
        if ( payload_space >= ent->len )
        {
            if ( ring_info->id.partner_id == XEN_ARGO_DOMID_ANY )
                wildcard_pending_list_remove(ent->domain_id, ent);

            list_del(&ent->node);
            ring_info->npending--;
            list_add(&ent->node, to_notify);
        }
    }

    spin_unlock(&ring_info->L4_lock);
}

static int
pending_queue(const struct domain *d, const struct argo_link *link,
              struct argo_ring_info *ring_info, domid_t src_id,
              unsigned int len)
{
    struct pending_ent *ent;

    ASSERT(LOCKING_L4(d, link, ring_info));

    if ( ring_info->npending >= MAX_PENDING_PER_RING )
        return -EBUSY;

    ent = xmalloc(struct pending_ent);
    if ( !ent )
        return -ENOMEM;

    ent->len = len;
    ent->domain_id = src_id;
    ent->ring_info = ring_info;

    if ( ring_info->id.partner_id == XEN_ARGO_DOMID_ANY )
        wildcard_pending_list_insert(src_id, ent);
    list_add(&ent->node, &ring_info->pending);
    ring_info->npending++;

    return 0;
}

static int
pending_requeue(const struct domain *d, const struct argo_link *link,
                struct argo_ring_info *ring_info,
                domid_t src_id, unsigned int len)
{
    struct pending_ent *ent;

    ASSERT(LOCKING_L4(d, link, ring_info));

    /* List structure is not modified here. Update len in a match if found. */
    list_for_each_entry(ent, &ring_info->pending, node)
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

    return pending_queue(d, link, ring_info, src_id, len);
}

static void
pending_cancel(const struct domain *d, const struct argo_link *link,
               struct argo_ring_info *ring_info, domid_t src_id)
{
    struct pending_ent *ent, *next;

    ASSERT(LOCKING_L4(d, link, ring_info));

    /* Remove all ents where domain_id matches src_id from the ring's list. */
    list_for_each_entry_safe(ent, next, &ring_info->pending, node)
    {
        if ( ent->domain_id == src_id )
        {
            /* For wildcard rings, remove each from their wildcard list too. */
            if ( ring_info->id.partner_id == XEN_ARGO_DOMID_ANY )
                wildcard_pending_list_remove(ent->domain_id, ent);
            list_del(&ent->node);
            xfree(ent);
            ring_info->npending--;
        }
    }
}

static void
wildcard_rings_pending_remove(struct domain *d)
{
    struct pending_ent *ent;

    ASSERT(LOCKING_Write_L1);

    /* Delete all pending signals to the domain about wildcard rings. */
    while ( (ent = list_first_entry_or_null(&d->argo->wildcard_pend_list,
                                            struct pending_ent, node)) )
    {
        /*
         * The ent->node deleted here, and the npending value decreased,
         * belong to the ring_info of another domain, which is why this
         * function requires holding W(L1):
         * it implies the L4 lock that protects that ring_info struct.
         */
        ent->ring_info->npending--;
        list_del(&ent->node);
        list_del(&ent->wildcard_node);
        xfree(ent);
    }
}

static void
ring_remove_mfns(const struct domain *d, const struct argo_link *link,
                 struct argo_ring_info *ring_info)
{
    unsigned int i;

    ASSERT(LOCKING_Write_rings_L3(d, link));

    if ( !ring_info->mfns )
        return;

    if ( !ring_info->mfn_mapping )
    {
        ASSERT_UNREACHABLE();
        return;
    }

    ring_unmap(d, link, ring_info);

    for ( i = 0; i < ring_info->nmfns; i++ )
        if ( !mfn_eq(ring_info->mfns[i], INVALID_MFN) )
            put_page_and_type(mfn_to_page(ring_info->mfns[i]));

    ring_info->nmfns = 0;
    XFREE(ring_info->mfns);
    XFREE(ring_info->mfn_mapping);
}

static void
ring_remove_info(const struct domain *d, const struct argo_link *link,
                 struct argo_ring_info *ring_info)
{
    ASSERT(LOCKING_Write_rings_L3(d, link));

    pending_remove_all(d, link, ring_info);
    list_del(&ring_info->node);
    ring_remove_mfns(d, link, ring_info);
    xfree(ring_info);
}

/*
 * This function does not decrement d->ring_count since it's used only
 * when removing all rings. The domain's ring count is set to zero afterwards
 * in domain_rings_remove_all.
 */
static void
remove_link_and_rings(const struct domain *d, struct argo_link *link)
{
    struct domain *dst_d = NULL;
    unsigned int i;

    ASSERT(LOCKING_Write_L1);

    for ( i = 0; i < ARGO_HASHTABLE_SIZE; ++i )
    {
        struct argo_ring_info *ring_info;
        struct list_head *bucket = &link->ring_hash[i];

        while ( (ring_info = list_first_entry_or_null(bucket,
                                                      struct argo_ring_info,
                                                      node)) )
        {
            if ( ring_info->id.domain_id != d->domain_id )
            {
                if ( !dst_d )
                    dst_d = get_domain_by_id(ring_info->id.domain_id);

                ASSERT(dst_d->domain_id == ring_info->id.domain_id);

                /* W(L1) implies W(count_L2) so ok to decrement: */
                dst_d->argo->ring_count--;
            }
            ring_remove_info(d, link, ring_info);
        }
    }

    if ( dst_d )
        put_domain(dst_d);

    /* Links for self-rings are not present on the upper list */
    if ( link->upper_domain_id != link->lower_domain_id )
        list_del(&link->upper_node);
    /* Links for wildcard rings are not present on the lower list */
    if ( link->upper_domain_id != XEN_ARGO_DOMID_ANY )
        list_del(&link->lower_node);

    xfree(link);
}

static void
domain_rings_remove_all(struct domain *d)
{
    unsigned int i;

    ASSERT(LOCKING_Write_L1);

    for ( i = 0; i < ARGO_HASHTABLE_SIZE; ++i )
    {
        struct argo_link *link;
        struct list_head *bucket = &d->argo->upper_links_hash[i];

        while ( (link = list_first_entry_or_null(bucket, struct argo_link,
                                                 upper_node) ) )
            remove_link_and_rings(d, link);

        bucket = &d->argo->lower_links_hash[i];
        while ( (link = list_first_entry_or_null(bucket, struct argo_link,
                                                 lower_node) ) )
            remove_link_and_rings(d, link);
    }

    d->argo->ring_count = 0;
}

static int
fill_ring_data(const struct domain *currd,
               XEN_GUEST_HANDLE(xen_argo_ring_data_ent_t) data_ent_hnd)
{
    xen_argo_ring_data_ent_t ent;
    struct domain *dst_d;
    struct argo_link *link;
    struct argo_ring_info *ring_info;
    struct argo_ring_id id;
    int ret = 0;

    ASSERT(currd == current->domain);
    ASSERT(LOCKING_Read_L1);

    if ( __copy_from_guest(&ent, data_ent_hnd, 1) )
        return -EFAULT;

    argo_dprintk("fill_ring_data: ent.ring.domain=%u,ent.ring.aport=%x\n",
                 ent.ring.domain_id, ent.ring.aport);

    ent.flags = 0;

    dst_d = get_domain_by_id(ent.ring.domain_id);
    if ( !dst_d || !dst_d->argo )
        goto out;

    /*
     * Don't supply information about rings that a guest is not
     * allowed to send to.
     */
    ret = xsm_argo_send(currd, dst_d);
    if ( ret )
    {
        put_domain(dst_d);
        return ret;
    }

    id.domain_id = currd->domain_id;
    id.partner_id = dst_d->domain_id;
    id.aport = ent.ring.aport;

    read_lock(&currd->argo->links_L2_rwlock);

    link = find_link(currd, dst_d->domain_id);
    if ( !link )
        goto out_unlock;

    read_lock(&link->rings_L3_rwlock);

    ring_info = find_ring_info_by_match(currd, link, &id);
    if ( ring_info )
    {
        unsigned int space_avail;

        ent.flags |= XEN_ARGO_RING_EXISTS;

        spin_lock(&ring_info->L4_lock);

        ent.max_message_size = ring_info->len -
                                   sizeof(struct xen_argo_ring_message_header) -
                                   ROUNDUP_MESSAGE(1);

        if ( ring_info->id.partner_id == XEN_ARGO_DOMID_ANY )
            ent.flags |= XEN_ARGO_RING_SHARED;

        space_avail = ringbuf_payload_space(dst_d, link, ring_info);

        argo_dprintk("fill_ring_data: aport=%x space_avail=%u"
                     " space_wanted=%u\n",
                     ring_info->id.aport, space_avail, ent.space_required);

        /* Do not queue a notification for an unachievable size */
        if ( ent.space_required > ent.max_message_size )
            ent.flags |= XEN_ARGO_RING_EMSGSIZE;
        else if ( space_avail >= ent.space_required )
        {
            pending_cancel(dst_d, link, ring_info, currd->domain_id);
            ent.flags |= XEN_ARGO_RING_SUFFICIENT;
        }
        else
        {
            ret = pending_requeue(dst_d, link, ring_info, currd->domain_id,
                                  ent.space_required);
            if ( ret == -EBUSY )
            {
                /*
                 * Too many other domains are already awaiting notification
                 * about available space on this ring. Indicate this state via
                 * flag. No need to return an error to the caller; allow the
                 * processing of queries about other rings to continue.
                 */
                ent.flags |= XEN_ARGO_RING_EBUSY;
                ret = 0;
            }
        }

        spin_unlock(&ring_info->L4_lock);

        if ( space_avail == ent.max_message_size )
            ent.flags |= XEN_ARGO_RING_EMPTY;

    }
    read_unlock(&link->rings_L3_rwlock);

 out_unlock:
    read_unlock(&currd->argo->links_L2_rwlock);

 out:
    if ( dst_d )
        put_domain(dst_d);

    if ( !ret && (__copy_field_to_guest(data_ent_hnd, &ent, flags) ||
                  __copy_field_to_guest(data_ent_hnd, &ent, max_message_size)) )
        return -EFAULT;

    return ret;
}

static int
find_ring_mfn(struct domain *d, gfn_t gfn, mfn_t *mfn)
{
    struct page_info *page;
    p2m_type_t p2mt;
    int ret;

    ret = check_get_page_from_gfn(d, gfn, false, &p2mt, &page);
    if ( unlikely(ret) )
        return ret;

    *mfn = page_to_mfn(page);
    if ( !mfn_valid(*mfn) )
        ret = -EINVAL;
#ifdef CONFIG_X86
    else if ( p2mt == p2m_ram_logdirty )
        ret = -EAGAIN;
#endif
    else if ( (p2mt != p2m_ram_rw) ||
              !get_page_and_type(page, d, PGT_writable_page) )
        ret = -EINVAL;

    put_page(page);

    return ret;
}

static int
find_ring_mfns(struct domain *d, const struct argo_link *link,
               struct argo_ring_info *ring_info, const unsigned int npage,
               XEN_GUEST_HANDLE_PARAM(xen_argo_gfn_t) gfn_hnd,
               const unsigned int len)
{
    unsigned int i;
    int ret = 0;
    mfn_t *mfns;
    void **mfn_mapping;

    ASSERT(LOCKING_Write_rings_L3(d, link));

    if ( ring_info->mfns )
    {
        /* Ring already existed: drop the previous mapping. */
        argo_dprintk("argo: vm%u re-register existing ring "
                     "(vm%u:%x vm%u) clears mapping\n",
                     d->domain_id, ring_info->id.domain_id,
                     ring_info->id.aport, ring_info->id.partner_id);

        ring_remove_mfns(d, link, ring_info);
        ASSERT(!ring_info->mfns);
    }

    mfns = xmalloc_array(mfn_t, npage);
    if ( !mfns )
        return -ENOMEM;

    for ( i = 0; i < npage; i++ )
        mfns[i] = INVALID_MFN;

    mfn_mapping = xzalloc_array(void *, npage);
    if ( !mfn_mapping )
    {
        xfree(mfns);
        return -ENOMEM;
    }

    ring_info->mfns = mfns;
    ring_info->mfn_mapping = mfn_mapping;

    for ( i = 0; i < npage; i++ )
    {
        mfn_t mfn;
        xen_argo_gfn_t argo_gfn;

        ret = __copy_from_guest_offset(&argo_gfn, gfn_hnd, i, 1) ? -EFAULT : 0;
        if ( ret )
            break;

        ret = find_ring_mfn(d, _gfn(argo_gfn), &mfn);
        if ( ret )
        {
            gprintk(XENLOG_ERR, "argo: vm%u: invalid gfn %"PRI_gfn" "
                    "r:(vm%u:%x vm%u) %p %u/%u\n",
                    d->domain_id, gfn_x(_gfn(argo_gfn)),
                    ring_info->id.domain_id, ring_info->id.aport,
                    ring_info->id.partner_id, ring_info, i, npage);
            break;
        }

        ring_info->mfns[i] = mfn;

        argo_dprintk("%u: %"PRI_gfn" -> %"PRI_mfn"\n",
                     i, gfn_x(_gfn(argo_gfn)), mfn_x(ring_info->mfns[i]));
    }

    ring_info->nmfns = i;

    if ( ret )
        ring_remove_mfns(d, link, ring_info);
    else
    {
        ASSERT(ring_info->nmfns == NPAGES_RING(len));

        argo_dprintk("argo: vm%u ring (vm%u:%x vm%u) %p "
                     "mfn_mapping %p len %u nmfns %u\n",
                     d->domain_id, ring_info->id.domain_id,
                     ring_info->id.aport, ring_info->id.partner_id, ring_info,
                     ring_info->mfn_mapping, ring_info->len, ring_info->nmfns);
    }

    return ret;
}

static long
unregister_ring(struct domain *currd,
                XEN_GUEST_HANDLE_PARAM(xen_argo_unregister_ring_t) unreg_hnd)
{
    xen_argo_unregister_ring_t unreg;
    struct argo_link *link;
    struct argo_ring_id ring_id;
    struct argo_ring_info *ring_info = NULL;

    ASSERT(currd == current->domain);

    if ( copy_from_guest(&unreg, unreg_hnd, 1) )
        return -EFAULT;

    if ( unreg.pad )
        return -EINVAL;

    ring_id.partner_id = unreg.partner_id;
    ring_id.aport = unreg.aport;
    ring_id.domain_id = currd->domain_id;

    read_lock(&L1_global_argo_rwlock);

    if ( unlikely(!currd->argo) )
    {
        read_unlock(&L1_global_argo_rwlock);
        return -ENODEV;
    }

    read_lock(&currd->argo->links_L2_rwlock);

    link = find_link(currd, unreg.partner_id);
    if ( !link )
        goto out;

    write_lock(&link->rings_L3_rwlock);

    ring_info = find_ring_info(currd, link, &ring_id);
    if ( !ring_info )
        goto out2;

    ring_remove_info(currd, link, ring_info);

    spin_lock(&currd->argo->count_L2_lock);
    currd->argo->ring_count--;
    spin_unlock(&currd->argo->count_L2_lock);

 out2:
    write_unlock(&link->rings_L3_rwlock);

 out:
    read_unlock(&currd->argo->links_L2_rwlock);

    read_unlock(&L1_global_argo_rwlock);

    if ( !ring_info )
    {
        argo_dprintk("unregister_ring: no ring_info found for ring(%u:%x %u)\n",
                     ring_id.domain_id, ring_id.aport, ring_id.partner_id);
        return -ENOENT;
    }

    return 0;
}

static int
create_link(struct domain *currd, domid_t partner_id, struct domain *dst_d)
{
    struct argo_link *link, *found_link;
    int i;

    ASSERT(LOCKING_Read_L1);

    link = xmalloc(struct argo_link);
    if ( !link )
        return -ENOMEM;

    rwlock_init(&link->rings_L3_rwlock);
    for ( i = 0; i < ARGO_HASHTABLE_SIZE; ++i )
        INIT_LIST_HEAD(&link->ring_hash[i]);

    if ( partner_id == XEN_ARGO_DOMID_ANY )
    {
        link->upper_domain_id = XEN_ARGO_DOMID_ANY;
        link->lower_domain_id = currd->domain_id;

        write_lock(&currd->argo->links_L2_rwlock);

        found_link = find_link(currd, partner_id);
        if ( !found_link )
            list_add(&link->upper_node, &currd->argo->upper_links_hash[
                                            link_index(partner_id)]);
    }
    else if ( partner_id > currd->domain_id )
    {
        ASSERT(dst_d);

        link->upper_domain_id = partner_id;
        link->lower_domain_id = currd->domain_id;

        /* Deadlock avoidance: lock domain with higher-numbered id first. */
        write_lock(&dst_d->argo->links_L2_rwlock);
        write_lock(&currd->argo->links_L2_rwlock);

        found_link = find_link(currd, partner_id);
        if ( !found_link )
        {
            list_add(&link->upper_node, &currd->argo->upper_links_hash[
                                            link_index(partner_id)]);
            list_add(&link->lower_node, &dst_d->argo->lower_links_hash[
                                            link_index(currd->domain_id)]);
        }
        write_unlock(&dst_d->argo->links_L2_rwlock);
    }
    else if ( partner_id < currd->domain_id )
    {
        ASSERT(dst_d);

        link->upper_domain_id = currd->domain_id;
        link->lower_domain_id = partner_id;

        /* Deadlock avoidance: lock domain with higher-numbered id first. */
        write_lock(&currd->argo->links_L2_rwlock);

        found_link = find_link(currd, partner_id);
        if ( !found_link )
        {
            write_lock(&dst_d->argo->links_L2_rwlock);

            list_add(&link->upper_node, &dst_d->argo->upper_links_hash[
                                            link_index(currd->domain_id)]);
            list_add(&link->lower_node, &currd->argo->lower_links_hash[
                                            link_index(partner_id)]);

            write_unlock(&dst_d->argo->links_L2_rwlock);
        }
    }
    else /* ( partner_id == currd->domain_id ) */
    {
        link->upper_domain_id = currd->domain_id;
        link->lower_domain_id = currd->domain_id;

        write_lock(&currd->argo->links_L2_rwlock);

        found_link = find_link(currd, partner_id);
        if ( !found_link )
            list_add(&link->lower_node, &currd->argo->lower_links_hash[
                                            link_index(partner_id)]);
    }

    write_unlock(&currd->argo->links_L2_rwlock);

    if ( found_link )
        xfree(link);

    return 0;
}

static long
create_ring(struct domain *currd, struct argo_link *link,
            const struct argo_ring_id *ring_id,
            struct argo_ring_info *new_ring_info,
            XEN_GUEST_HANDLE_PARAM(xen_argo_gfn_t) gfn_hnd,
            unsigned int len, unsigned int npage, unsigned int flags)
{
    int ret = 0;
    struct argo_ring_info *ring_info;
    unsigned int private_tx_ptr;
    xen_argo_ring_t *ringp;
    void *map_ringp;

    ASSERT(LOCKING_Write_rings_L3(currd, link));

    /* Minimize criticial region for count_L2: do an optimistic increment */
    spin_lock(&currd->argo->count_L2_lock);

    if ( currd->argo->ring_count >= MAX_RINGS_PER_DOMAIN )
        ret = -ENOSPC;
    else
        currd->argo->ring_count++;

    spin_unlock(&currd->argo->count_L2_lock);

    if ( ret )
        return ret;

    ring_info = find_ring_info(currd, link, ring_id);
    if ( !ring_info )
    {
        ring_info = new_ring_info;
        new_ring_info = NULL;

        spin_lock_init(&ring_info->L4_lock);

        ring_info->id = *ring_id;
        INIT_LIST_HEAD(&ring_info->pending);

        list_add(&ring_info->node,
                 &link->ring_hash[hash_index(&ring_info->id)]);

        argo_dprintk("argo: vm%u registering ring (vm%u:%x vm%u)\n",
                     currd->domain_id, ring_id->domain_id, ring_id->aport,
                     ring_id->partner_id);
    }
    else if ( ring_info->len )
    {
        /*
         * If the caller specified that the ring must not already exist,
         * fail at attempt to add a completed ring which already exists.
         */
        if ( flags & XEN_ARGO_REGISTER_FLAG_FAIL_EXIST )
        {
            gprintk(XENLOG_ERR, "argo: vm%u disallowed reregistration of "
                    "existing ring (vm%u:%x vm%u)\n",
                    currd->domain_id, ring_id->domain_id, ring_id->aport,
                    ring_id->partner_id);
            ret = -EEXIST;
            goto out_undo;
        }

        if ( ring_info->len != len )
        {
            /*
             * Change of ring size could result in entries on the pending
             * notifications list that will never trigger.
             * Simple blunt solution: disallow ring resize for now.
             * TODO: investigate enabling ring resize.
             */
            gprintk(XENLOG_ERR, "argo: vm%u attempted to change ring size "
                    "(vm%u:%x vm%u)\n",
                    currd->domain_id, ring_id->domain_id, ring_id->aport,
                    ring_id->partner_id);
            /*
             * Could return EINVAL here, but if the ring didn't already
             * exist then the arguments would have been valid, so: EEXIST.
             */
            ret = -EEXIST;
            goto out_undo;
        }

        argo_dprintk("argo: vm%u re-registering existing ring (vm%u:%x vm%u)\n",
                     currd->domain_id, ring_id->domain_id, ring_id->aport,
                     ring_id->partner_id);
    }

    ret = find_ring_mfns(currd, link, ring_info, npage, gfn_hnd, len);
    if ( ret )
    {
        gprintk(XENLOG_ERR,
                "argo: vm%u failed to find ring mfns (vm%u:%x vm%u)\n",
                currd->domain_id, ring_id->domain_id, ring_id->aport,
                ring_id->partner_id);

        ring_remove_info(currd, link, ring_info);
        goto out_undo;
    }

    /*
     * The first page of the memory supplied for the ring has the xen_argo_ring
     * structure at its head, which is where the ring indexes reside.
     */
    ret = ring_map_page(currd, link, ring_info, 0, &map_ringp);
    if ( ret )
    {
        gprintk(XENLOG_ERR,
                "argo: vm%u failed to map ring mfn 0 (vm%u:%x vm%u)\n",
                currd->domain_id, ring_id->domain_id, ring_id->aport,
                ring_id->partner_id);

        ring_remove_info(currd, link, ring_info);
        goto out_undo;
    }
    ringp = map_ringp;

    private_tx_ptr = read_atomic(&ringp->tx_ptr);

    if ( (private_tx_ptr >= len) ||
         (ROUNDUP_MESSAGE(private_tx_ptr) != private_tx_ptr) )
    {
        /*
         * Since the ring is a mess, attempt to flush the contents of it
         * here by setting the tx_ptr to the next aligned message slot past
         * the latest rx_ptr we have observed. Handle ring wrap correctly.
         */
        private_tx_ptr = ROUNDUP_MESSAGE(read_atomic(&ringp->rx_ptr));

        if ( private_tx_ptr >= len )
            private_tx_ptr = 0;

        update_tx_ptr(currd, link, ring_info, private_tx_ptr);
    }

    ring_info->tx_ptr = private_tx_ptr;
    ring_info->len = len;

    if ( ret )
    {
 out_undo:
        /* Undo the optimistic ring count increment. */
        spin_lock(&currd->argo->count_L2_lock);
        currd->argo->ring_count--;
        spin_unlock(&currd->argo->count_L2_lock);
    }

    return ret;
}

static long
register_ring(struct domain *currd,
              XEN_GUEST_HANDLE_PARAM(xen_argo_register_ring_t) reg_hnd,
              XEN_GUEST_HANDLE_PARAM(xen_argo_gfn_t) gfn_hnd,
              unsigned int npage, unsigned int flags)
{
    xen_argo_register_ring_t reg;
    struct argo_ring_id ring_id, fwd_ring_id;
    struct argo_link *link = NULL, *fwd_link = NULL;
    struct argo_ring_info *fwd_ring_info = NULL, *new_ring_info = NULL;
    struct domain *dst_d = NULL;
    int ret = 0;

    ASSERT(currd == current->domain);

    /* flags: reserve currently-undefined bits, require zero.  */
    if ( unlikely(flags & ~XEN_ARGO_REGISTER_FLAG_MASK) )
        return -EINVAL;

    if ( copy_from_guest(&reg, reg_hnd, 1) )
        return -EFAULT;

    /*
     * A ring must be large enough to transmit messages, so requires space for:
     * * 1 message header, plus
     * * 1 payload slot (payload is always rounded to a multiple of 16 bytes)
     *   for the message payload to be written into, plus
     * * 1 more slot, so that the ring cannot be filled to capacity with a
     *   single minimum-size message -- see the logic in ringbuf_insert --
     *   allowing for this ensures that there can be space remaining when a
     *   message is present.
     * The above determines the minimum acceptable ring size.
     */
    if ( (reg.len < (sizeof(struct xen_argo_ring_message_header)
                      + ROUNDUP_MESSAGE(1) + ROUNDUP_MESSAGE(1))) ||
         (reg.len > XEN_ARGO_MAX_RING_SIZE) ||
         (reg.len != ROUNDUP_MESSAGE(reg.len)) ||
         (NPAGES_RING(reg.len) != npage) ||
         (reg.partner.pad != 0) ||
         ((flags & XEN_ARGO_REGISTER_FLAG_REPLY_RING) &&
          (reg.partner.domain_id == XEN_ARGO_DOMID_ANY)) )
        return -EINVAL;

    ring_id.partner_id = reg.partner.domain_id;
    ring_id.aport = reg.aport;
    ring_id.domain_id = currd->domain_id;

    if ( reg.partner.domain_id == XEN_ARGO_DOMID_ANY )
    {
        ret = opt_argo_mac_permissive ? xsm_argo_register_any_source(currd) :
                                        -EPERM;
        if ( ret )
            return ret;
    }
    else
    {
        dst_d = get_domain_by_id(reg.partner.domain_id);
        if ( !dst_d )
        {
            argo_dprintk("!dst_d, ESRCH\n");
            return -ESRCH;
        }

        ret = xsm_argo_register_single_source(currd, dst_d);
        if ( ret )
            goto out;
    }

    /*
     * Common case is that the ring doesn't already exist, so do the alloc here
     * before picking up any locks.
     */
    new_ring_info = xzalloc(struct argo_ring_info);
    if ( !new_ring_info )
    {
        ret = -ENOMEM;
        goto out;
    }

    read_lock(&L1_global_argo_rwlock);

    if ( !currd->argo )
    {
        ret = -ENODEV;
        goto out_unlock;
    }

    if ( dst_d && !dst_d->argo )
    {
        argo_dprintk("!dst_d->argo, ECONNREFUSED\n");
        ret = -ECONNREFUSED;
        goto out_unlock;
    }

    /* For partner rings: ensure that the link between the domains exists */
    if ( reg.partner.domain_id != XEN_ARGO_DOMID_ANY )
    {
        bool link_exists;

        read_lock(&currd->argo->links_L2_rwlock);
        link_exists = !!find_link(currd, reg.partner.domain_id);
        read_unlock(&currd->argo->links_L2_rwlock);

        /* holding R(L1) so link will exist even when links_L2 is dropped */
        if ( !link_exists )
        {
            ret = create_link(currd, reg.partner.domain_id, dst_d);
            if ( ret )
                goto out_unlock;
        }
    }

    /*
     * Next: acquire all necessary links_L2 and rings_L3 locks.
     * If registering a reply ring, look up the forward ring and hold the
     * rings_L3 lock protecting it until registering is completed.
     *
     * If the forward ring is a wildcard ring, we need to access it via the
     * dst_d link for wildcard rings, so must read-lock dst_d's links_L2.
     * To avoid deadlock, take R(links_L2) on the domain with the
     * higher-numbered domain id first.
     */
    if ( flags & XEN_ARGO_REGISTER_FLAG_REPLY_RING )
    {
        /* Populating this before locking to reduce work in critical region */
        fwd_ring_id.domain_id = reg.partner.domain_id;
        fwd_ring_id.aport = reg.partner.aport;
        fwd_ring_id.partner_id = currd->domain_id; /* partner ring */

        /* Lock both links_L2 in deadlock-avoidance order */
        if ( currd->domain_id > dst_d->domain_id )
        {
            read_lock(&currd->argo->links_L2_rwlock);
            read_lock(&dst_d->argo->links_L2_rwlock);
        }
        else if ( currd->domain_id < dst_d->domain_id )
        {
            read_lock(&dst_d->argo->links_L2_rwlock);
            read_lock(&currd->argo->links_L2_rwlock);
        }
        else /* ( currd->domain_id == dst_d->domain_id ) */
            read_lock(&currd->argo->links_L2_rwlock);
    }
    else
        read_lock(&currd->argo->links_L2_rwlock);

    link = find_link(currd, reg.partner.domain_id);
    ASSERT(link);

    /* This link is where the new ring will go, so write lock it */
    write_lock(&link->rings_L3_rwlock);

    if ( flags & XEN_ARGO_REGISTER_FLAG_REPLY_RING )
    {
        fwd_ring_info = find_ring_info(currd, link, &fwd_ring_id);
        if ( fwd_ring_info )
            fwd_link = link;
        else
        {
            /* Search dst_d's wildcard ring link */
            fwd_ring_id.partner_id = XEN_ARGO_DOMID_ANY;
            fwd_link = find_link(dst_d, XEN_ARGO_DOMID_ANY);
            if ( fwd_link )
            {
                read_lock(&fwd_link->rings_L3_rwlock);

                fwd_ring_info = find_ring_info(dst_d, fwd_link, &fwd_ring_id);
            }
            if ( !fwd_ring_info )
            {
                ret = -ECONNREFUSED;
                goto out_unlock2;
            }
        }
    }

    ASSERT(!(flags & XEN_ARGO_REGISTER_FLAG_REPLY_RING) ||
           (currd->domain_id == ring_id.partner_id ) ||
           LOCKING_Read_rings_L3(dst_d, fwd_link));

    ret = create_ring(currd, link, &ring_id, new_ring_info, gfn_hnd, reg.len,
                      npage, flags);
    if ( !ret )
        new_ring_info = NULL;

 out_unlock2:
    write_unlock(&link->rings_L3_rwlock);
    if ( fwd_link && (fwd_link != link) )
        read_unlock(&fwd_link->rings_L3_rwlock);

    read_unlock(&currd->argo->links_L2_rwlock);
    if ( (flags & XEN_ARGO_REGISTER_FLAG_REPLY_RING) &&
         (currd->domain_id != dst_d->domain_id) )
        read_unlock(&dst_d->argo->links_L2_rwlock);

 out_unlock:
    read_unlock(&L1_global_argo_rwlock);

 out:
    if ( dst_d )
        put_domain(dst_d);

    xfree(new_ring_info);

    return ret;
}

static void
notify_ring(const struct domain *d, const struct argo_link *link,
            struct argo_ring_info *ring_info, struct list_head *to_notify)
{
    unsigned int space;

    ASSERT(LOCKING_Read_rings_L3(d, link));

    spin_lock(&ring_info->L4_lock);

    if ( ring_info->len )
        space = ringbuf_payload_space(d, link, ring_info);
    else
        space = 0;

    spin_unlock(&ring_info->L4_lock);

    if ( space )
        pending_find(d, link, ring_info, space, to_notify);
}

static void
notify_check_pending(struct domain *d)
{
    unsigned int i, j;
    LIST_HEAD(to_notify);

    ASSERT(LOCKING_Read_L1);

    read_lock(&d->argo->links_L2_rwlock);

    /* Walk all rings, call notify_ring on each to populate to_notify list */
    for ( i = 0; i < ARGO_HASHTABLE_SIZE; i++ )
    {
        struct argo_link *link, *next;
        struct list_head *link_bucket = &d->argo->upper_links_hash[i];

        list_for_each_entry_safe(link, next, link_bucket, upper_node)
        {
            read_lock(&link->rings_L3_rwlock);

            for ( j = 0; j < ARGO_HASHTABLE_SIZE; j++ )
            {
                struct argo_ring_info *ring_info, *next;
                struct list_head *ring_bucket = &link->ring_hash[j];

                list_for_each_entry_safe(ring_info, next, ring_bucket, node)
                    notify_ring(d, link, ring_info, &to_notify);
            }

            read_unlock(&link->rings_L3_rwlock);
        }

        link_bucket = &d->argo->lower_links_hash[i];

        list_for_each_entry_safe(link, next, link_bucket, lower_node)
        {
            read_lock(&link->rings_L3_rwlock);

            for ( j = 0; j < ARGO_HASHTABLE_SIZE; j++ )
            {
                struct argo_ring_info *ring_info, *next;
                struct list_head *ring_bucket = &link->ring_hash[j];

                list_for_each_entry_safe(ring_info, next, ring_bucket, node)
                    notify_ring(d, link, ring_info, &to_notify);
            }

            read_unlock(&link->rings_L3_rwlock);
        }
    }

    read_unlock(&d->argo->links_L2_rwlock);

    if ( !list_empty(&to_notify) )
        pending_notify(&to_notify);
}

static long
notify(struct domain *currd,
       XEN_GUEST_HANDLE_PARAM(xen_argo_ring_data_t) ring_data_hnd)
{
    XEN_GUEST_HANDLE(xen_argo_ring_data_ent_t) ent_hnd;
    xen_argo_ring_data_t ring_data;
    int ret = 0;

    ASSERT(currd == current->domain);

    read_lock(&L1_global_argo_rwlock);

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
        gprintk(XENLOG_ERR, "argo: notify entry count(%u) exceeds max(%u)\n",
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
    read_unlock(&L1_global_argo_rwlock);

    return ret;
}

static long
sendv(struct domain *src_d, xen_argo_addr_t *src_addr,
      const xen_argo_addr_t *dst_addr, xen_argo_iov_t *iovs, unsigned int niov,
      uint32_t message_type)
{
    struct domain *dst_d = NULL;
    struct argo_link *link;
    struct argo_ring_id src_id, dst_id;
    struct argo_ring_info *ring_info;
    int ret = 0;
    unsigned int len = 0;

    argo_dprintk("sendv: (%u:%x)->(%u:%x) niov:%u type:%x\n",
                 src_addr->domain_id, src_addr->aport, dst_addr->domain_id,
                 dst_addr->aport, niov, message_type);

    /* Check padding is zeroed. */
    if ( unlikely(src_addr->pad || dst_addr->pad) )
        return -EINVAL;

    if ( src_addr->domain_id == XEN_ARGO_DOMID_ANY )
         src_addr->domain_id = src_d->domain_id;

    /* No domain is currently authorized to send on behalf of another */
    if ( unlikely(src_addr->domain_id != src_d->domain_id) )
        return -EPERM;

    src_id.aport = src_addr->aport;
    src_id.domain_id = src_d->domain_id;
    src_id.partner_id = dst_addr->domain_id;

    dst_d = get_domain_by_id(dst_addr->domain_id);
    if ( !dst_d )
        return -ESRCH;

    ret = xsm_argo_send(src_d, dst_d);
    if ( ret )
    {
        gprintk(XENLOG_ERR, "argo: XSM REJECTED %i -> %i\n",
                src_d->domain_id, dst_d->domain_id);

        put_domain(dst_d);

        return ret;
    }

    read_lock(&L1_global_argo_rwlock);

    if ( !src_d->argo )
    {
        ret = -ENODEV;
        goto out_unlock;
    }

    if ( !dst_d->argo )
    {
        argo_dprintk("!dst_d->argo, ECONNREFUSED\n");
        ret = -ECONNREFUSED;
        goto out_unlock;
    }

    read_lock(&src_d->argo->links_L2_rwlock);

    link = find_link(src_d, dst_d->domain_id);
    if ( !link )
    {
        ret = -ECONNREFUSED;
        goto out_unlock2;
    }

    dst_id.domain_id = dst_d->domain_id;
    dst_id.partner_id = src_id.domain_id;
    dst_id.aport = dst_addr->aport;

    read_lock(&link->rings_L3_rwlock);

    ring_info = find_ring_info_by_match(src_d, link, &dst_id);
    if ( !ring_info )
    {
        gprintk(XENLOG_ERR,
                "argo: vm%u connection refused, src (vm%u:%x) dst (vm%u:%x)\n",
                current->domain->domain_id, src_id.domain_id, src_id.aport,
                dst_addr->domain_id, dst_addr->aport);

        ret = -ECONNREFUSED;
    }
    else
    {
        spin_lock(&ring_info->L4_lock);

        /*
         * Obtain the total size of data to transmit -- sets the 'len' variable
         * -- and sanity check that the iovs conform to size and number limits.
         */
        ret = iov_count(iovs, niov, &len);
        if ( !ret )
        {
            ret = ringbuf_insert(dst_d, link, ring_info, &src_id, iovs, niov,
                                 message_type, len);
            if ( ret == -EAGAIN )
            {
                int rc;

                argo_dprintk("argo_ringbuf_sendv failed, EAGAIN\n");
                /* requeue to issue a notification when space is there */
                rc = pending_requeue(dst_d, link, ring_info, src_id.domain_id,
                                     len);
                if ( rc )
                    ret = rc;
            }
        }

        spin_unlock(&ring_info->L4_lock);
    }

    read_unlock(&link->rings_L3_rwlock);

 out_unlock2:
    read_unlock(&src_d->argo->links_L2_rwlock);

 out_unlock:
    read_unlock(&L1_global_argo_rwlock);

    if ( ret >= 0 )
        signal_domain(dst_d);

    if ( dst_d )
        put_domain(dst_d);

    return ( ret < 0 ) ? ret : len;
}

long
do_argo_op(unsigned int cmd, XEN_GUEST_HANDLE_PARAM(void) arg1,
           XEN_GUEST_HANDLE_PARAM(void) arg2, unsigned long raw_arg3,
           unsigned long raw_arg4)
{
    struct domain *currd = current->domain;
    long rc;
    unsigned int arg3 = raw_arg3, arg4 = raw_arg4;

    argo_dprintk("->do_argo_op(%u,%p,%p,%lu,0x%lx)\n", cmd,
                 (void *)arg1.p, (void *)arg2.p, raw_arg3, raw_arg4);

    /* Reject numeric hypercall args outside 32-bit range */
    if ( (arg3 != raw_arg3) || (arg4 != raw_arg4) )
        return -EINVAL;

    if ( unlikely(!opt_argo) )
        return -EOPNOTSUPP;

    rc = xsm_argo_enable(currd);
    if ( rc )
        return rc;

    switch ( cmd )
    {
    case XEN_ARGO_OP_register_ring:
    {
        XEN_GUEST_HANDLE_PARAM(xen_argo_register_ring_t) reg_hnd =
            guest_handle_cast(arg1, xen_argo_register_ring_t);
        XEN_GUEST_HANDLE_PARAM(xen_argo_gfn_t) gfn_hnd =
            guest_handle_cast(arg2, xen_argo_gfn_t);
        /* arg3: npage, arg4: flags */

        BUILD_BUG_ON(!IS_ALIGNED(XEN_ARGO_MAX_RING_SIZE, PAGE_SIZE));

        if ( unlikely(arg3 > (XEN_ARGO_MAX_RING_SIZE >> PAGE_SHIFT)) )
        {
            rc = -EINVAL;
            break;
        }

        /* Check array to allow use of the faster __copy operations later */
        if ( unlikely(!guest_handle_okay(gfn_hnd, arg3)) )
        {
            rc = -EFAULT;
            break;
        }

        rc = register_ring(currd, reg_hnd, gfn_hnd, arg3, arg4);
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
        xen_argo_iov_t iovs[XEN_ARGO_MAXIOV];
        unsigned int niov;

        XEN_GUEST_HANDLE_PARAM(xen_argo_send_addr_t) send_addr_hnd =
            guest_handle_cast(arg1, xen_argo_send_addr_t);
        XEN_GUEST_HANDLE_PARAM(xen_argo_iov_t) iovs_hnd =
            guest_handle_cast(arg2, xen_argo_iov_t);
        /* arg3 is niov */
        /* arg4 is message_type. Must be a 32-bit value. */

        /* XEN_ARGO_MAXIOV value determines size of iov array on stack */
        BUILD_BUG_ON(XEN_ARGO_MAXIOV > 8);

        rc = copy_from_guest(&send_addr, send_addr_hnd, 1) ? -EFAULT : 0;
        if ( rc )
        {
            rc = -EFAULT;
            break;
        }

        /*
         * Reject niov above maximum limit or message_types that are outside
         * 32 bit range.
         */
        if ( unlikely((arg3 > XEN_ARGO_MAXIOV) || (arg4 != (uint32_t)arg4)) )
        {
            rc = -EINVAL;
            break;
        }
        niov = array_index_nospec(arg3, XEN_ARGO_MAXIOV + 1);

        rc = copy_from_guest(iovs, iovs_hnd, niov) ? -EFAULT : 0;
        if ( rc )
        {
            rc = -EFAULT;
            break;
        }

        rc = sendv(currd, &send_addr.src, &send_addr.dst, iovs, niov, arg4);
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

    argo_dprintk("<-do_argo_op(%u)=%ld\n", cmd, rc);

    return rc;
}

#ifdef CONFIG_COMPAT
long
compat_argo_op(unsigned int cmd, XEN_GUEST_HANDLE_PARAM(void) arg1,
               XEN_GUEST_HANDLE_PARAM(void) arg2, unsigned long arg3,
               unsigned long arg4)
{
    struct domain *currd = current->domain;
    long rc;
    xen_argo_send_addr_t send_addr;
    xen_argo_iov_t iovs[XEN_ARGO_MAXIOV];
    compat_argo_iov_t compat_iovs[XEN_ARGO_MAXIOV];
    unsigned int i, niov;
    XEN_GUEST_HANDLE_PARAM(xen_argo_send_addr_t) send_addr_hnd;

    /* check XEN_ARGO_MAXIOV as it sizes stack arrays: iovs, compat_iovs */
    BUILD_BUG_ON(XEN_ARGO_MAXIOV > 8);

    /* Forward all ops besides sendv to the native handler. */
    if ( cmd != XEN_ARGO_OP_sendv )
        return do_argo_op(cmd, arg1, arg2, arg3, arg4);

    if ( unlikely(!opt_argo) )
        return -EOPNOTSUPP;

    rc = xsm_argo_enable(currd);
    if ( rc )
        return rc;

    argo_dprintk("->compat_argo_op(%u,%p,%p,%lu,0x%lx)\n", cmd,
                 (void *)arg1.p, (void *)arg2.p, arg3, arg4);

    send_addr_hnd = guest_handle_cast(arg1, xen_argo_send_addr_t);
    /* arg2: iovs, arg3: niov, arg4: message_type */

    rc = copy_from_guest(&send_addr, send_addr_hnd, 1) ? -EFAULT : 0;
    if ( rc )
        goto out;

    if ( unlikely(arg3 > XEN_ARGO_MAXIOV) )
    {
        rc = -EINVAL;
        goto out;
    }
    niov = array_index_nospec(arg3, XEN_ARGO_MAXIOV + 1);

    rc = copy_from_guest(compat_iovs, arg2, niov) ? -EFAULT : 0;
    if ( rc )
        goto out;

    for ( i = 0; i < niov; i++ )
    {
#define XLAT_argo_iov_HNDL_iov_hnd(_d_, _s_) \
    guest_from_compat_handle((_d_)->iov_hnd, (_s_)->iov_hnd)

        XLAT_argo_iov(&iovs[i], &compat_iovs[i]);

#undef XLAT_argo_iov_HNDL_iov_hnd
    }

    rc = sendv(currd, &send_addr.src, &send_addr.dst, iovs, niov, arg4);
 out:
    argo_dprintk("<-compat_argo_op(%u)=%ld\n", cmd, rc);

    return rc;
}
#endif

static void
argo_domain_init(struct argo_domain *argo)
{
    unsigned int i;

    rwlock_init(&argo->links_L2_rwlock);
    spin_lock_init(&argo->wildcard_L2_lock);
    spin_lock_init(&argo->count_L2_lock);

    for ( i = 0; i < ARGO_HASHTABLE_SIZE; ++i )
    {
        INIT_LIST_HEAD(&argo->upper_links_hash[i]);
        INIT_LIST_HEAD(&argo->lower_links_hash[i]);
    }
    INIT_LIST_HEAD(&argo->wildcard_pend_list);
}

int
argo_init(struct domain *d)
{
    struct argo_domain *argo;

    if ( !opt_argo || xsm_argo_enable(d) )
    {
        argo_dprintk("argo disabled, domid: %u\n", d->domain_id);
        return 0;
    }

    argo_dprintk("init: domid: %u\n", d->domain_id);

    argo = xzalloc(struct argo_domain);
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

    argo_dprintk("destroy: domid %u d->argo=%p\n", d->domain_id, d->argo);

    if ( d->argo )
    {
        domain_rings_remove_all(d);
        wildcard_rings_pending_remove(d);
        XFREE(d->argo);
    }

    write_unlock(&L1_global_argo_rwlock);
}

void
argo_soft_reset(struct domain *d)
{
    write_lock(&L1_global_argo_rwlock);

    argo_dprintk("soft reset d=%u d->argo=%p\n", d->domain_id, d->argo);

    if ( d->argo )
    {
        domain_rings_remove_all(d);
        wildcard_rings_pending_remove(d);

        /*
         * Since neither opt_argo or xsm_argo_enable(d) can change at runtime,
         * if d->argo is true then both opt_argo and xsm_argo_enable(d) must be
         * true, and we can assume that init is allowed to proceed again here.
         */
        argo_domain_init(d->argo);
    }

    write_unlock(&L1_global_argo_rwlock);
}
