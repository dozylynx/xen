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

#ifndef __XEN_PUBLIC_ARGO_H__
#define __XEN_PUBLIC_ARGO_H__

#include "xen.h"

#define ARGO_RING_MAGIC      0xbd67e163e7777f2fULL

#define ARGO_DOMID_ANY           DOMID_INVALID

/*
 * The maximum size of an Argo ring is defined to be: 16GB
 *  -- which is 0x1000000 or 16777216 bytes.
 * A byte index into the ring is at most 24 bits.
 */
#define ARGO_MAX_RING_SIZE  (16777216ULL)

/*
 * ARGO_MAXIOV : maximum number of iovs accepted in a single sendv.
 * Rationale for the value:
 * The Linux argo driver never passes more than two iovs.
 * Linux defines UIO_MAXIOV as 1024.
 * POSIX mandates at least 16 -- not that this is a POSIX API of course.
 *
 * Limit the total amount of data posted in a single argo operation to
 * no more than 2^31 bytes to reduce risk of integer overflow defects.
 * Each argo iov can hold ~ 2^24 bytes, so set ARGO_MAXIOV to 2^(31-24),
 * minus one to enable simple efficient bounds checking via masking: 127.
*/
#define ARGO_MAXIOV          127U

typedef struct argo_iov
{
    uint64_t iov_base;
    uint32_t iov_len;
    uint32_t pad;
} argo_iov_t;
DEFINE_XEN_GUEST_HANDLE(argo_iov_t);

/* pfn type: 64-bit on all architectures to aid avoiding a compat ABI */
typedef uint64_t argo_pfn_t;

typedef struct argo_addr
{
    uint32_t port;
    domid_t domain_id;
    uint16_t pad;
} argo_addr_t;

typedef struct argo_send_addr
{
    argo_addr_t src;
    argo_addr_t dst;
} argo_send_addr_t;

typedef struct argo_ring_id
{
    struct argo_addr addr;
    domid_t partner;
    uint16_t pad;
} argo_ring_id_t;

typedef struct argo_ring
{
    uint64_t magic;
    argo_ring_id_t id;
    uint32_t len;
    /* Guests should use atomic operations to access rx_ptr */
    uint32_t rx_ptr;
    /* Guests should use atomic operations to access tx_ptr */
    uint32_t tx_ptr;
    uint8_t reserved[32];
#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 199901L
    uint8_t ring[];
#elif defined(__GNUC__)
    uint8_t ring[0];
#endif
} argo_ring_t;

/*
 * Messages on the ring are padded to 128 bits
 * Len here refers to the exact length of the data not including the
 * 128 bit header. The message uses
 * ((len + 0xf) & ~0xf) + sizeof(argo_ring_message_header) bytes.
 * Using typeof(a) make clear that this does not truncate any high-order bits.
 */
#define ARGO_ROUNDUP(a) (((a) + 0xf) & ~(typeof(a))0xf)

struct argo_ring_message_header
{
    uint32_t len;
    argo_addr_t source;
    uint32_t message_type;
#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 199901L
    uint8_t data[];
#elif defined(__GNUC__)
    uint8_t data[0];
#endif
};

/*
 * Hypercall operations
 */

/*
 * ARGO_MESSAGE_OP_register_ring
 *
 * Register a ring using the indicated memory.
 * Also used to reregister an existing ring (eg. after resume from sleep).
 *
 * arg1: XEN_GUEST_HANDLE(argo_ring_t)
 * arg2: XEN_GUEST_HANDLE(argo_pfn_t)
 * arg3: uint32_t npages
 * arg4: uint32_t flags
 */
#define ARGO_MESSAGE_OP_register_ring     1

/* Register op flags */
/*
 * Fail exist:
 * If set, reject attempts to (re)register an existing established ring.
 * If clear, reregistration occurs if the ring exists, with the new ring
 * taking the place of the old, preserving tx_ptr if it remains valid.
 */
#define ARGO_REGISTER_FLAG_FAIL_EXIST  0x1

/* Mask for all defined flags */
#define ARGO_REGISTER_FLAG_MASK ARGO_REGISTER_FLAG_FAIL_EXIST

/*
 * ARGO_MESSAGE_OP_unregister_ring
 *
 * Unregister a previously-registered ring, ending communication.
 *
 * arg1: XEN_GUEST_HANDLE(argo_ring_t)
 */
#define ARGO_MESSAGE_OP_unregister_ring     2

/*
 * ARGO_MESSAGE_OP_sendv
 *
 * Send a list of buffers contained in iovs.
 *
 * The send address struct specifies the source and destination addresses
 * for the message being sent, which are used to find the destination ring:
 * Xen first looks for a most-specific match with a registered ring with
 *  (id.addr == dst) and (id.partner == sending_domain) ;
 * if that fails, it then looks for a wildcard match (aka multicast receiver)
 * where (id.addr == dst) and (id.partner == DOMID_ANY).
 *
 * For each iov entry, send iov_len bytes from iov_base to the destination ring.
 * If insufficient space exists in the destination ring, it will return -EAGAIN
 * and Xen will notify the caller when sufficient space becomes available.
 *
 * The message type is a 32-bit data field available to communicate message
 * context data (eg. kernel-to-kernel, rather than application layer).
 *
 * arg1: XEN_GUEST_HANDLE(argo_send_addr_t) source and dest addresses
 * arg2: XEN_GUEST_HANDLE(argo_iov_t) iovs
 * arg3: uint32_t niov
 * arg4: uint32_t message type
 */
#define ARGO_MESSAGE_OP_sendv               5

/* The maximum size of a guest message that may be sent on an Argo ring. */
#define ARGO_MAX_MSG_SIZE ((ARGO_MAX_RING_SIZE) - \
        (sizeof(struct argo_ring_message_header)) - \
        ARGO_ROUNDUP(1))

#endif
