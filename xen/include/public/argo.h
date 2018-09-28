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

typedef struct argo_addr
{
    uint32_t port;
    domid_t domain_id;
    uint16_t pad;
} argo_addr_t;

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

#endif
