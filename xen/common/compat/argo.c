/******************************************************************************
 * Argo : Hypervisor-Mediated data eXchange
 *
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

#include <xen/lib.h>

#include <public/argo.h>

#include <compat/argo.h>

CHECK_argo_addr;
CHECK_argo_register_ring;
CHECK_argo_ring;
CHECK_argo_unregister_ring;

/*
 * Disable strict type checking in this compat validation macro for the
 * following struct checks because it cannot handle fields within structs that
 * have types that differ in the compat versus non-compat structs.
 * Replace it with a field size check which is sufficient here.
 */

#undef CHECK_FIELD_COMMON_
#define CHECK_FIELD_COMMON_(k, name, n, f) \
static inline int __maybe_unused name(k xen_ ## n *x, k compat_ ## n *c) \
{ \
    BUILD_BUG_ON(offsetof(k xen_ ## n, f) != \
                 offsetof(k compat_ ## n, f)); \
    return sizeof(x->f) == sizeof(c->f); \
}

CHECK_argo_send_addr;
CHECK_argo_iov;
