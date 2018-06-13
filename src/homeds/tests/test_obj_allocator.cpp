#include "homeds/memory/obj_allocator.hpp"
#include <sds_logging/logging.h>

SDS_LOGGING_INIT

using namespace homeds;
using namespace std;

template <typename T>
class Node
{
public:
    Node(T id) {
        m_id = id;
    }

    T get_id() {return m_id;}

    ~Node() {
        std::cout << "Destructor of Node " << m_id << " called\n";
    }
private:
    T m_id;
};

int main(int argc, char** argv)
{
    Node<uint64_t> *ptr1 = homeds::ObjectAllocator< Node< uint64_t > >::make_object((uint64_t) -1);
    std::cout << "ptr1 = " << (void *)ptr1 << " Id = " << ptr1->get_id() << std::endl;
    homeds::ObjectAllocator< Node<uint64_t> >::deallocate(ptr1);
}
