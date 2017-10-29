#include "cds/init.h"
#include <stdio.h>

#include "../memory/obj_allocator.hpp"

using namespace omds;
using namespace std;

class Node : public omds::RefCountedObject< Node > 
{
public:
	Node(int32_t id) {
		m_id = id;
	}

	int32_t get_id() {return m_id;}

	~Node() {
		std::cout << "Destructor of Node " << m_id << " called\n";
	}
private:
	int32_t m_id;
};

int main(int argc, char** argv)
{
	boost::intrusive_ptr< Node > ptr2;
	boost::intrusive_ptr< Node > ptr1 = omds::ObjectAllocator< Node >::make_object(1000);
	{
		ptr2 = omds::ObjectAllocator< Node >::make_object(2000);
		std::cout << "ptr2 = " << ptr2->get_id() << "\n";
		ptr2 = ptr1;
	}
	std::cout << "ptr2 = " << ptr2->get_id() << "\n";
}
