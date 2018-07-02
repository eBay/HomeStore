#define _INTERVAL_BTREE_HPP_

#include <vector>
#include <stdint.h>

using namespace std;
namespace omds {
namespace IntervalBtree {
#define MAX_BLKS_BITS 10 // 1024 blocks

        class baseClassBlob {
                public: 
                        baseClassBlob(){};
                        virtual baseClassBlob& operator|=(struct baseClassBlob& other) = 0;
                        virtual baseClassBlob& operator=(struct baseClassBlob& other) = 0;
                        virtual bool operator==(struct baseClassBlob& other) = 0;
                        virtual void modify_lo(int lo) = 0;
                        virtual void modify_hi(int hi) = 0;
        };

        template <typename blobT>
        class intervalBtree {
                private:
                struct node {
                        blobT blob;;
                        uint64_t left_indx:MAX_BLKS_BITS;
                        uint64_t right_indx:MAX_BLKS_BITS;
                };
                struct root_indx {
                        int alloc_root_indx;
                        int free_root_indx;
                };
                void *mem;
                bool is_alloc; /* set only memory is created by this object */
                int size;
                node* node_mem;
                int num_nodes;
                struct root_indx *root_indexes;
                struct node *alloc_root;
                struct node *free_root;

                void modify_size(int num);
                void insert_freeq(int i);
                struct node* get_free_node();
                int merge(struct node &new_node, struct node &node);
                int get_indx(node *new_node);
                int insert(node *new_node, node *root);
                int compare(blobT blob, struct node *root);
                uint32_t read_internal(uint64_t hi, uint64_t lo, struct node  *node,
                                                        std::vector<blobT> &blobList);
                public:
                intervalBtree(int num);
                ~intervalBtree();
                intervalBtree(uint64_t size, void *_mem);
                void *get_mem() const;
                uint64_t get_size() const;
                void set_mem(void *omem,uint64_t size);
                int insert_blob(const blobT blob);
                uint32_t read(uint64_t hi, uint64_t lo, std::vector<blobT> &blobList);
                blobT get_root_blob(void) const;
                void *modify(blobT blob, void *cookie);
                void *del(blobT blob, void *cookie);

        };
}
}
#endif
