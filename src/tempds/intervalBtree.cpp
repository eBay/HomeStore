#include <sys/types.h>
#include <atomic>
#include <iostream>
#include <cstring>
#include <assert.h>

using namespace omds::IntervalBtree;
using namespace std;

template<typename blobT>
intervalBtree<blobT>::intervalBtree(int num) {
        size = sizeof(struct indx) + num * sizeof(blobT);
        mem = malloc(size);
        root_indexes = static_cast<root_indx *>(mem);
        root_indexes->alloc_root_indx = -1; 
        root_indexes->free_root_indx = -1; 
        node_mem = mem + sizeof(root_indx);
        alloc_root = NULL;
        free_root = NULL;
        num_nodes = num;
        is_alloc = true;

        for (int i = 0; i < num; i++) {
                /* add the entries into free queue */
                insert_freeq(i);
        }   
}

template<typename blobT>
intervalBtree<blobT>::intervalBtree(uint64_t _size, void *_mem) {
        mem = malloc(size);
        memcpy(mem, _mem, size);
        size = _size;
        root_indexes = static_cast<root_indx *>(mem);
        node_mem = (struct node *)(_mem + sizeof(root_indx));
        num_nodes = (size - sizeof(root_indx))/(sizeof(struct node));
        if (root_indexes->alloc_root_indx != -1) {
                alloc_root = node_mem[root_indexes->alloc_root_indx];
        } else {
                alloc_root = NULL;
        }   
        if (root_indexes->free_root_indx != -1) {
                free_root = node_mem[root_indexes->free_root_indx];
        } else {
                free_root = NULL;
        }   
}
template<typename blobT>
intervalBtree<blobT>::~intervalBtree() {
        if (is_alloc) {
                free(mem);
        }
}

template<typename blobT>void
intervalBtree<blobT>::modify_size(int num) {
        uint64_t temp_size = sizeof(struct indx) + num * sizeof(blobT);
        node *temp_mem = malloc(temp_size);

        memcpy(temp_mem, mem, size);
        free(mem);

        mem = temp_mem;
        size = temp_size;
        root_indexes = static_cast<root_indx *>(mem);
        node_mem = mem + sizeof(root_indx);
        num_nodes = num;
        if (root_indexes->alloc_root_indx != -1) {
                alloc_root = node_mem[root_indexes->alloc_root_indx];
        } else {
                alloc_root = NULL;;
        }
        if (root_indexes->free_root_indx != -1) {
                free_root = node_mem[root_indexes->free_root_indx];
        } else {
                free_root = NULL;
        }

        for (int i = size; i < num; i++) {
                /* there is no child node of these nodes */
                insert_freeq(i);
        }
}

template<typename blobT> void
intervalBtree<blobT>::insert_freeq(int i) {
        struct node *temp_root = &node_mem[i];

        bzero(&node_mem[i], sizeof(struct node));
        if (free_root == NULL) {
                free_root->right_indx = i;
                free_root->left_indx = i;
        } else {
                temp_root->right_indx = root_indexes->free_root_indx;
                temp_root->left_indx = i;
        }
        root_indexes->free_root_indx = i;
        free_root = temp_root;
        /* TODO: need a way to compact this buffer */
}
template<typename blobT> struct node *
intervalBtree<blobT>::get_free_node() {
        if (free_root == NULL) {
                /* allocate 10 more entries */
                modify_size(10 + num_nodes);
        }
        assert(free_root != NULL);

        struct node * free_node = free_root;
        root_indexes->free_root_indx = free_root->right_indx;
        free_root = node_mem[free_root->right_indx];

        free_node->left_indx = free_node->right_indx =
                                        get_indx(free_node);

        return free_node;
}

template<typename blobT> int
intervalBtree<blobT>::merge(struct node &new_node, struct node &node) {
        const blobT new_blob = new_node.blob; /* these are temp values */
        const blobT blob = node.blob;

        if (blob.lo() == new_blob.lo()) {
                if (blob.hi() == new_blob.hi()) {
                        /* copying the value */
                        node.blob |= new_node.blob;
                        return 0;
                } else if (blob.hi() < new_blob.hi()) {
                        /* exisitng node would be completely merged with the new node */
                        node.blob |= new_blob;
                        /* new node is split */
                        new_node.blob.modify_lo(blob.hi() + 1);
                        return 1; // traverse right btree
                } else {
                        /* existing node would be partially merged. split the existing node and update the new node */
                        node.blob.modify_hi(new_blob.hi());
                        node.blob |= new_blob;

                        new_node.blob.modify_lo(new_blob.hi() + 1);
                        new_node.blob.modify_hi(blob.hi());
                        /* invalid the existing value as it will contain the new value now */
                        new_node.blob = blob;

                        return 1; // traverse right btree
                }
        } else if (blob.lo() > new_blob.lo()) {
                if (new_blob.hi() >= blob.lo()) {
                        if (new_blob.hi() < blob.hi()) {
                                /* we have three nodes to work here */
                                /* update hi of new node */
                                new_node.blob.modify_hi(blob.lo() - 1);

                                /* split the exsiting node into two. one contains the modified value
                                 * and other contains the existing value.
                                 */
                                node.blob.modify_hi(new_blob.hi());
                                /* OR with the existing value */
                                node.blob |= new_node.blob;

                                /* split the existing node */
                                struct node *other_node = get_free_node();
                                assert(other_node != NULL);
                                other_node->blob.modify_lo(new_blob.hi() + 1);
                                other_node->blob.modify_hi(blob.hi());
                                /* modifying the value by calling assignment operator */
                                other_node->blob = blob;
                                insert(other_node, node);

                                return -1; // traverse left binary tree
                        } else if (new_blob.hi() == blob.hi()) {
                                /* first node */
                                new_node.blob.modify_hi(blob.lo() - 1);

                                /* second node */
                                node.blob |= new_blob;
                                return -1;
                        } else { // new_bloby.hi() > blob.hi()
                                /* we have three nodes to work here */
                                /* first node */
                                new_node.blob.modify_hi(blob.lo() - 1);

                                /* second node */
                                node.blob |= new_blob;

                                /* third node */
                                struct node *other_node = get_free_node();
                                assert(new_node != NULL);
                                other_node->blob.modify_lo(blob.hi() + 1);
                                other_node->blob.modify_hi(new_blob.hi());
                                other_node->blob = new_blob;
                                insert(other_node, node);
				
                                return -1;
                        }
                } else if (new_blob.hi() + 1 == blob.lo()) {
                        if (new_blob == blob) {
                                blob.modify_lo(new_blob.lo());
                                return 0;
                        } else {
                                return -1;
                        }
                } else {
                        /* no overlapping. traverse left binary tree */
                        return -1;
                }
        } else { /* blob.lo() < new_blob.lo() */
                if (new_blob.lo() <= blob.hi()) {
                        if (new_blob.hi() < blob.hi()) {
                                /* first node */
                                node.blob.modify_hi(new_blob.lo() - 1);

                                /* second node */
                                new_node.blob |= blob;

                                /* third node */
                                struct node *other_node = get_free_node();
                                assert(new_node != NULL);
                                other_node->blob.modify_lo(new_blob.hi() + 1);
                                other_node->blob.modify_hi(blob.hi());
                                other_node->blob = blob;
                                insert(other_node, node);

                                return 1;
                        } else if (new_blob.hi() == blob.hi()) {
                                /* first node */
                                node.blob.modify_hi(new_blob.lo() - 1);

                                /* second node */
                                new_node.blob |= blob;
                                return 1;
                        } else { // new_blob.hi() > blob.hi()
                                /* first node */
                                node.blob.modify_hi(new_blob.lo() - 1);

                                /* second node */
                                new_node.blob |= blob;

                                /* third node */
                                struct node *other_node = get_free_node();
                                assert(new_node != NULL);
                                other_node->blob.modify_lo(blob.hi() + 1);
                                other_node->blob.modify_hi(new_blob.hi());
                                other_node->blob = new_blob;
                                insert(other_node, node);
                                return 1;
                        }
                } else if (new_blob.lo() == blob.hi() + 1) {
                        if (new_blob == blob) {
                                node.blob.modify_hi(new_blob.hi());
                                return 0;
                        } else {
                                return 1;
                        }
                } else {
                        /* no overlapping. traverse right binary tree */
                        return 1;
                }
        }
}

template<typename blobT> int
intervalBtree<blobT>::get_indx(node *new_node) {
        return ((new_node - node_mem)/sizeof(struct node));
}

/* TODO:rishabh: we should change it into RB tree */
template<typename blobT> int
intervalBtree<blobT>::insert(node *new_node, node *root) {
        if (alloc_root == NULL) {
                assert(root == NULL);
                /* this is the first node */
                alloc_root = new_node;
                return 0;
        } else if (root == NULL) {
                root = alloc_root;
        }

        int ret = merge(new_node, root);
        if (ret == 0) {
                /* free this node as it is merged with the existing node */
                insert_freeq(get_indx(new_node));
                return 0;
        } else if(ret > 0) {
                /* traverse right tree */
                if (root->right_indx == get_indx(root)) {
                        /* there is no right. insert this node */
                        root->right_indx = get_indx(new_node);
                        return 0;
                } else {
                        return(insert(new_node, &node_mem[root->right_indx]));
                }
        } else {
                /* traverse left tree */
                if (root->left_indx == get_indx(root)) {
                        /* there is no left. insert this node */
                        root->left_indx = get_indx(new_node);
                        return 0;
                } else {
                        return(insert(new_node, &node_mem[root->left_indx]));
                }
        }
}

template<typename blobT> int
intervalBtree<blobT>::insert_blob(const blobT blob) {
        node *new_node = get_free_node();
        assert(new_node != NULL);
        new_node->blob.modify_lo(blob.lo());
        new_node->blob.modify_hi(blob.hi());
        new_node->blob = blob;
        return (insert(new_node, NULL));
}

template<typename blobT> int
intervalBtree<blobT>::compare(blobT blob, struct node *root) {
         if (root->blob.lo() == blob.lo()) {
                return 0;
         } else if (blob.lo() > root->blob.lo()) {
                if (blob.lo() <= root->blob.hi()) {
                        return 0;
                } else {
                        return 1;
                }
        } else {
                if (blob.hi() >= root->blob.hi()) {
                        return 0;
                } else {
                        return -1;
                }
        }
}

template<typename blobT> uint32_t
intervalBtree<blobT>::read_internal(uint64_t hi, uint64_t lo, struct node* root,
                                std::vector<blobT> &blobList) {
        int total_blks = 0;
        if (root == NULL) {
                return 0;
        }
        int ret = compare(hi, lo,  root);
        if (ret == 0) {
                /* It means interval is overlapping */
                if (lo >= root->blob.lo()  && hi <= root->blob.hi()) {
                        /* asked interval is the subset of this interval */
                        blobT temp_blob = root;
                        temp_blob.modify_hi(hi);
                        temp_blob.modify_lo(lo);
                        blobList.push_back(temp_blob);
                        total_blks = temp_blob.hi() - temp_blob.lo() + 1;
                        /* return total number of blocks */
                        return total_blks;
                } else if (lo < root->blob.lo() && hi <= root->blob.hi()) {
                        blobT temp_blob = root;
                        temp_blob.modify_hi(hi);
                        total_blks = read(temp_blob.lo() - 1, lo,
                                                mem[root->left_indx], &blobList) +
                                                temp_blob.hi() - temp_blob.lo() + 1;
                        /* all the pushes should be in increasing order of hi and lo values */
                        blobList.push_back(temp_blob);
                        /* return total number of blocks */
                        return (total_blks);
                } else if (lo >= root->blob.lo() && hi > root->blob.hi()) {
                        blobT temp_blob = root;
                        temp_blob.modify_lo(lo);
                        blobList.push_back(temp_blob);
                        total_blks = read(hi, temp_blob.hi() + 1,
                                                mem[root->right_indx], &blobList) +
                                                temp_blob.hi() - temp_blob.lo() + 1;
                        /* return total number of blocks */
                        return (total_blks);
                } else if (lo < root->blob.lo() && hi > root->blob.hi()) {
                        {
                                blobT temp_blob = root;
                                temp_blob.modify_hi(hi);
                                total_blks = read(temp_blob.lo() - 1, lo,
                                                mem[root->left_indx], &blobList) +
                                                temp_blob.hi() - temp_blob.lo() + 1;
                                blobList.push_back(temp_blob);
                        }
                        {
                                blobT temp_blob = root;
                                temp_blob.modify_lo(lo);
                                blobList.push_back(temp_blob);
                                total_blks += read(hi, temp_blob.hi() + 1,
                                                        mem[root->right_indx], &blobList) +
                                                        temp_blob.hi() - temp_blob.lo() + 1;
                        }
                        return total_blks;

                } else {
                        assert(0);
                }

        } else if (ret > 0) {
                if (root->right_indx != get_indx(root)) {
                        return(read(hi, lo, mem[root->right_indx], &blobList));
                } else {
                        return 0;
                }
        } else {
                if (root->left_indx != get_indx(root)) {
                        return(read(hi, lo, mem[root->left_indx], &blobList));
                } else {
                        return 0;
                }
        }
}

template<typename blobT> blobT
intervalBtree<blobT>::get_root_blob(void) const {
        assert(alloc_root != NULL);
        return alloc_root->blob;
}

template<typename blobT> void *
intervalBtree<blobT>::modify(blobT blob, void *cookie) {
        /* TODO:rishabh: will do it later */
}

template<typename blobT> void *
intervalBtree<blobT>::del(blobT blob, void *cookie) {
        /* TODO:rishabh: will do it later */
}

template<typename blobT> void *
intervalBtree<blobT>::get_mem(void) const {
        return mem;
}

template<typename blobT> uint64_t
intervalBtree<blobT>::get_size(void) const {
        return size;
}

template<typename blobT> void
intervalBtree<blobT>::set_mem(void *omem, uint64_t size) {
        /* TODO: there is an intentional memory leak , which would be fixed in future once
         * append_blob doesn't create temp memory.
         */
        mem = omem;
        root_indexes = (root_indx *)mem;
        node_mem = (struct node *)(mem + sizeof(root_indx));
        num_nodes = (size - sizeof(root_indx))/(sizeof(struct node));
        if (root_indexes->alloc_root_indx != -1) {
                alloc_root = node_mem[root_indexes->alloc_root_indx];
        } else {
                alloc_root = NULL;
        }
        if (root_indexes->free_root_indx != -1) {
                free_root = node_mem[root_indexes->free_root_indx];
        } else {
                free_root = NULL;
        }
}

