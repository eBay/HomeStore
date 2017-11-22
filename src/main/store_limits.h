//
// Created by Kadayam, Hari on 16/11/17.
//

#ifndef OMSTORE_STORE_LIMITS_H
#define OMSTORE_STORE_LIMITS_H


namespace omstore {
/*
 * This defines the miminum size the blkstore at the backend operates on. It will operate in increments of this.
 * What this means is Caching layer, BlkStore layer, VirtualDev layer works only in this increments.
 */
#define BLKSTORE_BLK_SIZE    8192U
}
#endif //OMSTORE_STORE_LIMITS_H
