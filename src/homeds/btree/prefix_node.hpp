/*
 * BtreePrefixNode.hpp
 *
 *  Created on: 14-Sep-2016
 *      Author: hkadayam
 *
 *  Copyright © 2016 Kadayam, Hari. All rights reserved.
 */
#ifndef BTREE_PREFIXNODE_HPP_
#define BTREE_PREFIXNODE_HPP_

class BtreePrefixNode: public BtreeAbstractNode
{
public:
	BtreePrefixNode(bnodeid_t id, bool initPerp, bool initTrans) :
					BtreeAbstractNode(id, initPerp, initTrans)
	{
		this->setNodeType(BTREE_NODETYPE_PREFIX);
	}

	void insert(uint32_t ind, BtreeKey& key, BtreeValue& val)
	{
		// First move the record portion and create room to add 1 record.
		uint32_t sz = (getTotalEntries() - ind) * getPerRecordSize();
		uint8_t *from = getRecordAreaStart() + (ind * getPerRecordSize());
		uint8_t *to = getRecordAreaStart() + ( (ind + 1) * getPerRecordSize());
		memmove(to, from, sz);

		// Next move the data
		BtreePrefixRecord *insertRec = new (from)();

		// Next All index info in the records from current ind, needs to be incremented by 1,
		// since we are going to move the memory
		for (uint16_t i = ind; i < getTotalEntries(); i++) {
			BtreePrefixRecord *rec = getRecordPtr(ind);
			uint16_t prefixInd = rec->getPrefixRecordIndex();
			if (prefixInd >= ind) {
				rec->setPrefixRecordIndex(prefixInd + 1);
			}

			rec->getDataOffset()
		}

		// Next move the data portion to ensure the data is in the same
		// order as index. This helps in removing entries.

		uint32_t keySize;
		key.getMemBlob(&keySize);

		setNthEntry(ind, key, val);
		incrementEntries();
		incrementGen();

#ifdef DEBUG
		//print();
#endif
	}

	inline uint8_t *getRecordAreaStart()
	{
		return getNodeSpace() + sizeof(BtreePrefixHdr);
	}

	inline uint32_t getPerRecordSize()
	{
		return sizeof(BtreePrefixRecord);
	}

	inline BtreePrefixRecord *getRecordPtr(uint32_t ind)
	{
		return (BtreePrefixRecord *) (getRecordAreaStart() + (getPerRecordSize() * ind));
	}

	inline uint32_t getTotalRecordSize()
	{
		return getTotalEntries() * getPerRecordSize();
	}

	inline uint8_t *getDataAreaStart()
	{
		BtreePrefixHdr *hdr = (BtreePrefixHdr *) getNodeSpace();
		return (getNodeSpace() + hdr->dataOffset);
	}

	inline uint32_t getAvailableSpace()
	{
		// Start of the data area - end of record area and
		getDataAreaStart() - (getRecordAreaStart() * getTotalRecordSize());
	}

	inline bool isNodeFull(BtreeConfig cfg)
	{
		// leave area to at least one record
		return ( (getAvailableSpace() - getPerRecordSize()) < cfg.getMaxKeySize());
	}
};

struct BtreePrefixHdr
{
	uint16_t dataOffset;
}__attribute__((__packed__));

class BtreePrefixRecord
{
private:
	uint64_t m_dataSize :12;
	uint64_t m_dataOffset :12;
	uint64_t m_prefixRecordInd :12;
	uint64_t m_prefixDataSize :12;

public:
	void setDataSize(uint16_t sz)
	{
		m_dataSize = sz;
	}
	void setDataOffset(uint16_t o)
	{
		m_dataOffset = o;
	}
	;
	void setPrefixRecordIndex(uint16_t ind)
	{
		m_prefixRecordInd = ind;
	}
	void setPrefixSize(uint16_t sz)
	{
		m_prefixDataSize = sz;
	}
	;

	uint16_t getDataSize()
	{
		return m_dataSize;
	}
	uint16_t getDataOffset()
	{
		return m_dataOffset;
	}
	uint16_t getPrefixRecordIndex()
	{
		return m_prefixRecordInd;
	}
	uint16_t getPrefixSize()
	{
		return m_prefixDataSize;
	}

	uint32_t getNthKey(BtreePrefixNode *node, uint32_t myInd, uint8_t *outBlob)
	{
		uint8_t *curBlobPtr = outBlob;
		uint32_t size = 0;

		if (myInd != m_prefixRecordInd) {
			size = getNthKey(node, m_prefixRecordInd, outBlob);
			curBlobPtr += size;
		}
		memcpy(curBlobPtr, ((uint8_t *) node) + m_dataOffset, m_dataSize);
		size += m_dataSize;
		return (size);
	}

}__attribute__((__packed__));
