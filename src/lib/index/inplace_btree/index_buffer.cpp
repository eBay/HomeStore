/////////////////////// IndexBuffer methods //////////////////////////
IndexBuffer::IndexBuffer(BlkId blkid, uint32_t buf_size, uint32_t align_size) :
        m_blkid{blkid}, m_bytes{hs_utils::iobuf_alloc(buf_size, sisl::buftag::btree_node, align_size)} {}

IndexBuffer::IndexBuffer(uint8_t* raw_bytes, BlkId blkid) : m_blkid(blkid), m_bytes{raw_bytes} {}

IndexBuffer::~IndexBuffer() {
    if (m_bytes) { hs_utils::iobuf_free(m_bytes, sisl::buftag::btree_node); }
}

std::string IndexBuffer::to_string() const {
    if (m_is_meta_buf) {
        return fmt::format("Buf={} [Meta] index={} state={} create/dirty_cp={}/{} down_wait#={} freed={}",
                           voidptr_cast(const_cast< IndexBuffer* >(this)), m_index_ordinal, int_cast(state()),
                           m_created_cp_id, m_dirtied_cp_id, m_wait_for_down_buffers.get(), m_node_freed);
    } else {
        // store m_down_buffers in a string
        std::string down_bufs = "";
#ifndef NDEBUG
        for (auto const& down_buf : m_down_buffers) {
            if (auto ptr = down_buf.lock()) {
                fmt::format_to(std::back_inserter(down_bufs), "[{}]", voidptr_cast(ptr.get()));
            }
        }
#endif

        return fmt::format("Buf={} index={} state={} create/dirty_cp={}/{} down_wait#={}{} up={} node=[{}] down=[{}]",
                           voidptr_cast(const_cast< IndexBuffer* >(this)), m_index_ordinal, int_cast(state()),
                           m_created_cp_id, m_dirtied_cp_id, m_wait_for_down_buffers.get(),
                           m_node_freed ? " Freed" : "", voidptr_cast(const_cast< IndexBuffer* >(m_up_buffer.get())),
                           (m_bytes == nullptr) ? "not attached yet"
                                                : r_cast< PersistentHeader const* >(m_bytes)->to_compact_string(),
                           down_bufs);
    }
}
std::string IndexBuffer::to_string_dot() const {
    auto str = fmt::format("IndexBuffer {} ", reinterpret_cast< void* >(const_cast< IndexBuffer* >(this)));
    if (m_bytes == nullptr) {
        fmt::format_to(std::back_inserter(str), " node_buf=nullptr ");
    } else {
        fmt::format_to(std::back_inserter(str), " node_buf={} {} created/dirtied={}/{} {}  down_wait#={}",
                       static_cast< void* >(m_bytes), m_is_meta_buf ? "[META]" : "", m_created_cp_id, m_dirtied_cp_id,
                       m_node_freed ? "FREED" : "", m_wait_for_down_buffers.get());
    }
    return str;
}

MetaIndexBuffer::MetaIndexBuffer(superblk< index_table_sb >& sb) : IndexBuffer{nullptr, BlkId{}}, m_sb{sb} {
    m_is_meta_buf = true;
}

MetaIndexBuffer::MetaIndexBuffer(shared< MetaIndexBuffer > const& other) :
        IndexBuffer{nullptr, BlkId{}}, m_sb{other->m_sb} {
    m_is_meta_buf = true;
    m_bytes = hs_utils::iobuf_alloc(m_sb.size(), sisl::buftag::metablk, meta_service().align_size());
    copy_sb_to_buf();
}

MetaIndexBuffer::~MetaIndexBuffer() {
    if (m_bytes) {
        hs_utils::iobuf_free(m_bytes, sisl::buftag::metablk);
        m_bytes = nullptr;
    }
}

void MetaIndexBuffer::copy_sb_to_buf() { std::memcpy(m_bytes, m_sb.raw_buf()->cbytes(), m_sb.size()); }