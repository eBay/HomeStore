#pragma once

class PhysicalDevChunk;

namespace homestore {

class ChunkSelector {
public:
    ChunkSelector();
    virtual ~ChunkSelector() = default;
    ChunkSelector(const ChunkSelector&) = delete;
    ChunkSelector(ChunkSelector&&) noexcept = delete;
    ChunkSelector& operator=(const ChunkSelector&) = delete;
    ChunkSelector& operator=(ChunkSelector&&) noexcept = delete;

    virtual void add_chunk(PhysicalDevChunk*) = 0;
    virtual PhysicalDevChunk* select_chunk() = 0;
};

} // namespace homestore