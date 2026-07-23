#pragma once

#include "common.hpp"

#define EXL_MODULE_NAME "OCoopMod"

#define EXL_DEBUG
#define EXL_USE_FAKEHEAP

/*
#define EXL_SUPPORTS_REBOOTPAYLOAD
*/

namespace exl::setting {
    /* How large the fake .bss heap will be. */
    constexpr size_t HeapSize = 0x5000;

    /* How large the JIT area will be for hooks. OCoop reached the stock
     * 40-trampoline ceiling on PATCH-0047; one extra page raises the pool to
     * 61 slots while keeping the allocation page-aligned. */
    constexpr size_t JitSize = 0x3000;

    /* How large the area will be inline hook pool. */
    constexpr size_t InlinePoolSize = 0x1000;

    /* How large the formatting buffer should be for logging. The buffer will be on the stack. */
    constexpr size_t LogBufferSize = 512;

    /* Sanity checks. */
    static_assert(ALIGN_UP(JitSize, PAGE_SIZE) == JitSize, "");
    static_assert(ALIGN_UP(InlinePoolSize, PAGE_SIZE) == InlinePoolSize, "");
}
