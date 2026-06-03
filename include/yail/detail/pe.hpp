#pragma once
#include <Windows.h>
#include <cstdint>
#include <optional>
#include <span>

namespace yail::detail
{
    [[nodiscard]]
    std::optional<WORD> get_pe_machine(const std::span<const std::uint8_t>& raw_pe);

    [[nodiscard]]
    bool relocate_for_base(std::uint8_t* local_image, std::uintptr_t target_base);
}
