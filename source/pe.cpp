#include <yail/detail/pe.hpp>

namespace yail::detail
{
    std::optional<WORD> get_pe_machine(const std::span<const std::uint8_t>& raw_pe)
    {
        if (raw_pe.size() < sizeof(IMAGE_DOS_HEADER))
            return std::nullopt;

        const auto dos_headers = reinterpret_cast<const IMAGE_DOS_HEADER*>(raw_pe.data());

        if (dos_headers->e_magic != IMAGE_DOS_SIGNATURE || dos_headers->e_lfanew < 0)
            return std::nullopt;

        constexpr std::size_t nt_prefix_size = sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER);
        const auto nt_offset = static_cast<std::size_t>(dos_headers->e_lfanew);
        if (nt_offset > raw_pe.size() || raw_pe.size() - nt_offset < nt_prefix_size)
            return std::nullopt;

        const auto* signature = reinterpret_cast<const DWORD*>(raw_pe.data() + nt_offset);
        if (*signature != IMAGE_NT_SIGNATURE)
            return std::nullopt;

        const auto* file_header = reinterpret_cast<const IMAGE_FILE_HEADER*>(signature + 1);
        return file_header->Machine;
    }

    bool relocate_for_base(std::uint8_t* local_image, const std::uintptr_t target_base)
    {
        const auto* dos_headers = reinterpret_cast<IMAGE_DOS_HEADER*>(local_image);
        auto* nt_headers = reinterpret_cast<IMAGE_NT_HEADERS*>(local_image + dos_headers->e_lfanew);

        const auto delta = static_cast<std::intptr_t>(target_base - nt_headers->OptionalHeader.ImageBase);
        if (delta == 0)
            return true;

        // ReSharper disable once CppUseStructuredBinding
        const auto& relocation_directory = nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        if (!relocation_directory.Size)
            return false;

        auto* block = reinterpret_cast<IMAGE_BASE_RELOCATION*>(local_image + relocation_directory.VirtualAddress);
        while (block->SizeOfBlock && block->VirtualAddress)
        {
            const std::size_t count = (block->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            auto* info = reinterpret_cast<std::uint16_t*>(block + 1);
#ifdef _WIN64
            constexpr WORD reloc_entry_type = IMAGE_REL_BASED_DIR64;
#else
            constexpr WORD reloc_entry_type = IMAGE_REL_BASED_HIGHLOW;
#endif
            for (std::size_t i = 0; i < count; i++, info++)
            {
                if (*info >> 0x0C != reloc_entry_type)
                    continue;
                auto* patch = reinterpret_cast<std::uintptr_t*>(local_image + block->VirtualAddress + (*info & 0xFFF));
                *patch += delta;
            }
            block = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<std::uint8_t*>(block) + block->SizeOfBlock);
        }

        nt_headers->OptionalHeader.ImageBase = target_base;
        return true;
    }
}
