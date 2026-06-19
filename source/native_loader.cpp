#include <yail/detail/native_loader.hpp>
#include <winternl.h>
#include <array>
#include <omath/utility/pe_pattern_scan.hpp>

namespace yail::detail
{
    namespace
    {
        struct LdrDataTableEntryFull final
        {
            LIST_ENTRY in_load_order_links;
            LIST_ENTRY in_memory_order_links;
            LIST_ENTRY in_initialization_order_links;
            PVOID dll_base;
            PVOID entry_point;
            ULONG size_of_image;
            [[maybe_unused]] UNICODE_STRING full_dll_name;
            [[maybe_unused]] UNICODE_STRING base_dll_name;
            [[maybe_unused]] ULONG flags;
            [[maybe_unused]] USHORT obsolete_load_count;
            [[maybe_unused]] USHORT tls_index;
            LIST_ENTRY hash_links;
            [[maybe_unused]] ULONG time_date_stamp;
        };

#ifdef _WIN64
        using LdrpHandleTlsDataFn = NTSTATUS(NTAPI*)(LdrDataTableEntryFull*);
        using RtlInsertInvertedFunctionTableFn = void(NTAPI*)(PVOID image_base, ULONG size_of_image);
#else
        // Modern x86 ntdll uses __fastcall for these internal functions despite the
        // legacy `_Name@N` symbol decoration - args come in ECX/EDX, not on the stack.
        using LdrpHandleTlsDataFn = NTSTATUS(__fastcall*)(LdrDataTableEntryFull*);
        using RtlInsertInvertedFunctionTableFn = void(__fastcall*)(PVOID image_base, ULONG size_of_image);
#endif
        // The shellcode reference implementation used for regeneration lives in tools/generate_shellcode.cpp.
    } // namespace

    std::expected<void*, std::string> find_ldrp_handle_tls_data()
    {
        constexpr std::array signatures = {
#ifdef _WIN64
            "4C 8B DC 49 89 5B ? 49 89 73 ? 57 41 54 41 55 41 56 41 57 48 81 EC ? ? ? ? 48 8B 05 ? ? ? ? 48 33 C4 48 89 84 24 ? ? ? ? 48 8B F9", // Windows 11 24H2
            "48 89 5C 24 ? 48 89 74 24 ? 48 89 7C 24 ? 41 55 41 56 41 57 48 81 EC",
#else
            // x86 - patterns may need updating per Windows build
            "8B FF 55 8B EC 83 EC ? 53 56 57 8B 7D ? 89 4D",
            "8B FF 55 8B EC 51 51 53 56 57 8B F1 89 75",
            "6A ? 68 ? ? ? ? E8 ? ? ? ? 8B C1 89 45 ? 89 45",
#endif
        };

        const auto* ntdll = GetModuleHandleA("ntdll.dll");
        for (const auto* sig : signatures)
        {
            if (const auto result = omath::PePatternScanner::scan_for_pattern_in_loaded_module(ntdll, sig))
                return reinterpret_cast<void*>(result.value());
        }

        return std::unexpected("Failed to find LdrpHandleTlsData");
    }

    std::expected<void*, std::string> find_rtl_insert_inverted_function_table()
    {
        constexpr std::array signatures = {
#ifdef _WIN64
            "48 8B C4 48 89 58 ? 48 89 68 ? 48 89 70 ? 57 48 83 EC ? 83 60", // Windows 11 24H2
            "4C 8B DC 49 89 5B ? 49 89 73 ? 57 48 83 EC ? 8B FA",
            "48 89 5C 24 ? 57 48 83 EC ? 8B DA 4C 8D 44 24" // win11 23h2?
#else
            // x86 - patterns may need updating per Windows build.
            // Win11 24H2 x86 ntdll: __fastcall convention (ECX/EDX), see typedef above.
            "8B FF 55 8B EC 83 EC ? 53 56 57 8D 45 ? 8B FA 50 8D 55", // Win11 24H2
            "8B FF 55 8B EC 51 51 53 56 57 8B 7D ? 8D 45",
            "8B FF 55 8B EC 53 56 57 8B 7D ? 8D 45",
#endif
        };

        const auto* ntdll = GetModuleHandleA("ntdll.dll");
        for (const auto* sig : signatures)
        {
            if (const auto result = omath::PePatternScanner::scan_for_pattern_in_loaded_module(ntdll, sig))
                return reinterpret_cast<void*>(result.value());
        }

        return std::unexpected("Failed to find RtlInsertInvertedFunctionTable");
    }
}
