#ifndef DFM_LOADER_ELF_H
#define DFM_LOADER_ELF_H

// Internal, side-effect-free helpers shared by the loader and host regression tests.
#include <elf.h>
#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <string_view>
#include <unordered_map>

namespace loader::detail {

inline constexpr size_t kMaxModuleSize = 64 * 1024 * 1024;

inline bool range_ok(size_t size, uint64_t offset, uint64_t length)
{
    return offset <= size && length <= size - offset;
}

template <typename T>
bool read_object(std::string_view data, uint64_t offset, T& out)
{
    if (!range_ok(data.size(), offset, sizeof(T)))
        return false;
    std::memcpy(&out, data.data() + offset, sizeof(T));
    return true;
}

class ElfView {
public:
    explicit ElfView(std::string_view image) : image_(image) {}

    bool parse()
    {
        if (!read_object(image_, 0, header_) ||
            std::memcmp(header_.e_ident, ELFMAG, SELFMAG) != 0 ||
            header_.e_ident[EI_CLASS] != ELFCLASS64 ||
            header_.e_ident[EI_DATA] != ELFDATA2LSB ||
            header_.e_ident[EI_VERSION] != EV_CURRENT ||
            header_.e_version != EV_CURRENT || header_.e_type != ET_REL ||
            header_.e_machine != EM_AARCH64 ||
            header_.e_ehsize != sizeof(Elf64_Ehdr) ||
            header_.e_shentsize != sizeof(Elf64_Shdr) ||
            header_.e_shnum == 0 || header_.e_shstrndx == SHN_UNDEF ||
            header_.e_shstrndx >= header_.e_shnum ||
            !range_ok(image_.size(), header_.e_shoff,
                      uint64_t(header_.e_shnum) * sizeof(Elf64_Shdr)))
            return false;

        if (!section_at(header_.e_shstrndx, names_) ||
            names_.sh_type != SHT_STRTAB ||
            !range_ok(image_.size(), names_.sh_offset, names_.sh_size))
            return false;

        for (uint16_t i = 0; i < header_.e_shnum; ++i) {
            Elf64_Shdr section{};
            std::string_view name;
            if (!section_at(i, section) || !string_at(names_, section.sh_name, name))
                return false;
            if (section.sh_type != SHT_NOBITS && section.sh_type != SHT_NULL &&
                !range_ok(image_.size(), section.sh_offset, section.sh_size))
                return false;
            const uint64_t alignment = section.sh_addralign;
            if (alignment != 0 && (alignment & (alignment - 1)) != 0)
                return false;
        }
        return true;
    }

    uint64_t section_offset(uint16_t index) const
    {
        return header_.e_shoff + uint64_t(index) * sizeof(Elf64_Shdr);
    }

    bool section_at(uint16_t index, Elf64_Shdr& out) const
    {
        return index < header_.e_shnum && read_object(image_, section_offset(index), out);
    }

    bool section_named(std::string_view wanted, Elf64_Shdr& out,
                       uint16_t* index = nullptr) const
    {
        for (uint16_t i = 0; i < header_.e_shnum; ++i) {
            Elf64_Shdr section{};
            std::string_view name;
            if (!section_at(i, section) || !string_at(names_, section.sh_name, name))
                return false;
            if (name == wanted) {
                out = section;
                if (index)
                    *index = i;
                return true;
            }
        }
        return false;
    }

    bool string_at(const Elf64_Shdr& section, uint64_t offset, std::string_view& out) const
    {
        if (!range_ok(image_.size(), section.sh_offset, section.sh_size) ||
            offset >= section.sh_size)
            return false;
        const char* begin = image_.data() + section.sh_offset + offset;
        const auto* end = static_cast<const char*>(
                std::memchr(begin, '\0', size_t(section.sh_size - offset)));
        if (!end)
            return false;
        out = std::string_view(begin, size_t(end - begin));
        return true;
    }

    bool symbol_tables(Elf64_Shdr& symbols, Elf64_Shdr& strings) const
    {
        return section_named(".symtab", symbols) && symbols.sh_type == SHT_SYMTAB &&
               symbols.sh_entsize == sizeof(Elf64_Sym) &&
               symbols.sh_size % sizeof(Elf64_Sym) == 0 &&
               range_ok(image_.size(), symbols.sh_offset, symbols.sh_size) &&
               symbols.sh_link < header_.e_shnum &&
               section_at(uint16_t(symbols.sh_link), strings) &&
               strings.sh_type == SHT_STRTAB &&
               range_ok(image_.size(), strings.sh_offset, strings.sh_size);
    }

    bool modinfo(std::string_view key, std::string& value) const
    {
        Elf64_Shdr section{};
        if (!section_named(".modinfo", section) || section.sh_type != SHT_PROGBITS)
            return false;
        const std::string prefix = std::string(key) + '=';
        for (uint64_t offset = 0; offset < section.sh_size;) {
            std::string_view entry;
            if (!string_at(section, offset, entry))
                return false;
            if (entry.starts_with(prefix)) {
                value = entry.substr(prefix.size());
                return true;
            }
            offset += entry.size() + 1;
        }
        return false;
    }

private:
    std::string_view image_;
    Elf64_Ehdr header_{};
    Elf64_Shdr names_{};
};

inline std::string_view canonical_symbol(std::string_view name)
{
    // Only compiler suffixes known to ksud; "foo" must never match "foobar".
    const size_t suffix = std::min(name.find('$'), name.find(".llvm."));
    return name.substr(0, suffix);
}

class KernelSymbols {
public:
    void add_line(const char* line)
    {
        unsigned long long address = 0;
        char type = 0;
        char name[512]{};
        char owner[2]{};
        // A fourth field identifies symbols owned by a loadable module. Making
        // these SHN_ABS would bypass dependency/refcount tracking in the kernel.
        if (std::sscanf(line, "%llx %c %511s %1s", &address, &type, name, owner) != 3 ||
            address == 0)
            return;
        insert(exact_, name, uint64_t(address));
        const auto canonical = canonical_symbol(name);
        if (!canonical.empty() && canonical != name)
            insert(aliases_, std::string(canonical), uint64_t(address));
    }

    uint64_t find(const std::string& name, bool& aliased) const
    {
        aliased = false;
        if (const auto it = exact_.find(name); it != exact_.end())
            return it->second;
        if (const auto it = aliases_.find(name); it != aliases_.end()) {
            aliased = it->second != 0;
            return it->second;
        }
        return 0;
    }

    bool empty() const { return exact_.empty(); }

private:
    static void insert(std::unordered_map<std::string, uint64_t>& map,
                       const std::string& name, uint64_t address)
    {
        const auto [it, inserted] = map.emplace(name, address);
        if (!inserted && it->second != address)
            it->second = 0; // Ambiguous local/LTO names must stay unresolved.
    }

    std::unordered_map<std::string, uint64_t> exact_;
    std::unordered_map<std::string, uint64_t> aliases_;
};

inline std::string required_vermagic(std::string_view logs, std::string_view module_name,
                                     std::string_view old_vermagic)
{
    if (module_name.empty() || old_vermagic.empty())
        return {};
    const std::string prefix = std::string(module_name) + ": version magic '" +
                               std::string(old_vermagic) + "' should be '";
    std::string required;
    while (!logs.empty()) {
        const size_t newline = logs.find('\n');
        auto message = logs.substr(0, newline);
        if (const size_t semicolon = message.find(';'); semicolon != std::string_view::npos)
            message.remove_prefix(semicolon + 1); // /dev/kmsg record header
        if (message.starts_with(prefix)) {
            message.remove_prefix(prefix.size());
            const size_t quote = message.find('\'');
            if (quote != std::string_view::npos && quote > 0 && quote <= 1024)
                required = message.substr(0, quote);
        }
        if (newline == std::string_view::npos)
            break;
        logs.remove_prefix(newline + 1);
    }
    return required;
}

inline bool replace_vermagic(std::string& image, std::string_view required)
{
    if (required.empty() || required.size() > 1024 ||
        required.find_first_of(std::string_view("\0\n\r'", 4)) != std::string_view::npos)
        return false;

    ElfView elf(image);
    Elf64_Shdr section{};
    uint16_t index = 0;
    if (!elf.parse() || !elf.section_named(".modinfo", section, &index) ||
        section.sh_type != SHT_PROGBITS || (section.sh_flags & SHF_COMPRESSED) != 0)
        return false;

    std::string new_modinfo;
    bool replaced = false;
    for (uint64_t offset = 0; offset < section.sh_size;) {
        std::string_view entry;
        if (!elf.string_at(section, offset, entry))
            return false;
        offset += entry.size() + 1;
        if (entry.starts_with("vermagic=")) {
            if (replaced)
                continue;
            new_modinfo += "vermagic=";
            new_modinfo += required;
            replaced = true;
        } else if (!entry.empty()) {
            new_modinfo += entry;
        } else {
            continue;
        }
        new_modinfo += '\0';
    }
    if (!replaced) {
        new_modinfo += "vermagic=";
        new_modinfo += required;
        new_modinfo += '\0';
    }

    const uint64_t alignment = std::max<uint64_t>(1, section.sh_addralign);
    if (image.size() > kMaxModuleSize || alignment > kMaxModuleSize)
        return false;
    const uint64_t new_offset = (image.size() + alignment - 1) & ~(alignment - 1);
    if (!range_ok(kMaxModuleSize, new_offset, new_modinfo.size()))
        return false;
    const uint64_t header_offset = elf.section_offset(index);
    // Append instead of overwriting adjacent sections when the string grows.
    // This is metadata compatibility only: no CRCs, ABI layouts or signatures
    // are changed, and init_module still performs its normal checks.
    section.sh_offset = new_offset;
    section.sh_size = new_modinfo.size();
    image.resize(size_t(new_offset), '\0');
    image += new_modinfo;
    std::memcpy(image.data() + header_offset, &section, sizeof(section));
    return true;
}

inline bool release_matches(std::string_view release, std::string_view version)
{
    if (!release.starts_with(version))
        return false;
    return release.size() == version.size() || release[version.size()] == '.' ||
           release[version.size()] == '-';
}

} // namespace loader::detail

#endif
