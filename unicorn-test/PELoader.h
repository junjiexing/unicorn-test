#pragma once
#include <string>
#include <fstream>
#include <vector>
#include <windows.h>


struct IATItem
{
	std::string dll;
	std::string proc_name;
	uint32_t hint;
	uint32_t va;

	uint32_t fake_proc_addr;
};


class PELoader
{
public:
	bool load(std::string const& path);

	uint32_t rva2va(uint32_t rva);
	uint32_t rva2foa(uint32_t rva);

	bool readOffset(void* buffer, uint32_t size, uint32_t foa);

	std::string readCStrOffset(uint32_t foa);

	auto const& sec_headers() const { return m_sec_headers; }

	uint32_t base() const { return m_base; }

	uint32_t ep() const
	{
		return base() + m_nt_headers.OptionalHeader.AddressOfEntryPoint;
	}

	auto const& iat() const { return m_iat; }
	auto& iat() { return m_iat; }
private:
	std::string m_path;
	std::ifstream m_ifs;

	IMAGE_DOS_HEADER m_dos_header;
	IMAGE_NT_HEADERS32 m_nt_headers;
	uint32_t m_base = 0;
	std::vector<IMAGE_SECTION_HEADER> m_sec_headers;

	std::vector<IATItem> m_iat;
};

