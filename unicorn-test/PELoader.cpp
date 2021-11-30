#include "PELoader.h"
#include <iostream>
#include <cassert>


bool PELoader::load(std::string const& path)
{
	m_path = path;
	m_ifs.open(path, std::ios::binary | std::ios::in);

	if (!m_ifs)
	{
		//std::cout << "open failed" << std::endl;
		return false;
	}

	m_ifs.read(reinterpret_cast<char*>(&m_dos_header), sizeof(m_dos_header));

	if (m_dos_header.e_magic != IMAGE_DOS_SIGNATURE)
	{
		//std::cout << "invalid e_magic" << std::endl;
		return false;
	}

	m_ifs.seekg(m_dos_header.e_lfanew, std::ios::beg);

	m_ifs.read(reinterpret_cast<char*>(&m_nt_headers), sizeof(m_nt_headers));

	if (m_nt_headers.Signature != IMAGE_NT_SIGNATURE)
	{
		//std::cout << "invalid nt signature" << std::endl;
		return false;
	}

	m_base = m_nt_headers.OptionalHeader.ImageBase;


	auto sec_num = m_nt_headers.FileHeader.NumberOfSections;
	m_sec_headers.resize(sec_num);

	m_ifs.read(reinterpret_cast<char*>(m_sec_headers.data()), sizeof(IMAGE_SECTION_HEADER) * m_sec_headers.size());

	//导入表
	auto import_directory = m_nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

	if (import_directory.Size > 0)
	{
		std::vector<IMAGE_IMPORT_DESCRIPTOR> import_descriptors(import_directory.Size / sizeof(IMAGE_IMPORT_DESCRIPTOR));
		readOffset(import_descriptors.data(), import_directory.Size, rva2foa(import_directory.VirtualAddress));
		assert(import_descriptors.back().Name == 0);
		import_descriptors.pop_back();		//最后一个所有字段都为0
		for (auto const& import_descriptor : import_descriptors)
		{
			std::string dll = readCStrOffset(rva2foa(import_descriptor.Name));
			for (int i = 0; ; ++i)
			{
				IMAGE_THUNK_DATA32 thunk_data;
				readOffset(&thunk_data, sizeof(thunk_data), rva2foa(import_descriptor.OriginalFirstThunk + sizeof(thunk_data) * i));
				if (thunk_data.u1.AddressOfData == 0)
				{
					break;
				}

				WORD import_hint;
				auto foa = rva2foa(thunk_data.u1.AddressOfData);
				readOffset(&import_hint, sizeof(import_hint), foa);
				auto func = readCStrOffset(foa + sizeof(import_hint));
			}


			for (int i = 0; ; ++i)
			{
				IMAGE_THUNK_DATA32 thunk_data;
				uint32_t rva = import_descriptor.FirstThunk + sizeof(thunk_data) * i;
				readOffset(&thunk_data, sizeof(thunk_data), rva2foa(rva));
				if (thunk_data.u1.AddressOfData == 0)
				{
					break;
				}

				WORD import_hint;
				auto foa = rva2foa(thunk_data.u1.AddressOfData);
				readOffset(&import_hint, sizeof(import_hint), foa);
				auto func = readCStrOffset(foa + sizeof(import_hint));

				m_iat.emplace_back(IATItem{ dll, func, import_hint, rva + base(), 0 });
			}
		}

	}

	//TODO: 如果重定位表不为空，需要执行重定位
	auto reloc_directory = m_nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	if (reloc_directory.Size > 0)
	{
		std::vector<IMAGE_BASE_RELOCATION> base_relocations(reloc_directory.Size / sizeof(IMAGE_BASE_RELOCATION));
		readOffset(base_relocations.data(), reloc_directory.Size, rva2foa(reloc_directory.VirtualAddress));
		assert(base_relocations.back().VirtualAddress == 0);
		base_relocations.pop_back();		//最后一个所有字段都为0
	}

	return true;
}

uint32_t PELoader::rva2va(uint32_t rva)
{
	return m_nt_headers.OptionalHeader.ImageBase + rva;
}

uint32_t PELoader::rva2foa(uint32_t rva)
{
	for (auto const& sec_header : m_sec_headers)
	{
		if (rva >= sec_header.VirtualAddress && rva < sec_header.VirtualAddress + sec_header.Misc.VirtualSize)
		{
			return sec_header.PointerToRawData + (rva - sec_header.VirtualAddress);
		}
	}

	return 0;
}

bool PELoader::readOffset(void* buffer, uint32_t size, uint32_t foa)
{
	m_ifs.seekg(foa, std::ios::beg);
	m_ifs.read(reinterpret_cast<char*>(buffer), size);

	return m_ifs.good();
}

std::string PELoader::readCStrOffset(uint32_t foa)
{
	m_ifs.seekg(foa, std::ios::beg);
	std::string str;
	for (;;)
	{
		int c = m_ifs.get();
		if (c <= 0)
		{
			break;
		}

		str.push_back(c);
	}

	return str;
}

