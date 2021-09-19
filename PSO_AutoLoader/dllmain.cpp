#include <Windows.h>
#include "MinHook.h"
#include <intrin.h>
#include <iostream>
#include <fstream>
#include <iomanip>   
#pragma intrinsic(_ReturnAddress)
#include <string>
#pragma comment(lib,"libMinHook.x64.lib")
#include "xxhash.h"


extern "C" {
	bool fIsDestinationReachableA() { return true; }
	bool fIsDestinationReachableW() { return true; }
	bool fIsNetworkAlive() { return true; }
}

typedef void* (__cdecl* sub_14008CBF0)(__int64 a1, __int64* a2, char* a3, char* a4);
sub_14008CBF0 sub_14008CBF0_org = NULL;
sub_14008CBF0 sub_14008CBF0_ptr = NULL;

int megaid = 0;
//std::wofstream file_out;
__int64 start_addr;
__int64 end_addr;

bool redirected = false;


wchar_t TranslateDir[256]; wchar_t TranslatePath[256];


void* __cdecl sub_14008CBF0_my(__int64 a1, __int64* a2, char* a3, char* a4)
{
	void* retval = sub_14008CBF0_ptr(a1, a2,a3,a4);
	//file_out << "MAIN_OFFSET = " << std::hex << a1 << std::endl;
	//char test[256];
	//sprintf_s(test, "%llX %llX %llX", retval, Size, Alignment);
	//MessageBoxA(0, test, test, 0);
	return retval;
}




__int64 __stdcall get_str_offset()
{
	__int64 stringlist1 = 0x3BE5C90;
	stringlist1 += ((__int64)GetModuleHandle(0));
	stringlist1 = *(__int64*)stringlist1;
	return *(__int64*)(stringlist1 + 96);
}

__int64 __stdcall get_str_offset2()
{
	__int64 stringlist1 = 0x3BE5460;
	stringlist1 += ((__int64)GetModuleHandle(0));
	stringlist1 = *(__int64*)stringlist1;
	return *(__int64*)(stringlist1 + 408);
}



__int64 __stdcall get_str_offset3()
{
	__int64 stringlist1 = 0x03BCB718;
	stringlist1 += ((__int64)GetModuleHandle(0));
	stringlist1 = *(__int64*)stringlist1;
	stringlist1 = *(__int64*)(stringlist1 + 0x18);
	return stringlist1 + 0x2A0;
}




unsigned __int64 sub_140056380(char* a1)
{
	char* v1; // r9
	char* v3; // r11
	unsigned __int64 v4; // r10
	__int64 v5; // rcx
	__int64 v6; // r8

	v1 = a1;
	if (!a1)
	{
		return 0i64;
	}
	v3 = a1;
	v4 = 0i64;
	v5 = -1i64;
	do
	{
		++v5;
	} while (v1[v5]);
	if (v1 > &v1[v5])
	{
		v5 = 0i64;
	}
	if (v5)
	{
		do
		{
			v6 = *v3++;
			v4 ^= (v4 >> 2) + (v4 << 6) + 2654435769u + v6;
		} while (v3 - v1 != v5);
	}
	return v4;
}
const wchar_t* badtext = L"baaad";
wchar_t tmpstringbuffer[40960];

void __stdcall seek_listable(__int64 a1, signed int a3 /*translate id */)
{
	__int64* v3; // rbx
	__int64 v4; // rdi
	__int64* v6; // rcx
	__int64 v7; // r9
	__int64 v9; // rdi
	__int64 v10; // r8
	__int64 v11; // rax
	unsigned __int64* v12; // rdx

	if ((unsigned int)a3 > 0xB)
	{
		//file_out << L"ERROR 1" << std::endl;
		//file_out.flush();
		return;
	}
	v3 = *(__int64**)(a1 + 8i64 * a3 + 16);
	v4 = a1 + 8i64 * a3;
	if (!v3)
	{
		//file_out << L"ERROR 2" << std::endl;
		//file_out.flush();
		return;
	}
	v6 = *(__int64**)(v4 + 16);
	v7 = 0i64;
	v9 = 0i64;
	v10 = ((__int64)(v6[1] - *v6) >> 4) - 1;

	wchar_t tmp[256];
	char tmp2[256];

	if (v10 >= 0)
	{
		while (v7 <= v10)
		{
			//file_out << L"ID " << v7 << L" of " << v10 << L". Offset = " << v3 << std::endl;
			//file_out << std::hex << ((*v3 + 16 * v7) + 8) << std::endl;
			__int64 text_str_offset = *(__int64*)((*v3 + 16 * v7) + 8);
			__int64 text_str_offset_hash = *(__int64*)((*v3 + 16 * v7) );
			if (text_str_offset)
			{
				//file_out << megaid << std::endl;

				//file_out << L" : " <<std::hex << text_str_offset << L" -> "<<  std::endl;
				__int64 text_offset = (text_str_offset + 0x10);
				__int64 test_off = (text_str_offset + 0x18);
				__int64 text_flag = (text_str_offset + 0x28);	
				bool is_text = (*(__int64*)(text_flag) & 16 || *(__int64*)(text_flag) & 32 || *(__int64*)(text_flag) & 8
					|| *(__int64*)(text_flag) & 128 || *(__int64*)(text_flag) & 64);
				/*wsprintfW(tmp, L" %i : %IX - %IX - %IX - %s = ", megaid, test_off, text_offset, text_str_offset,
					is_text ? L"Normal text":L"Bad text" );*/

			
				//file_out << std::wstring(tmp) << std::endl;
				//////MessageBoxW(0, tmp, tmp, 0);
				if (is_text)
				{	
					wchar_t hash[64];
					wchar_t addr[64];
					XXH64_hash_t hashx = XXH64((*(wchar_t**)(text_offset)), lstrlenW((*(wchar_t**)(text_offset))) * sizeof(wchar_t), 0);
					wsprintfW(hash, L"%IX", hashx);
					wsprintfW(addr, L"%IX", text_str_offset);
					WritePrivateProfileStringW(hash, L"DEBUG", addr, TranslatePath);
					DWORD count = 0;
					if ((count = GetPrivateProfileStringW(hash, L"TEXT", L"", tmpstringbuffer, 40960, TranslatePath)) > 0)
					{
						count += 50;
						wchar_t* stringbuffer = new wchar_t[count];
						(*(wchar_t**)(text_offset)) = stringbuffer;
						memcpy(stringbuffer, tmpstringbuffer, count * sizeof(wchar_t));
					}
					else
					{
						WritePrivateProfileStringW(hash, L"TEXT", (*(wchar_t**)(text_offset)), TranslatePath);
					}
					//file_out << std::wstring((*(wchar_t**)(text_offset))) << std::endl;
					//	//MessageBoxW(0, tmp, L"TEXT", 0);
					//	//MessageBoxW(0, tmp, *(wchar_t**)(text_offset), 0);
					//(*(wchar_t**)(text_offset))[0] = L'Z';
					//file_out << std::wstring((*(wchar_t**)(text_offset))) << std::endl;

					//file_out << (*(wchar_t**)(text_offset)) << std::endl;
				}
				/*else
					((wchar_t*)(text_offset))[0] = L'Z';*/
			}
			v7++;
			megaid++;
		}
		//file_out << L"END 7" << std::endl;
		//file_out.flush();
	}


	//file_out << L"END 6" << std::endl;
	//file_out.flush();
}


void __stdcall get_real_list_tables(__int64 a1)
{
	unsigned __int64 v3; // rax
	__int64 v4; // r11
	__int64 v7; // r8
	__int64 v8 = 0; // rax

	v4 = *(__int64*)(a1 + 72);
	v7 = ((*(__int64*)(a1 + 80) - v4) >> 4) - 1; // maxstrings
	if (v7 < 0)
	{
		//file_out << L"ERROR 4" << std::endl;
		return;
	}
	char tmp[256];
	while (v8 <= v7)
	{
		//file_out << L"START OF LIST " << v8 << L" OF " << v7 << std::endl;
		seek_listable(*(__int64*)((v4 + 16 * v8) + 8), 1);
		//file_out << L"END OF LIST" << std::endl;
		++v8;
	}

	//file_out << L"END 5" << std::endl;
	//file_out.flush();
	return;
}


struct PatternData
{
	uint32_t	Count;
	uint32_t	Size;
	uint32_t	Length[16];
	uint32_t	Skip[16];
	__m128i		Value[16];
};

void GeneratePattern(const char* Signature, const char* Mask, PatternData* Out)
{
	auto l = strlen(Mask);

	Out->Count = 0;

	for (auto i = 0; i < l; i++)
	{
		if (Mask[i] == '?')
			continue;

		auto ml = 0, sl = 0;

		for (auto j = i; j < l; j++)
		{
			if (Mask[j] == '?' || sl >= 16)
				break;
			sl++;
		}

		for (auto j = i + sl; j < l; j++)
		{
			if (Mask[j] != '?')
				break;
			ml++;
		}

		auto c = Out->Count;

		Out->Length[c] = sl;
		Out->Skip[c] = sl + ml;
		Out->Value[c] = _mm_loadu_si128((const __m128i*)((uint8_t*)Signature + i));

		Out->Count++;

		i += sl - 1;
	}

	Out->Size = l;
}

__forceinline bool Matches(const uint8_t* Data, PatternData* Patterns)
{
	auto k = Data + Patterns->Skip[0];

	for (auto i = 1; i < Patterns->Count; i++)
	{
		auto l = Patterns->Length[i];

		if (_mm_cmpestri(Patterns->Value[i], l, _mm_loadu_si128((const __m128i*)k), l, _SIDD_CMP_EQUAL_EACH | _SIDD_MASKED_NEGATIVE_POLARITY) != l)
			break;

		if (i + 1 == Patterns->Count)
			return true;

		k += Patterns->Skip[i];
	}

	return false;
}

uint8_t* FindEx(const uint8_t* Data, const uint32_t Length, const char* Signature, const char* Mask)
{
	PatternData d;
	GeneratePattern(Signature, Mask, &d);

	auto out = static_cast<uint8_t*>(nullptr);
	auto end = Data + Length - d.Size;

	//C3010: 'break' : jump out of OpenMP structured block not allowed
#pragma omp parallel for
	for (intptr_t i = Length - 32; i >= 0; i -= 32)
	{
#pragma omp flush (out)
		if (out == nullptr)
		{
			auto p = Data + i;
			auto b = _mm256_loadu_si256((const __m256i*)p);

			if (_mm256_test_all_zeros(b, b) == 1)
				continue;

			auto f = _mm_cmpestri(d.Value[0], d.Length[0], _mm256_extractf128_si256(b, 0), 16, _SIDD_CMP_EQUAL_ORDERED);

			if (f == 16)
			{
				f += _mm_cmpestri(d.Value[0], d.Length[0], _mm256_extractf128_si256(b, 1), 16, _SIDD_CMP_EQUAL_ORDERED);

				if (f == 32)
					continue;
			}

		PossibleMatch:
			p += f;

			if (p + d.Size > end)
			{
				for (auto j = 0; j < d.Size && j + i + f < Length; j++)
				{
					if (Mask[j] == 'x' && (uint8_t)Signature[j] != p[j])
						break;

					if (j + 1 == d.Size)
						out = (uint8_t*)p;
				}

				continue;
			}

			if (Matches(p, &d))
				out = (uint8_t*)p;
#pragma omp flush (out)

			if (out == nullptr)
			{
				p++;
				f = _mm_cmpestri(d.Value[0], d.Length[0], _mm_loadu_si128((const __m128i*)p), 16, _SIDD_CMP_EQUAL_ORDERED);

				if (f < 16)
					goto PossibleMatch;
			}
		}
	}

	return out;
}

void FindLargestArray(const char* Signature, const char* Mask, int Out[2])
{
	uint32_t t1 = 0;
	uint32_t t2 = strlen(Signature);
	uint32_t len = strlen(Mask);

	for (auto j = t2; j < len; j++)
	{
		if (Mask[j] != 'x')
			continue;

		auto count = strlen(&Signature[j]);

		if (count > t2)
		{
			t1 = j;
			t2 = count;
		}

		j += (count - 1);
	}

	Out[0] = t1;
	Out[1] = t2;
}

uint8_t* Find(const uint8_t* Data, const uint32_t Length, const char* Signature, const char* Mask)
{
	int d[2] = { 0 };
	FindLargestArray(Signature, Mask, d);

	const uint8_t len = static_cast<uint8_t>(strlen(Mask));
	const uint8_t mbeg = static_cast<uint8_t>(d[0]);
	const uint8_t mlen = static_cast<uint8_t>(d[1]);
	const uint8_t mfirst = static_cast<uint8_t>(Signature[mbeg]);

	uint8_t wildcard[UCHAR_MAX + 1] = { 0 };

	for (auto i = mbeg; i < mbeg + mlen; i++)
		wildcard[(uint8_t)Signature[i]] = 1;

	for (int i = Length - len; i >= 0; i--)
	{
		auto c = Data[i];
		auto w = wildcard[c];
		auto k = 0;

		while (w == 0 && i > mlen)
		{
			i -= mlen;
			w = wildcard[Data[i]];
			k = 1;
		}

		if (k == 1)
		{
			i++;
			continue;
		}

		if (c != mfirst)
			continue;

		if (i - mbeg < 0 || i - mbeg + len > Length)
			return nullptr;

		for (auto j = 0; j < len - 1; j++)
		{
			if (j == mbeg || Mask[j] != 'x')
				continue;

			if (Data[i - mbeg + j] != (uint8_t)Signature[j])
				break;

			if (j + 1 == len - 1)
				return (uint8_t*)(Data + i - mbeg);
		}
	}

	return nullptr;
}

	bool Supported()
	{
		int id[4] = { 0 };
		__cpuid(id, 1);

		bool sse42 = (id[3] & 0x04000000) != 0;
		bool avx = (id[2] & 0x18000000) != 0;

		return (sse42 && avx);
	}
	/*return FindEx((const uint8_t*)baseAddress, size, Pattern, Mask);
	*/
/*switch (test)
		{
		case Tests::First:
			Pattern = "\x45\x43\x45\x55\x33\x9a\xfa\x00\x00\x00\x00\x45\x68\x21";
			Mask = "xxxxxxx????xxx";
			break;
		case Tests::Second:
			Pattern = "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xbb\xaa\x00\x00\x00\x00\x45\x68\x21";
			Mask = "xxxxxxxxxxx????xxx";
			break;
		default:
			break;
			Find((const uint8_t*)baseAddress, size, Pattern, Mask);
			*/

void SearchAllPtrString()
{
	__int64 startsearchaddr = *(__int64*)(((__int64)GetModuleHandle(0)) + 0x3BCBC58);
	MEMORY_BASIC_INFORMATION info;
	VirtualQueryEx(GetCurrentProcess(), (LPCVOID)startsearchaddr, &info, sizeof(info));
	startsearchaddr = (__int64)info.BaseAddress;
	__int64 endaddr = startsearchaddr + 0x500000;
	__int64 head_class[2];
	head_class[0] = 0x30D5148 + ((__int64)GetModuleHandle(0));
	head_class[1] = 0;

	if (Supported())
	{
		__int64 addr = 0;
		while ((startsearchaddr + 0x100 < endaddr) 
			&&
			(addr = (__int64)FindEx((const uint8_t*)startsearchaddr, endaddr - startsearchaddr, (const char*)&head_class[0], "xxxxxxxx")))
		{
			startsearchaddr = addr + 8;
			get_real_list_tables(addr);
		}
	}
	else
	{
		__int64 addr = 0;
		while ((startsearchaddr + 0x100 < endaddr)
			&&
			(addr = (__int64)Find((const uint8_t*)startsearchaddr, endaddr - startsearchaddr, (const char*)&head_class[0], "xxxxxxxx")))
		{
			startsearchaddr = addr + 8;
			get_real_list_tables(addr);
		}
	}
	//for (__int64 i = startsearchaddr; i < endaddr; i += 8)
	//{
	//	if (*(__int64*)i == head_class)
	//	{
	//		//file_out << L"START 0x" << std::hex << i << std::endl;
	//		//file_out << L"FILENAME: " << std::wstring((wchar_t*)(i + 0x20)) << std::endl;
	//		get_real_list_tables(i);
	//		//file_out << L"END 1113" << std::endl;
	//		i += 0x40;
	//	}
	//}
}

DWORD WINAPI thread(LPVOID)
{
	Sleep(10000);
	/*int a1 = MH_Initialize();
	sub_14008CBF0_org = (sub_14008CBF0)(((__int64)GetModuleHandleA(0)) + 0x829C0);
	int a3 = MH_CreateHook(sub_14008CBF0_org, &sub_14008CBF0_my, reinterpret_cast<void**>(&sub_14008CBF0_ptr));
	int a4 = MH_EnableHook(sub_14008CBF0_org);*/

	GetCurrentDirectoryW(256, TranslateDir);
	wsprintfW(TranslatePath, L"%s\\%s", TranslateDir, L"translate.ini");
	FILE* f;
	_wfopen_s(&f, TranslatePath, L"ab+");
	fclose(f);
	//file_out << L"START 444" << std::endl;

	while (true)
	{
		if ((GetKeyState('1') & 0x8000))
		{
			while ((GetKeyState('1') & 0x8000))
			{
			
			}
			MessageBoxA(0, "START", "SUCCESS", 0);

			SearchAllPtrString();

			/*get_real_list_tables(get_str_offset());
			file_out << L"END 1113" << std::endl;
			get_real_list_tables(get_str_offset2());
			file_out.flush();
			file_out << L"END 1113" << std::endl;
			get_real_list_tables(get_str_offset3());
			file_out.flush();
			file_out << L"END 555" << std::endl;
			file_out.close();*/
			MessageBoxA(0, "SUCCESS", "SUCCESS", 0);
		}
	
	
		Sleep(1000);
	}
	return 0;
}


BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
	static bool injected = false;
	if (ul_reason_for_call == DLL_PROCESS_ATTACH && !injected)
	{
		injected = true;
		if (!GetModuleHandleA("pso2.exe"))
			return 1;
		//file_out.open(L"text.txt", std::ios_base::app);
		//file_out << "Need save data ? " << *(__int64*)(0x143BCB4C8) << std::endl
	

		CreateThread(0, 0, thread, 0, 0, 0);
	}
	return 1;
}
