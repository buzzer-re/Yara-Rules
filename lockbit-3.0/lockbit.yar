import "pe"
import "math"

rule Ransom_Loader_Lockbit_V3 {
    meta:
        reference = "506f3b12853375a1fbbf85c82ddf13341cf941c5acd4a39a51d6addf145a7a51"
        description = "Yara rule for the encrypted Lockbit 3.0 binary"
        
    strings:
        $indirectPEBAccess = {
            33 C0    // xor eax, eax
            40       // inc eax
            C1 E0 06 // shl eax, 6
            8D 40 F0 // lea eax, [eax-0x10]
            64 8B 00 // mov eax, fs:[eax]
            C3       // retn
        }

        $Hex2BinUpperCaseSnippet = {
            66 83 F8 41 // cmp ax, 0x41 ; 'A'
            72 ??       // jb 
            66 83 F8 46 // cmp ax, 0x46 ; 'F'
            77 06       // ja  <lower_case_cmp>
            66 83 E8 37 // sub ax, 0x37 ; '7'
            EB ??       // jmp <switch_dispatcher>
        }

        $GetCommandLineBuffer = {
            E8 ?? FF FF FF //  call GetPEB ; indirectPEBAccess string
            8B 40 10       //  mov eax, [eax+0x10];  GetPEB()->ProcessParameters
            8B 40 44       //  mov eax, [eax+0x44];  GetPEB()->ProcessParameters->CommandLine.Buffer;
            C3             //  retn
        }

    condition:
        pe.is_pe and
        // Not every sample will have a total entropy of >= 7.9, some variants have ~ 6.5 entropy rate at encrypted .text
        // So a overall entropy of 6.3 it's a good start point
        math.entropy(0, filesize) >= 6.3 
        and for any section in pe.sections: 
        (
            (
                section.name != ".text"
                and section.characteristics & 0xff == 0x20 // executable
                and 
                (
                    pe.entry_point >= section.raw_data_offset and
                    pe.entry_point <= (section.raw_data_offset + section.raw_data_size)
                )
                and $indirectPEBAccess in (section.raw_data_offset .. (section.raw_data_offset + section.raw_data_size))
                and $Hex2BinUpperCaseSnippet in (section.raw_data_offset .. (section.raw_data_offset + section.raw_data_size))
                and $GetCommandLineBuffer in (section.raw_data_offset .. (section.raw_data_offset + section.raw_data_size))
            ) 
        )
}

