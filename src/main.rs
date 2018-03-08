#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

extern crate zydis;
// #[macro_use]
extern crate clap;
extern crate tabwriter;
#[macro_use] extern crate bitflags;
#[macro_use] extern crate lazy_static;
#[macro_use] extern crate maplit;

use std::io::Write;

static APPLICATION_NAME: &'static str = "rzdis";
static APPLICATION_VERSION: &'static str = "0.1.0";
static APPLICATION_AUTHOR: &'static str = "TA Thanh Dinh <tathanhdinh@gmail.com>";
static APPLICATION_ABOUT: &'static str = "A x86 disassembler";

static ARGUMENT_OPCODE: &'static str = "x86 opcode";
static ARGUMENT_BASE: &'static str = "base address";
static ARGUMENT_MODE: &'static str = "disassembling mode";
static ARGUMENT_DETAIL: &'static str = "show instruction details";

lazy_static! {
    static ref InstructionEncodingMethod: std::collections::HashMap<zydis::gen::ZydisInstructionEncodings,
                                                                    &'static str> = {
        // let mut hm = std::collections::HashMap::new();
        // hm.insert(zydis::gen::ZYDIS_INSTRUCTION_ENCODING_INVALID, "invalid");
        // hm.insert(zydis::gen::ZYDIS_INSTRUCTION_ENCODING_DEFAULT, "default");
        // hm.insert(zydis::gen::ZYDIS_INSTRUCTION_ENCODING_3DNOW, "3DNow");
        // hm.insert(zydis::gen::ZYDIS_INSTRUCTION_ENCODING_XOP, "XOP");
        // hm.insert(zydis::gen::ZYDIS_INSTRUCTION_ENCODING_VEX, "VEX");
        // hm.insert(zydis::gen::ZYDIS_INSTRUCTION_ENCODING_EVEX, "EVEX");
        // hm.insert(zydis::gen::ZYDIS_INSTRUCTION_ENCODING_MVEX, "MVEX");
        hashmap! {
            zydis::gen::ZYDIS_INSTRUCTION_ENCODING_INVALID => "invalid",
            zydis::gen::ZYDIS_INSTRUCTION_ENCODING_DEFAULT => "default",
            zydis::gen::ZYDIS_INSTRUCTION_ENCODING_3DNOW => "3DNow",
            zydis::gen::ZYDIS_INSTRUCTION_ENCODING_XOP => "XOP",
            zydis::gen::ZYDIS_INSTRUCTION_ENCODING_VEX => "VEX",
            zydis::gen::ZYDIS_INSTRUCTION_ENCODING_EVEX => "EVEX",
            zydis::gen::ZYDIS_INSTRUCTION_ENCODING_MVEX => "EVEX",
        }
    };
}

pub trait ZydisInstructionEncodingMethods {
    fn get_string(self) -> Option<&'static str>;
}

impl ZydisInstructionEncodingMethods for zydis::gen::ZydisInstructionEncodings {
    fn get_string(self) -> Option<&'static str> {
        InstructionEncodingMethod.get(&self).map(|x| *x)
        // match InstructionEncodingMethod.get(&self) {
        //     Some(x) => Some(*x),
        //     None => None
        // }
        // match self {
        //     zydis::gen::ZYDIS_INSTRUCTION_ENCODING_INVALID => {
        //         Some("invalid")
        //     },
            
        //     zydis::gen::ZYDIS_INSTRUCTION_ENCODING_DEFAULT => {
        //         Some("default")
        //     },
            
        //     zydis::gen::ZYDIS_INSTRUCTION_ENCODING_3DNOW => {
        //         Some("3DNow")
        //     },
            
        //     zydis::gen::ZYDIS_INSTRUCTION_ENCODING_XOP => {
        //         Some("XOP")
        //     },

        //     zydis::gen::ZYDIS_INSTRUCTION_ENCODING_VEX => {
        //         Some("VEX")
        //     },

        //     zydis::gen::ZYDIS_INSTRUCTION_ENCODING_EVEX => {
        //         Some("EVEX")
        //     },

        //     zydis::gen::ZYDIS_INSTRUCTION_ENCODING_MVEX => {
        //         Some("MVEX")
        //     },

        //     _ => {
        //         None
        //     }
        // }
    }
}

lazy_static! {
    static ref InstructionOpcodeMapMethod: std::collections::HashMap<zydis::gen::ZydisOpcodeMaps, 
                                                                     &'static str> = {
        let mut hm = std::collections::HashMap::new();
        hm.insert(zydis::gen::ZYDIS_OPCODE_MAP_DEFAULT, "default");
        hm.insert(zydis::gen::ZYDIS_OPCODE_MAP_0F, "0F");
        hm.insert(zydis::gen::ZYDIS_OPCODE_MAP_0F38, "0F38");
        hm.insert(zydis::gen::ZYDIS_OPCODE_MAP_0F3A, "0F3A");
        hm.insert(zydis::gen::ZYDIS_OPCODE_MAP_0F0F, "0F0F");
        hm.insert(zydis::gen::ZYDIS_OPCODE_MAP_XOP8, "XOP8");
        hm.insert(zydis::gen::ZYDIS_OPCODE_MAP_XOP9, "XOP9");
        hm.insert(zydis::gen::ZYDIS_OPCODE_MAP_XOPA, "XOPA");
        hm
    };
}

pub trait ZydisInstructionOpcodeMapMethods {
    fn get_string(self) -> Option<&'static str>;
}

impl ZydisInstructionOpcodeMapMethods for zydis::gen::ZydisOpcodeMaps {
    fn get_string(self) -> Option<&'static str> {
        InstructionOpcodeMapMethod.get(&self).map(|x| *x)
    }
}

lazy_static! {
    static ref InstructionExceptionClass: std::collections::HashMap<zydis::gen::ZydisExceptionClasses, &'static str> = {
        let mut hm = std::collections::HashMap::new();
        hm.insert(zydis::gen::ZYDIS_EXCEPTION_CLASS_NONE, "None");
        hm.insert(zydis::gen::ZYDIS_EXCEPTION_CLASS_SSE1, "SSE1");
        hm.insert(zydis::gen::ZYDIS_EXCEPTION_CLASS_SSE2, "SSE2");
        hm.insert(zydis::gen::ZYDIS_EXCEPTION_CLASS_SSE3, "SSE3");
        hm.insert(zydis::gen::ZYDIS_EXCEPTION_CLASS_SSE4, "SSE4");
        hm.insert(zydis::gen::ZYDIS_EXCEPTION_CLASS_SSE5, "SSE5");
        hm.insert(zydis::gen::ZYDIS_EXCEPTION_CLASS_SSE7, "SSE7");
        hm.insert(zydis::gen::ZYDIS_EXCEPTION_CLASS_AVX1, "AVX1");
        hm.insert(zydis::gen::ZYDIS_EXCEPTION_CLASS_AVX2, "AVX2");
        hm.insert(zydis::gen::ZYDIS_EXCEPTION_CLASS_AVX3, "AVX3");
        hm.insert(zydis::gen::ZYDIS_EXCEPTION_CLASS_AVX5, "AVX4");
        hm.insert(zydis::gen::ZYDIS_EXCEPTION_CLASS_AVX6, "AVX6");
        hm.insert(zydis::gen::ZYDIS_EXCEPTION_CLASS_AVX7, "AVX7");
        hm.insert(zydis::gen::ZYDIS_EXCEPTION_CLASS_AVX8, "AVX8");
        hm.insert(zydis::gen::ZYDIS_EXCEPTION_CLASS_AVX11, "AVX11");
        hm.insert(zydis::gen::ZYDIS_EXCEPTION_CLASS_AVX12, "AVX12");
        hm.insert(zydis::gen::ZYDIS_EXCEPTION_CLASS_E1, "E1");
        hm.insert(zydis::gen::ZYDIS_EXCEPTION_CLASS_E1NF, "E1NF");
        hm.insert(zydis::gen::ZYDIS_EXCEPTION_CLASS_E2, "E2");
        hm.insert(zydis::gen::ZYDIS_EXCEPTION_CLASS_E2NF, "E2NF");
        hm.insert(zydis::gen::ZYDIS_EXCEPTION_CLASS_E3, "E3");
        hm.insert(zydis::gen::ZYDIS_EXCEPTION_CLASS_E3NF, "E3NF");
        hm.insert(zydis::gen::ZYDIS_EXCEPTION_CLASS_E4, "E4");
        hm.insert(zydis::gen::ZYDIS_EXCEPTION_CLASS_E4NF, "E4NF");
        hm.insert(zydis::gen::ZYDIS_EXCEPTION_CLASS_E5, "E5");
        hm.insert(zydis::gen::ZYDIS_EXCEPTION_CLASS_E5NF, "E5NF");
        hm.insert(zydis::gen::ZYDIS_EXCEPTION_CLASS_E6, "E6");
        hm.insert(zydis::gen::ZYDIS_EXCEPTION_CLASS_E6NF, "E6NF");
        hm.insert(zydis::gen::ZYDIS_EXCEPTION_CLASS_E7NM, "E7NM");
        hm.insert(zydis::gen::ZYDIS_EXCEPTION_CLASS_E7NM128, "E7NM128");
        hm.insert(zydis::gen::ZYDIS_EXCEPTION_CLASS_E9NF, "E9NF");
        hm.insert(zydis::gen::ZYDIS_EXCEPTION_CLASS_E10, "E10");
        hm.insert(zydis::gen::ZYDIS_EXCEPTION_CLASS_E10NF, "E10NF");
        hm.insert(zydis::gen::ZYDIS_EXCEPTION_CLASS_E11, "E6");
        hm.insert(zydis::gen::ZYDIS_EXCEPTION_CLASS_E11NF, "E6NF");
        hm.insert(zydis::gen::ZYDIS_EXCEPTION_CLASS_E12, "E12");
        hm.insert(zydis::gen::ZYDIS_EXCEPTION_CLASS_E12NP, "E12NP");
        hm.insert(zydis::gen::ZYDIS_EXCEPTION_CLASS_K20, "K20");
        hm.insert(zydis::gen::ZYDIS_EXCEPTION_CLASS_K21, "K21");
        hm
    };
}

fn ZydisExceptionClassGetString(ec: zydis::gen::ZydisExceptionClasses) -> Option<&'static str> {
    InstructionExceptionClass.get(&ec).map(|x| *x)
}

bitflags! {
    struct InstructionAttributeFlag: u64 {
        const ZYDIS_ATTRIB_HAS_MODRM = zydis::gen::ZYDIS_ATTRIB_HAS_MODRM as u64;
        const ZYDIS_ATTRIB_HAS_SIB = zydis::gen::ZYDIS_ATTRIB_HAS_SIB as u64;
        const ZYDIS_ATTRIB_HAS_REX = zydis::gen::ZYDIS_ATTRIB_HAS_REX as u64;
        const ZYDIS_ATTRIB_HAS_XOP = zydis::gen::ZYDIS_ATTRIB_HAS_XOP as u64;
        const ZYDIS_ATTRIB_HAS_VEX = zydis::gen::ZYDIS_ATTRIB_HAS_VEX as u64;
        const ZYDIS_ATTRIB_HAS_EVEX = zydis::gen::ZYDIS_ATTRIB_HAS_EVEX as u64;
        const ZYDIS_ATTRIB_HAS_MVEX = zydis::gen::ZYDIS_ATTRIB_HAS_MVEX as u64;
        const ZYDIS_ATTRIB_IS_RELATIVE = zydis::gen::ZYDIS_ATTRIB_IS_RELATIVE as u64;
        const ZYDIS_ATTRIB_IS_PRIVILEGED = zydis::gen::ZYDIS_ATTRIB_IS_PRIVILEGED as u64;
        const ZYDIS_ATTRIB_IS_FAR_BRANCH = zydis::gen::ZYDIS_ATTRIB_IS_FAR_BRANCH as u64;
        const ZYDIS_ATTRIB_ACCEPTS_LOCK = zydis::gen::ZYDIS_ATTRIB_ACCEPTS_LOCK as u64;
        const ZYDIS_ATTRIB_ACCEPTS_REP = zydis::gen::ZYDIS_ATTRIB_ACCEPTS_REP as u64;
        const ZYDIS_ATTRIB_ACCEPTS_REPE = zydis::gen::ZYDIS_ATTRIB_ACCEPTS_REPE as u64;
        const ZYDIS_ATTRIB_ACCEPTS_REPZ = zydis::gen::ZYDIS_ATTRIB_ACCEPTS_REPZ as u64;
        const ZYDIS_ATTRIB_ACCEPTS_REPPNE = zydis::gen::ZYDIS_ATTRIB_ACCEPTS_REPZ as u64;
        const ZYDIS_ATTRIB_ACCEPTS_REPNZ = zydis::gen::ZYDIS_ATTRIB_ACCEPTS_REPZ as u64;
        const ZYDIS_ATTRIB_ACCEPTS_BOUND = zydis::gen::ZYDIS_ATTRIB_ACCEPTS_BOUND as u64;
        const ZYDIS_ATTRIB_ACCEPTS_XACQUIRE = zydis::gen::ZYDIS_ATTRIB_ACCEPTS_XACQUIRE as u64;
        const ZYDIS_ATTRIB_ACCEPTS_XRELEASE = zydis::gen::ZYDIS_ATTRIB_ACCEPTS_XRELEASE as u64;
        const ZYDIS_ATTRIB_ACCEPTS_HLE_WITHOUT_LOCK = zydis::gen::ZYDIS_ATTRIB_ACCEPTS_HLE_WITHOUT_LOCK as u64;
        const ZYDIS_ATTRIB_ACCEPTS_BRANCH_HINTS = zydis::gen::ZYDIS_ATTRIB_ACCEPTS_BRANCH_HINTS as u64;
        const ZYDIS_ATTRIB_ACCEPTS_SEGMENT = zydis::gen::ZYDIS_ATTRIB_ACCEPTS_SEGMENT as u64;
        const ZYDIS_ATTRIB_HAS_LOCK = zydis::gen::ZYDIS_ATTRIB_HAS_LOCK as u64;
        const ZYDIS_ATTRIB_HAS_REP = zydis::gen::ZYDIS_ATTRIB_HAS_REP as u64;
        const ZYDIS_ATTRIB_HAS_REPE = zydis::gen::ZYDIS_ATTRIB_HAS_REPE as u64;
        const ZYDIS_ATTRIB_HAS_REPZ = zydis::gen::ZYDIS_ATTRIB_HAS_REPZ as u64;
        const ZYDIS_ATTRIB_HAS_REPNE = zydis::gen::ZYDIS_ATTRIB_HAS_REPNE as u64;
        const ZYDIS_ATTRIB_HAS_REPNZ = zydis::gen::ZYDIS_ATTRIB_HAS_REPNZ as u64;
        const ZYDIS_ATTRIB_HAS_BOUND = zydis::gen::ZYDIS_ATTRIB_HAS_BOUND as u64;
        const ZYDIS_ATTRIB_HAS_XACQUIRE = zydis::gen::ZYDIS_ATTRIB_HAS_XACQUIRE as u64;
        const ZYDIS_ATTRIB_HAS_XRELEASE = zydis::gen::ZYDIS_ATTRIB_HAS_XRELEASE as u64;
        const ZYDIS_ATTRIB_HAS_BRANCH_NOT_TAKEN = zydis::gen::ZYDIS_ATTRIB_HAS_BRANCH_NOT_TAKEN as u64;
        const ZYDIS_ATTRIB_HAS_BRANCH_TAKEN = zydis::gen::ZYDIS_ATTRIB_HAS_BRANCH_TAKEN as u64;
        const ZYDIS_ATTRIB_HAS_SEGMENT = zydis::gen::ZYDIS_ATTRIB_HAS_SEGMENT as u64;
        const ZYDIS_ATTRIB_HAS_SEGMENT_CS = zydis::gen::ZYDIS_ATTRIB_HAS_SEGMENT_CS as u64;
        const ZYDIS_ATTRIB_HAS_SEGMENT_SS = zydis::gen::ZYDIS_ATTRIB_HAS_SEGMENT_SS as u64;
        const ZYDIS_ATTRIB_HAS_SEGMENT_DS = zydis::gen::ZYDIS_ATTRIB_HAS_SEGMENT_DS as u64;
        const ZYDIS_ATTRIB_HAS_SEGMENT_ES = zydis::gen::ZYDIS_ATTRIB_HAS_SEGMENT_ES as u64;
        const ZYDIS_ATTRIB_HAS_SEGMENT_FS = zydis::gen::ZYDIS_ATTRIB_HAS_SEGMENT_FS as u64;
        const ZYDIS_ATTRIB_HAS_SEGMENT_GS = zydis::gen::ZYDIS_ATTRIB_HAS_SEGMENT_GS as u64;
        const ZYDIS_ATTRIB_HAS_OPERANDSIZE = zydis::gen::ZYDIS_ATTRIB_HAS_OPERANDSIZE as u64;
        const ZYDIS_ATTRIB_HAS_ADDRESSSIZE = zydis::gen::ZYDIS_ATTRIB_HAS_ADDRESSSIZE as u64;
    }
}

lazy_static! {
    static ref InstructionAttribute: std::collections::HashMap<InstructionAttributeFlag, &'static str> = {
        let hm = std::collections::HashMap::new();
        hm
    };
}

// fn ZydisInstructionAttributesGetStrings(atts: zydis::gen::ZydisInstructionAttributes) -> Vec<&'static str> {

// }

fn main() {
    let matches = clap::App::new(APPLICATION_NAME)
        .version(APPLICATION_VERSION)
        .author(APPLICATION_AUTHOR)
        .about(APPLICATION_ABOUT)
        .arg(clap::Arg::with_name(ARGUMENT_OPCODE)
             .required(true)
             .index(1))
        .arg(clap::Arg::with_name(ARGUMENT_BASE)
             .short("b")
             .long("base")
             .takes_value(true)
             .default_value("0"))
        .arg(clap::Arg::with_name(ARGUMENT_MODE)
             .short("m")
             .long("mode")
             .takes_value(true)
             .default_value("x64")
             .possible_values(&["x64", "x32"]))
        .arg(clap::Arg::with_name(ARGUMENT_DETAIL)
             .short("v")
             .long("verbose")
             .multiple(true))
        .get_matches();

    let (address_width, disasm_mode) = if matches.is_present(ARGUMENT_MODE) {
        match matches.value_of(ARGUMENT_MODE).unwrap() {
            "x32" => {
                (zydis::gen::ZYDIS_ADDRESS_WIDTH_32, zydis::gen::ZYDIS_MACHINE_MODE_LONG_COMPAT_32)
            },
            "x64" => {
                (zydis::gen::ZYDIS_ADDRESS_WIDTH_64, zydis::gen::ZYDIS_MACHINE_MODE_LONG_64)
            },
            _ => {
                unreachable!();
            }
        }
    }
    else {
        // default
        (zydis::gen::ZYDIS_ADDRESS_WIDTH_64, zydis::gen::ZYDIS_MACHINE_MODE_LONG_64)
    };

    let formatter = zydis::Formatter::new(zydis::gen::ZYDIS_FORMATTER_STYLE_INTEL).unwrap();
    let decoder = zydis::Decoder::new(disasm_mode, address_width).unwrap();

    let base_address = if matches.is_present(ARGUMENT_BASE) {
        // value_t!(matches, ARGUMENT_BASE, u64).unwrap_or(0x0)
        let base = matches.value_of(ARGUMENT_BASE).unwrap(); // should not panic
        if let Ok(base) = u64::from_str_radix(base, 16) {
            base
        }
        else {
            println!("{}", "bad base address");
            return;
        }
    }
    else {
        0x0
    };

    let opcode = matches.value_of(ARGUMENT_OPCODE).unwrap(); // should not panic
    // let opcode = opcode.split_whitespace().collect::<Vec<&str>>();
    // let opcode: Result<Vec<_>, _> = opcode.split_whitespace().map(|oc| { u8::from_str_radix(oc, 16) }).collect();

    let detail_level = matches.occurrences_of(ARGUMENT_DETAIL);
    
    if let Ok(opcode) = opcode.split_whitespace()
        .map(|oc| { u8::from_str_radix(oc, 16) })
        .collect::<Result<Vec<_>, _>>() {

        let mut disasm_results: Vec<_> = Vec::new();
        for (mut ins, ins_address) in decoder.instruction_iterator(&opcode, base_address) {
            if let Ok(formatted_ins) = formatter.format_instruction(&mut ins, 30, None) {
                // let ins_opcode = ins.data[0..ins.length];
                // let data = ins.data.into_iter().take(ins.length as usize);
                // let data = data[0..3];
                let ins_opcode = ins.data
                    .into_iter()
                    .take(ins.length as usize)
                    .map(|opc| format!("{:02x}", opc))
                    .collect::<Vec<_>>()
                    .join(" ");

                let disasm_result = format!("0x{:x}\t{}\t{}\t", ins_address, ins_opcode, formatted_ins);
                disasm_results.push(disasm_result);

                match detail_level {
                    1 => {
                        let mnemonic = zydis::mnemonic::ZydisMnemonicMethods::get_string(ins.mnemonic as zydis::gen::ZydisMnemonics).unwrap();
                        let encoding = ZydisInstructionEncodingMethods::get_string(ins.encoding as zydis::gen::ZydisInstructionEncodings).unwrap();
                        let opcode_map = ZydisInstructionOpcodeMapMethods::get_string(ins.opcodeMap as zydis::gen::ZydisOpcodeMaps).unwrap();
                        let opcode = ins.opcode;
                        // let basic_info = format!("\t\tmnemonic:\t{} [encoding: {}, opcode map: {}, opcode: {:x}]", mnemonic, encoding, opcode_map, opcode);
                        // disasm_results.push(basic_info);
                        disasm_results.push(format!("\t\t\tmnemonic:\t{} [encoding: {}, opcode map: {}, opcode: {:x}]", mnemonic, encoding, opcode_map, opcode));
                        disasm_results.push(format!("\t\t\tlength:\t{}", ins.length));
                        disasm_results.push(format!("\t\t\tstack width:\t{}", ins.stackWidth));
                        disasm_results.push(format!("\t\t\toperand width:\t{}", ins.operandWidth));
                        disasm_results.push(format!("\t\t\taddress width:\t{}", ins.addressWidth));

                        let category = unsafe { 
                            std::ffi::CStr::from_ptr(zydis::gen::ZydisCategoryGetString(ins.meta.category)).to_string_lossy()
                        };
                        disasm_results.push(format!("\t\t\tcategory:\t{}", category));

                        let isa_set = unsafe {
                            std::ffi::CStr::from_ptr(zydis::gen::ZydisISASetGetString(ins.meta.isaSet)).to_string_lossy()
                        };
                        disasm_results.push(format!("\t\t\tisa set:\t{}", isa_set));

                        let isa_ext = unsafe {
                            std::ffi::CStr::from_ptr(zydis::gen::ZydisISAExtGetString(ins.meta.isaExt)).to_string_lossy()
                        };
                        disasm_results.push(format!("\t\t\tisa extension:\t{}", isa_ext));

                        let exception_class = ZydisExceptionClassGetString(ins.meta.exceptionClass as zydis::gen::ZydisExceptionClasses).unwrap();
                        disasm_results.push(format!("\t\t\texception class:\t{}", exception_class));

                        let attributes = ins.attributes;
                    },

                    2 => {

                    }

                    _ => {

                    }
                }
            }
            else {
                break;
            }
        }
        let disasm_results = disasm_results.join("\r\n");

        let mut tw = tabwriter::TabWriter::new(std::io::stdout()).padding(4);
        writeln!(&mut tw, "{}", disasm_results).unwrap();
        tw.flush().unwrap();
    }
    else {
        println!("{}", "bad input hex opcode");
    }
}
