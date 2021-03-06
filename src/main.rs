// #![feature(stdsimd)]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

extern crate zydis;
extern crate tabwriter;
extern crate syntect;
extern crate pager;

#[macro_use] extern crate clap;
#[macro_use] extern crate bitflags;
#[macro_use] extern crate lazy_static;
#[macro_use] extern crate maplit;
#[macro_use] extern crate failure;

use std::io::{Read, Write};

static APPLICATION_NAME: &'static str = "rzdis";
static APPLICATION_VERSION: &'static str = "0.1.0";
static APPLICATION_AUTHOR: &'static str = "TA Thanh Dinh <tathanhdinh@gmail.com>";
static APPLICATION_ABOUT: &'static str = "A x86 disassembler";

static ARGUMENT_BINARY_CODE: &'static str = "x86 binary code";
static ARGUMENT_BINARY_FILE: &'static str = "x68 binary input file";
static ARGUMENT_BASE: &'static str = "base address";
static ARGUMENT_MODE: &'static str = "disassembling mode";
static ARGUMENT_DETAIL: &'static str = "show instruction details";

// pub struct AAA {
//     abc: u32,
// }

// macro_rules! create_instruction_encoding_map {
//     // (general $x:ident, $y:ident) => {
//     //     lazy_static! {
//     //         static ref InstructionEncodingMap:
//     //             std::collections::HashMap<zydis::gen::ZydisInstructionEncodings, &'static str> = {
//     //                 hashmap! {
//     //                     zydis::gen::ZYDIS_INSTRUCTION_ENCODING_$x => stringtify!($x),
//     //                     zydis::gen::ZYDIS_INSTRUCTION_ENCODING_$y => stringtify!($y),
//     //                 }
//     //             };
//     //     }
//     // }
//     ($( $x:ident ),*) => {
//         // let mut InstructionEncodingMap = 
//         //     std::collections::HashMap<zydis::gen::ZydisInstructionEncodings, &'static str>::new();
//         let mut tmp = 3;
//     //     lazy_static! {
//     //         static ref InstructionEncodingsdf: 
//     //     std::collections::HashMap<zydis::gen::ZydisInstructionEncodings,
//     //                               &'static str> = {
//     //     // let mut hm = std::collections::HashMap::new();
//     //     // hm.insert(zydis::gen::ZYDIS_INSTRUCTION_ENCODING_INVALID, "invalid");
//     //     // hm.insert(zydis::gen::ZYDIS_INSTRUCTION_ENCODING_DEFAULT, "default");
//     //     // hm.insert(zydis::gen::ZYDIS_INSTRUCTION_ENCODING_3DNOW, "3DNow");
//     //     // hm.insert(zydis::gen::ZYDIS_INSTRUCTION_ENCODING_XOP, "XOP");
//     //     // hm.insert(zydis::gen::ZYDIS_INSTRUCTION_ENCODING_VEX, "VEX");
//     //     // hm.insert(zydis::gen::ZYDIS_INSTRUCTION_ENCODING_EVEX, "EVEX");
//     //     // hm.insert(zydis::gen::ZYDIS_INSTRUCTION_ENCODING_MVEX, "MVEX");
//     //     hashmap! {
//     //         // zydis::gen::ZYDIS_INSTRUCTION_ENCODING_INVALID => "invalid",
//     //         // zydis::gen::ZYDIS_INSTRUCTION_ENCODING_DEFAULT => "default",
//     //         // zydis::gen::ZYDIS_INSTRUCTION_ENCODING_3DNOW => "3DNow",
//     //         // zydis::gen::ZYDIS_INSTRUCTION_ENCODING_XOP => "XOP",
//     //         // zydis::gen::ZYDIS_INSTRUCTION_ENCODING_VEX => "VEX",
//     //         // zydis::gen::ZYDIS_INSTRUCTION_ENCODING_EVEX => "EVEX",
//     //         // zydis::gen::ZYDIS_INSTRUCTION_ENCODING_MVEX => "EVEX",
//     //                             $(
//     //                     zydis::gen::ZYDIS_INSTRUCTION_ENCODING_A => "a",
//     //                 )*
//     //     }
//     // };
//         // };


//         // lazy_static! {
//         //     $(
//         //         println!("{}", stringify!($x));
//         //     )*
//         // }

//         let tmp = hashmap! {
//             $(
//                 // zydis::gen::ZYDIS_INSTRUCTION_ENCODING_$x => stringify!($x),
//                 stringify!($x) => stringify!(zydis::gen::ZYDIS_INSTRUCTION_ENCODING_$x),
//             )*
            
//         }
        
        
//         // lazy_static! {
//         //     static ref InstructionEncodingMap:
//         //     std::collections::HashMap<zydis::gen::ZydisInstructionEncodings, &'static str> = {
//         //         hashmap! {
//         //             $(
//         //                 zydis::gen::ZYDIS_INSTRUCTION_ENCODING_$x => stringify!($x),
//         //             )*
//         //         }
//         //     };
//         // }
//     };

//     ($( $x:expr ),*) => {
//         let mut tmp = Vec::new();
//         $(
//             tmp.push($x);
//         )*
//         tmp
//     }
// }

// macro_rules! vvec {
//     ($( $x:expr ),*) => {
//         let mut tmp = Vec::new;
//         $(
//             temp_vec.push($x);
//         )*
//         temp_vec
//     };
// }

// create_instruction_encoding_map!["abc", "def"];

lazy_static! {
    static ref InstructionEncoding: 
        std::collections::HashMap<zydis::gen::ZydisInstructionEncodings,
                                  &'static str> = {
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
        InstructionEncoding.get(&self).map(|x| *x)
    }
}

lazy_static! {
    static ref InstructionOpcodeMapMethod: 
        std::collections::HashMap<zydis::gen::ZydisOpcodeMaps, 
                                  &'static str> = {
        hashmap! {
            zydis::gen::ZYDIS_OPCODE_MAP_DEFAULT => "default",
            zydis::gen::ZYDIS_OPCODE_MAP_0F => "0F",
            zydis::gen::ZYDIS_OPCODE_MAP_0F38 => "0F38",
            zydis::gen::ZYDIS_OPCODE_MAP_0F3A => "0F3A",
            zydis::gen::ZYDIS_OPCODE_MAP_0F0F => "0F0F",
            zydis::gen::ZYDIS_OPCODE_MAP_XOP8 => "XOP8",
            zydis::gen::ZYDIS_OPCODE_MAP_XOP9 => "XOP9",
            zydis::gen::ZYDIS_OPCODE_MAP_XOPA => "XOPA",
        }
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
    static ref InstructionExceptionClass: 
        std::collections::HashMap<zydis::gen::ZydisExceptionClasses, 
                                  &'static str> = {
        hashmap! {
            zydis::gen::ZYDIS_EXCEPTION_CLASS_NONE => "None",
            zydis::gen::ZYDIS_EXCEPTION_CLASS_SSE1 => "SSE1",
            zydis::gen::ZYDIS_EXCEPTION_CLASS_SSE2 => "SSE2",
            zydis::gen::ZYDIS_EXCEPTION_CLASS_SSE3 => "SSE3",
            zydis::gen::ZYDIS_EXCEPTION_CLASS_SSE4 => "SSE4",
            zydis::gen::ZYDIS_EXCEPTION_CLASS_SSE5 => "SSE5",
            zydis::gen::ZYDIS_EXCEPTION_CLASS_SSE7 => "SSE7",
            zydis::gen::ZYDIS_EXCEPTION_CLASS_AVX1 => "AVX1",
            zydis::gen::ZYDIS_EXCEPTION_CLASS_AVX2 => "AVX2",
            zydis::gen::ZYDIS_EXCEPTION_CLASS_AVX3 => "AVX3",
            zydis::gen::ZYDIS_EXCEPTION_CLASS_AVX4 => "AVX4",
            zydis::gen::ZYDIS_EXCEPTION_CLASS_AVX5 => "AVX5",
            zydis::gen::ZYDIS_EXCEPTION_CLASS_AVX6 => "AVX6",
            zydis::gen::ZYDIS_EXCEPTION_CLASS_AVX7 => "AVX7",
            zydis::gen::ZYDIS_EXCEPTION_CLASS_AVX8 => "AVX8",
            zydis::gen::ZYDIS_EXCEPTION_CLASS_AVX11 => "AVX11",
            zydis::gen::ZYDIS_EXCEPTION_CLASS_AVX12 => "AVX12",
            zydis::gen::ZYDIS_EXCEPTION_CLASS_E1 => "E1",
            zydis::gen::ZYDIS_EXCEPTION_CLASS_E1NF => "E1NF",
            zydis::gen::ZYDIS_EXCEPTION_CLASS_E2 => "E2",
            zydis::gen::ZYDIS_EXCEPTION_CLASS_E2NF => "E2NF",
            zydis::gen::ZYDIS_EXCEPTION_CLASS_E3 => "E3",
            zydis::gen::ZYDIS_EXCEPTION_CLASS_E3NF => "E3NF",
            zydis::gen::ZYDIS_EXCEPTION_CLASS_E4 => "E4",
            zydis::gen::ZYDIS_EXCEPTION_CLASS_E4NF => "E4NF",
            zydis::gen::ZYDIS_EXCEPTION_CLASS_E5 => "E5",
            zydis::gen::ZYDIS_EXCEPTION_CLASS_E5NF => "E5NF",
            zydis::gen::ZYDIS_EXCEPTION_CLASS_E6 => "E6",
            zydis::gen::ZYDIS_EXCEPTION_CLASS_E6NF => "E6NF",
            zydis::gen::ZYDIS_EXCEPTION_CLASS_E7NM => "E7NM",
            zydis::gen::ZYDIS_EXCEPTION_CLASS_E7NM128 => "E7NM128",
            zydis::gen::ZYDIS_EXCEPTION_CLASS_E9NF => "E9NF",
            zydis::gen::ZYDIS_EXCEPTION_CLASS_E10 => "E10",
            zydis::gen::ZYDIS_EXCEPTION_CLASS_E10NF => "E10NF",
            zydis::gen::ZYDIS_EXCEPTION_CLASS_E11 => "E6",
            zydis::gen::ZYDIS_EXCEPTION_CLASS_E11NF => "E6NF",
            zydis::gen::ZYDIS_EXCEPTION_CLASS_E12 => "E12",
            zydis::gen::ZYDIS_EXCEPTION_CLASS_E12NP => "E12NP",
            zydis::gen::ZYDIS_EXCEPTION_CLASS_K20 => "K20",
            zydis::gen::ZYDIS_EXCEPTION_CLASS_K21 => "K21",
        }
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
        const ZYDIS_ATTRIB_ACCEPTS_REPNE = zydis::gen::ZYDIS_ATTRIB_ACCEPTS_REPNE as u64;
        const ZYDIS_ATTRIB_ACCEPTS_REPNZ = zydis::gen::ZYDIS_ATTRIB_ACCEPTS_REPNZ as u64;
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
    static ref InstructionAttribute: 
        std::collections::HashMap<InstructionAttributeFlag, 
                                  &'static str> = {
        hashmap! {
            InstructionAttributeFlag::ZYDIS_ATTRIB_HAS_MODRM => "HAS_MODRM",
            InstructionAttributeFlag::ZYDIS_ATTRIB_HAS_SIB => "HAS_SIB",
            InstructionAttributeFlag::ZYDIS_ATTRIB_HAS_REX => "HAS_REX",
            InstructionAttributeFlag::ZYDIS_ATTRIB_HAS_XOP => "HAS_XOP",
            InstructionAttributeFlag::ZYDIS_ATTRIB_HAS_VEX => "HAS_VEX",
            InstructionAttributeFlag::ZYDIS_ATTRIB_HAS_EVEX => "HAS_EVEX",
            InstructionAttributeFlag::ZYDIS_ATTRIB_HAS_MVEX => "HAS_MVEX",
            InstructionAttributeFlag::ZYDIS_ATTRIB_IS_RELATIVE => "IS_RELATIVE",
            InstructionAttributeFlag::ZYDIS_ATTRIB_IS_PRIVILEGED => "IS_PRIVILEGED",
            InstructionAttributeFlag::ZYDIS_ATTRIB_IS_FAR_BRANCH => "IS_FAR_BRANCH",
            InstructionAttributeFlag::ZYDIS_ATTRIB_ACCEPTS_LOCK => "ACCEPTS_LOCK",
            InstructionAttributeFlag::ZYDIS_ATTRIB_ACCEPTS_REPE => "ACCEPTS_REPE",
            InstructionAttributeFlag::ZYDIS_ATTRIB_ACCEPTS_REPZ => "ACCEPTS_REPZ",
            InstructionAttributeFlag::ZYDIS_ATTRIB_ACCEPTS_REPNE => "ACCEPTS_REPNE",
            InstructionAttributeFlag::ZYDIS_ATTRIB_ACCEPTS_REPNZ => "ACCEPTS_REPNZ",
            InstructionAttributeFlag::ZYDIS_ATTRIB_ACCEPTS_BOUND => "ACCEPTS_BOUNDS",
            InstructionAttributeFlag::ZYDIS_ATTRIB_ACCEPTS_XACQUIRE => "ACCEPTS_XACQUIRE",
            InstructionAttributeFlag::ZYDIS_ATTRIB_ACCEPTS_XRELEASE => "ACCEPTS_XRELEASE",
            InstructionAttributeFlag::ZYDIS_ATTRIB_ACCEPTS_HLE_WITHOUT_LOCK => "ACCEPTS_HLE_WITHOUT_LOCK",
            InstructionAttributeFlag::ZYDIS_ATTRIB_ACCEPTS_BRANCH_HINTS => "ACCEPTS_BRANCH_HINTS",
            InstructionAttributeFlag::ZYDIS_ATTRIB_ACCEPTS_SEGMENT => "ACCEPTS_SEGMENT",
            InstructionAttributeFlag::ZYDIS_ATTRIB_HAS_LOCK => "HAS_LOCK",
            InstructionAttributeFlag::ZYDIS_ATTRIB_HAS_REP => "HAS_REP",
            InstructionAttributeFlag::ZYDIS_ATTRIB_HAS_REPE => "HAS_REPE",
            InstructionAttributeFlag::ZYDIS_ATTRIB_HAS_REPZ => "HAS_REPZ",
            InstructionAttributeFlag::ZYDIS_ATTRIB_HAS_REPNE => "HAS_REPNE",
            InstructionAttributeFlag::ZYDIS_ATTRIB_HAS_REPNZ => "HAS_REPNZ",
            InstructionAttributeFlag::ZYDIS_ATTRIB_HAS_BOUND => "HAS_BOUND",
            InstructionAttributeFlag::ZYDIS_ATTRIB_HAS_XACQUIRE => "HAS_XACQUIRE",
            InstructionAttributeFlag::ZYDIS_ATTRIB_HAS_XRELEASE => "HAS_XRELEASE",
            InstructionAttributeFlag::ZYDIS_ATTRIB_HAS_BRANCH_NOT_TAKEN => "HAS_BRANCH_NOT_TAKEN",
            InstructionAttributeFlag::ZYDIS_ATTRIB_HAS_BRANCH_TAKEN => "HAS_BRANCH_TAKEN",
            InstructionAttributeFlag::ZYDIS_ATTRIB_HAS_SEGMENT => "HAS_SEGMENT",
            InstructionAttributeFlag::ZYDIS_ATTRIB_HAS_SEGMENT_CS => "HAS_SEGMENT_CS",
            InstructionAttributeFlag::ZYDIS_ATTRIB_HAS_SEGMENT_SS => "HAS_SEGMENT_SS",
            InstructionAttributeFlag::ZYDIS_ATTRIB_HAS_SEGMENT_DS => "HAS_SEGMENT_DS",
            InstructionAttributeFlag::ZYDIS_ATTRIB_HAS_SEGMENT_ES => "HAS_SEGMENT_ES",
            InstructionAttributeFlag::ZYDIS_ATTRIB_HAS_SEGMENT_FS => "HAS_SEGMENT_FS",
            InstructionAttributeFlag::ZYDIS_ATTRIB_HAS_SEGMENT_GS => "HAS_SEGMENT_GS",
            InstructionAttributeFlag::ZYDIS_ATTRIB_HAS_OPERANDSIZE => "HAS_OPERANDSIZE",
            InstructionAttributeFlag::ZYDIS_ATTRIB_HAS_ADDRESSSIZE => "ADDRESSSIZE"
        }
    };
}

fn ZydisInstructionAttributesGetStrings(atts: zydis::gen::ZydisInstructionAttributes) -> Vec<&'static str> {
    let mut att_strs = Vec::new();
    let attributes = InstructionAttributeFlag::from_bits_truncate(atts);
    for attr in InstructionAttribute.keys() {
        if attributes.contains(*attr) {
            att_strs.push(*InstructionAttribute.get(attr).unwrap());
        }
    }
    att_strs
}

fn main() {
    pager::Pager::with_pager("less -R -X").setup();

    match run() {
        Ok(()) => {},
        Err(ref err) => {
            if let Some(ref _err) = err.downcast_ref::<std::io::Error>() {
                std::process::exit(0);
            }
            else {
                println!("Error: {}", err);
            }
        }
    }

    // if let Err(ref err) = run() {
    //     if err.kind() == io::ErrorKind::BrokenPipe {
    //         std::process::exit(0);
    //     }
    //     else {
    //         println!("{}", err)
    //     }
        
    // }
}

fn run() -> Result<(), failure::Error> {
    let matches = clap::App::new(APPLICATION_NAME)
        .version(APPLICATION_VERSION)
        .author(APPLICATION_AUTHOR)
        .about(APPLICATION_ABOUT)
        .arg(clap::Arg::with_name(ARGUMENT_BINARY_CODE)
                .required_unless(ARGUMENT_BINARY_FILE)
                .index(1))
        .arg(clap::Arg::with_name(ARGUMENT_BINARY_FILE)
                .short("f")
                .long("file")
                .takes_value(true)
                .conflicts_with(ARGUMENT_BINARY_CODE))
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

    let (address_width, disasm_mode) = 
        if matches.is_present(ARGUMENT_MODE) {
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

    let mut formatter = zydis::Formatter::new(zydis::gen::ZYDIS_FORMATTER_STYLE_INTEL).unwrap();
    unsafe {
        // let mut fm = &formatter as *mut zydis::gen::ZydisFormatter; 
        // let fm = &formatter as *mut zydis::gen::ZydisFormatter;
        // let mut fm = &formatter as *mut zydis::Formatter;
        let fm: *mut zydis::Formatter = &mut formatter;
        // let fm = fm as *mut zydis::gen::ZydisFormatter;
        // let a = &mut formatter as *mut zydis::gen::ZydisFormatter;
        // zydis::gen::ZydisFormatterSetProperty(fm as *mut zydis::gen::ZydisFormatter,
        //                                       zydis::gen::ZYDIS_ADDR_FORMAT_RELATIVE_SIGNED as zydis::gen::ZydisFormatterProperty, 
        //                                       zydis::gen::ZYDIS_TRUE as zydis::gen::ZydisUPointer);
        zydis::gen::ZydisFormatterSetProperty(fm as *mut zydis::gen::ZydisFormatter,
                                              zydis::gen::ZYDIS_FORMATTER_PROP_ADDR_FORMAT as zydis::gen::ZydisFormatterProperty, 
                                              zydis::gen::ZYDIS_ADDR_FORMAT_RELATIVE_SIGNED as zydis::gen::ZydisUPointer);
    };
    let decoder = zydis::Decoder::new(disasm_mode, address_width).unwrap();

    let base_address = if matches.is_present(ARGUMENT_BASE) {
        // value_t!(matches, ARGUMENT_BASE, u64).unwrap_or(0x0)
        // let base = matches.value_of(ARGUMENT_BASE).unwrap(); // should not panic

        u64::from_str_radix(matches.value_of(ARGUMENT_BASE).unwrap(), 16)?
    }
    else {
        0x0
    };

    let detail_level = matches.occurrences_of(ARGUMENT_DETAIL);

    let mut binary_code = Vec::new();
    if matches.is_present(ARGUMENT_BINARY_FILE) {
        let mut input_file = std::fs::File::open(matches.value_of(ARGUMENT_BINARY_FILE).unwrap())?;
        input_file.read_to_end(&mut binary_code)?;
    }
    else {
        let native_code = matches.value_of(ARGUMENT_BINARY_CODE).unwrap(); // should not panic
        binary_code = native_code.split_whitespace().map(|c| u8::from_str_radix(c, 16)).collect::<Result<Vec<_>, _>>()?
    };
    

    let mut disasm_results: Vec<_> = Vec::new();
    for (mut ins, ins_address) in decoder.instruction_iterator(&binary_code, base_address) {
        if let Ok(formatted_ins) = formatter.format_instruction(&mut ins, 50, None) {
            let ins_opcode = ins.data.into_iter()
                                .take(ins.length as usize)
                                .map(|opc| format!("{:02x}", opc))
                                .collect::<Vec<_>>()
                                .join(" ");

            let disasm_result = format!("0x{:x}\t{}\t{}\t", ins_address, ins_opcode, formatted_ins);
            disasm_results.push(disasm_result);

            if detail_level != 0 {
                let mnemonic = zydis::mnemonic::ZydisMnemonicMethods::get_string(ins.mnemonic as zydis::gen::ZydisMnemonics).ok_or_else(|| format_err!("invalid mnemonic"))?;
                let encoding = ZydisInstructionEncodingMethods::get_string(ins.encoding as zydis::gen::ZydisInstructionEncodings).ok_or_else(|| format_err!("invalid encoding"))?;
                let opcode_map = ZydisInstructionOpcodeMapMethods::get_string(ins.opcodeMap as zydis::gen::ZydisOpcodeMaps).ok_or_else(|| format_err!("invalid opcode map"))?;
                let opcode = ins.opcode;
                disasm_results.push(format!("\t\t\tmnemonic:\t{} [encoding: {}, opcode map: {}, opcode: {:x}]", mnemonic, encoding, opcode_map, opcode));

                if detail_level > 1 {
                    // disasm_results.push(format!("\t\t\tmnemonic:\t{} [encoding: {}, opcode map: {}, opcode: {:x}]", mnemonic, encoding, opcode_map, opcode));
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

                    let exception_class = ZydisExceptionClassGetString(ins.meta.exceptionClass as zydis::gen::ZydisExceptionClasses).ok_or_else(|| format_err!("invalid exception class"))?;
                    disasm_results.push(format!("\t\t\texception class:\t{}", exception_class));
                }

                let category = unsafe { 
                    std::ffi::CStr::from_ptr(zydis::gen::ZydisCategoryGetString(ins.meta.category)).to_string_lossy()
                };
                disasm_results.push(format!("\t\t\tcategory:\t{}", category));

                if detail_level > 1 {
                    let att_strs = ZydisInstructionAttributesGetStrings(ins.attributes);
                    disasm_results.push(format!("\t\t\tattributes:\t{}", att_strs.join(",")));
                }
                
            }

            // match detail_level {
            //     1 => {
            //         let mnemonic = zydis::mnemonic::ZydisMnemonicMethods::get_string(ins.mnemonic as zydis::gen::ZydisMnemonics).unwrap();
            //         let encoding = ZydisInstructionEncodingMethods::get_string(ins.encoding as zydis::gen::ZydisInstructionEncodings).unwrap();
            //         let opcode_map = ZydisInstructionOpcodeMapMethods::get_string(ins.opcodeMap as zydis::gen::ZydisOpcodeMaps).unwrap();
            //         let opcode = ins.opcode;
            //         disasm_results.push(format!("\t\t\tmnemonic:\t{} [encoding: {}, opcode map: {}, opcode: {:x}]", mnemonic, encoding, opcode_map, opcode));
            //         disasm_results.push(format!("\t\t\tlength:\t{}", ins.length));
            //         disasm_results.push(format!("\t\t\tstack width:\t{}", ins.stackWidth));
            //         disasm_results.push(format!("\t\t\toperand width:\t{}", ins.operandWidth));
            //         disasm_results.push(format!("\t\t\taddress width:\t{}", ins.addressWidth));

            //         let category = unsafe { 
            //             std::ffi::CStr::from_ptr(zydis::gen::ZydisCategoryGetString(ins.meta.category)).to_string_lossy()
            //         };
            //         disasm_results.push(format!("\t\t\tcategory:\t{}", category));

            //         let isa_set = unsafe {
            //             std::ffi::CStr::from_ptr(zydis::gen::ZydisISASetGetString(ins.meta.isaSet)).to_string_lossy()
            //         };
            //         disasm_results.push(format!("\t\t\tisa set:\t{}", isa_set));

            //         let isa_ext = unsafe {
            //             std::ffi::CStr::from_ptr(zydis::gen::ZydisISAExtGetString(ins.meta.isaExt)).to_string_lossy()
            //         };
            //         disasm_results.push(format!("\t\t\tisa extension:\t{}", isa_ext));

            //         let exception_class = ZydisExceptionClassGetString(ins.meta.exceptionClass as zydis::gen::ZydisExceptionClasses).unwrap();
            //         disasm_results.push(format!("\t\t\texception class:\t{}", exception_class));

                    
            //         // let mut attr_string = Vec::new();
            //         // let attributes = InstructionAttributeFlag::from_bits(ins.attributes).ok_or_else(|| format_err!("Export directory not found"))?;
            //         // for attr in InstructionAttribute.keys() {
            //         //     if attributes.contains(*attr) {
            //         //         attr_string.push(format!("{}", InstructionAttribute.get(attr).unwrap()));
            //         //     }
            //         // }
            //         let att_strs = ZydisInstructionAttributesGetStrings(ins.attributes);
            //         disasm_results.push(format!("\t\t\tattributes:\t{}", att_strs.join(",")));
            //     },

            //     2 => {

            //     }

            //     _ => {

            //     }
            // }
        }
        else {
            break;
        }
    }
    let disasm_results = disasm_results.join("\r\n");

    // let mut tw = tabwriter::TabWriter::new(std::io::stdout()).padding(4);
    let mut tw = tabwriter::TabWriter::new(vec![]).padding(4);
    writeln!(&mut tw, "{}", disasm_results)?;
    tw.flush()?;

    let written_strs = String::from_utf8(tw.into_inner()?)?;
    let written_strs = written_strs.split("\r\n").collect::<Vec<&str>>();
    let theme_set = syntect::highlighting::ThemeSet::load_defaults();
    let theme = &theme_set.themes["Solarized (dark)"];
    let syntax_set = syntect::parsing::SyntaxSet::load_defaults_nonewlines();
    // syntax_set.load_syntaxes("/public/syntaxes", false);
    let syntax = syntax_set.find_syntax_by_extension("asm").unwrap_or_else(|| syntax_set.find_syntax_plain_text());
    // let syntax = syntax_set.find_syntax_by_name("Nasm Assembly").unwrap_or_else(|| { syntax_set.find_syntax_plain_text() });
    // let syntax = syntax_set.find_syntax_by_name("x86_64 Assembly").unwrap_or_else(|| { syntax_set.find_syntax_plain_text() });
    let mut highlighter = syntect::easy::HighlightLines::new(syntax, theme);
        // if let Some(syntax) = syntax_set.find_syntax_by_extension("asm") {
        //     syntax
        // }
        // else {
        //     syntax_set.find_syntax_plain_text()
        // };
    for line in written_strs {
        let ranges: Vec<(syntect::highlighting::Style, &str)> = highlighter.highlight(line);
        let escaped = syntect::util::as_24_bit_terminal_escaped(&ranges[..], true);
        // println!("{}", escaped);
        writeln!(&mut std::io::stdout(), "{}", escaped)?;
    }

    Ok(())
}