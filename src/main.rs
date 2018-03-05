extern crate zydis;
// #[macro_use]
extern crate clap;
extern crate tabwriter;

use std::io::Write;
// use zydis::mnemonic::ZydisMnemonicMethods;

static APPLICATION_NAME: &'static str = "rzdis";
static APPLICATION_VERSION: &'static str = "0.1.0";
static APPLICATION_AUTHOR: &'static str = "TA Thanh Dinh <tathanhdinh@gmail.com>";
static APPLICATION_ABOUT: &'static str = "A x86 disassembler";

static ARGUMENT_OPCODE: &'static str = "x86 opcode";
static ARGUMENT_BASE: &'static str = "base address";
static ARGUMENT_MODE: &'static str = "disassembling mode";
static ARGUMENT_DETAIL: &'static str = "show instruction details";

pub trait ZydisInstructionEncodingMethods {
    fn get_string(self) -> Option<&'static str>;
}

impl ZydisInstructionEncodingMethods for zydis::gen::ZydisInstructionEncodings {
    fn get_string(self) -> Option<&'static str> {
        match self {
            zydis::gen::ZYDIS_INSTRUCTION_ENCODING_INVALID => {
                Some("invalid")
            },
            
            zydis::gen::ZYDIS_INSTRUCTION_ENCODING_DEFAULT => {
                Some("default")
            },
            
            zydis::gen::ZYDIS_INSTRUCTION_ENCODING_3DNOW => {
                Some("3DNow")
            },
            
            zydis::gen::ZYDIS_INSTRUCTION_ENCODING_XOP => {
                Some("XOP")
            },

            zydis::gen::ZYDIS_INSTRUCTION_ENCODING_VEX => {
                Some("VEX")
            },

            zydis::gen::ZYDIS_INSTRUCTION_ENCODING_EVEX => {
                Some("EVEX")
            },

            zydis::gen::ZYDIS_INSTRUCTION_ENCODING_MVEX => {
                Some("MVEX")
            },

            _ => {
                None
            }
        }
    }
}

pub trait ZydisInstructionOpcodeMapMethods {
    fn get_string(self) -> Option<&'static str>;
}

impl ZydisInstructionOpcodeMapMethods for zydis::gen::ZydisOpcodeMaps {
    fn get_string(self) -> Option<&'static str> {
        match self {
            zydis::gen::ZYDIS_OPCODE_MAP_DEFAULT => {
                Some("default")
            }

            zydis::gen::ZYDIS_OPCODE_MAP_0F => {
                Some("0F")
            },

            zydis::gen::ZYDIS_OPCODE_MAP_0F38 => {
                Some("0F38")
            },

            zydis::gen::ZYDIS_OPCODE_MAP_0F3A => {
                Some("0F3A")
            },

            zydis::gen::ZYDIS_OPCODE_MAP_0F0F => {
                Some("0F0F")
            },

            zydis::gen::ZYDIS_OPCODE_MAP_XOP8 => {
                Some("XOP8")
            },

            zydis::gen::ZYDIS_OPCODE_MAP_XOP9 => {
                Some("XOP9")
            },

            zydis::gen::ZYDIS_OPCODE_MAP_XOPA => {
                Some("XOPA")
            },

            _ => {
                None
            }
        }
    }
}

fn ZydisExceptionClassGetString(zydis::gen::ZydisExceptionClasses ec) -> Option<&'static str> {
    match ec {
        zydis::gen::ZYDIS_EXCEPTION_CLASS_NONE => {
            Some("None")
        },

        zydis::gen::ZYDIS_EXCEPTION_CLASS_SSE1 => {
            Some("SSE1")
        },

        zydis::gen::ZYDIS_EXCEPTION_CLASS_SSE2 => {
            Some("SSE2")
        },

        zydis::gen::ZYDIS_EXCEPTION_CLASS_SSE3 => {
            Some("SSE3")
        },

        zydis::gen::ZYDIS_EXCEPTION_CLASS_SSE4 => {
            Some("SSE4")
        },

        zydis::gen::ZYDIS_EXCEPTION_CLASS_SSE5 => {
            Some("SSE5")
        },

        zydis::gen::ZYDIS_EXCEPTION_CLASS_SSE7 => {
            Some("SSE7")
        },

        zydis::gen::ZYDIS_EXCEPTION_CLASS_AVX1 => {
            Some("AVX1")
        },

        zydis::gen::ZYDIS_EXCEPTION_CLASS_AVX2 => {
            Some("AVX2")
        },

        zydis::gen::ZYDIS_EXCEPTION_CLASS_AVX3 => {
            Some("AVX3")
        },

        zydis::gen::ZYDIS_EXCEPTION_CLASS_AVX4 => {
            Some("AVX4")
        },

        zydis::gen::ZYDIS_EXCEPTION_CLASS_AVX5 => {
            Some("AVX5")
        },

        zydis::gen::ZYDIS_EXCEPTION_CLASS_AVX6 => {
            Some("AVX6")
        },

        zydis::gen::ZYDIS_EXCEPTION_CLASS_AVX7 => {
            Some("AVX7")
        },

        zydis::gen::ZYDIS_EXCEPTION_CLASS_AVX8 => {
            Some("AVX8")
        },

        zydis::gen::ZYDIS_EXCEPTION_CLASS_AVX11 => {
            Some("AVX11")
        },

        zydis::gen::ZYDIS_EXCEPTION_CLASS_AVX12 => {
            Some("AVX12")
        },
    }
}

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
                // println!("{}", "bad disassembling mode (should be either x32 or x64)");
                unreachable!();
                // return;
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

                        let exception_class = ins.meta.exceptionClass as zydis::gen::ZydisExceptionClasses;
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
