extern crate zydis;
// #[macro_use]
extern crate clap;
extern crate tabwriter;

use std::io::Write;

static APPLICATION_NAME: &'static str = "rzdis";
static APPLICATION_VERSION: &'static str = "0.1.0";
static APPLICATION_AUTHOR: &'static str = "TA Thanh Dinh <tathanhdinh@gmail.com>";
static APPLICATION_ABOUT: &'static str = "A x86 disassembler";

static ARGUMENT_OPCODE: &'static str = "x86 opcode";
static ARGUMENT_BASE: &'static str = "base address";
static ARGUMENT_MODE: &'static str = "disassembling mode";

fn main() {
    // println!("Hello, world!");
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
             .default_value("x64"))
        .get_matches();

    let (address_width, disasm_mode) = if matches.is_present(ARGUMENT_MODE) {
        match matches.value_of(ARGUMENT_MODE).unwrap() {
            "x32" => {
                // keystone::MODE_32
                (zydis::gen::ZYDIS_ADDRESS_WIDTH_32, zydis::gen::ZYDIS_MACHINE_MODE_LONG_COMPAT_32)
            },
            "x64" => {
                (zydis::gen::ZYDIS_ADDRESS_WIDTH_64, zydis::gen::ZYDIS_MACHINE_MODE_LONG_64)
            },
            _ => {
                println!("{}", "bad disassembling mode (should be either x32 or x64)");
                return;
            }
        }
    }
    else {
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
    
    if let Ok(opcode) = opcode.split_whitespace()
        .map(|oc| { u8::from_str_radix(oc, 16) })
        .collect::<Result<Vec<_>, _>>() {

        // let mut ins_address = base_address;
        let mut disasm_results: Vec<_> = Vec::new();
        for (mut ins, ins_address) in decoder.instruction_iterator(&opcode, base_address) {
            // ins_address += ins_length;
            if let Ok(formatted_ins) = formatter.format_instruction(&mut ins, 30, None) {
                let disasm_result = format!("0x{:x}\t{}", ins_address, formatted_ins);
                disasm_results.push(disasm_result);
            }
            else {
                break;
            }
        }
        let disasm_results = disasm_results.join("\r\n");

        let mut tw = tabwriter::TabWriter::new(std::io::stdout()).padding(4);
        writeln!(&mut tw, "{}", disasm_results).unwrap();
        // tw.flush().unwrap();
        tw.flush().unwrap();
    }
    else {
        println!("{}", "bad input hex opcode");
    }
}
